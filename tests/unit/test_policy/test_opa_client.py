"""Unit tests for OPAClient using respx-mocked httpx transport (Batch 3, Task A)."""

from __future__ import annotations

import httpx
import pytest
import respx

from ci_agent.policy.opa_client import DEFAULT_BASE_URL, OPAClient, OPAUnavailableError

FACTS = {"stage_id": "security_gate", "findings": []}


@respx.mock
def test_success_returns_result_document(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post(f"{DEFAULT_BASE_URL}/v1/data/ci_agent/security_policy").mock(
        return_value=httpx.Response(200, json={"result": {"decision": "pass", "reasons": []}})
    )
    client = OPAClient()

    result = client.evaluate("ci_agent/security_policy", FACTS)

    assert result == {"decision": "pass", "reasons": []}
    assert route.called
    # The request body must carry the facts under the "input" key.
    import json

    request = route.calls.last.request
    assert json.loads(request.content) == {"input": FACTS}
    client.close()


@respx.mock
def test_missing_result_returns_empty_dict(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(url__startswith=DEFAULT_BASE_URL).mock(
        return_value=httpx.Response(200, json={})  # OPA answers without "result"
    )
    client = OPAClient()

    assert client.evaluate("ci_agent/security_policy", FACTS) == {}
    client.close()


@respx.mock
def test_timeout_raises_opa_unavailable(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(url__startswith=DEFAULT_BASE_URL).mock(
        side_effect=httpx.ConnectTimeout("too slow")
    )
    client = OPAClient()

    with pytest.raises(OPAUnavailableError, match="OPA unreachable"):
        client.evaluate("ci_agent/security_policy", FACTS)
    client.close()


@respx.mock
def test_connection_refused_raises_opa_unavailable(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(url__startswith=DEFAULT_BASE_URL).mock(
        side_effect=httpx.ConnectError("refused")
    )
    client = OPAClient()

    with pytest.raises(OPAUnavailableError, match="refused"):
        client.evaluate("ci_agent/identity_policy", FACTS)
    client.close()


@respx.mock
def test_http_500_raises_opa_unavailable(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(url__startswith=DEFAULT_BASE_URL).mock(
        return_value=httpx.Response(500, text="boom")
    )
    client = OPAClient()

    with pytest.raises(OPAUnavailableError, match="HTTP 500"):
        client.evaluate("ci_agent/build_policy", FACTS)
    client.close()


@respx.mock
def test_non_json_body_raises_opa_unavailable(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(url__startswith=DEFAULT_BASE_URL).mock(
        return_value=httpx.Response(200, text="<html>")
    )
    client = OPAClient()

    with pytest.raises(OPAUnavailableError, match="non-JSON"):
        client.evaluate("ci_agent/tool_policy", FACTS)
    client.close()


def test_base_url_trailing_slash_normalized() -> None:
    client = OPAClient(base_url="http://localhost:9999/")

    assert client.base_url == "http://localhost:9999"
    client.close()
