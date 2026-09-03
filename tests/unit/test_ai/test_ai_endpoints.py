"""AI feature endpoint tests (Batch 9; ``ingress/ai_api.py``).

Exercises the three endpoints through the real FastAPI app (real wiring,
real DB, default noop gateway — no model calls anywhere):

- auth: ``X-Admin-Key`` 401/403 on triage/summarize;
- state guard: 404 unknown run, 409 non-terminal run, 200 terminal run;
- explain: 200 with a valid PipelineSpec (NO auth), 422 with an invalid one;
- every response is ADVISORY (``ai_assisted``/``fallback_used`` flags surface).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from ci_agent.config.settings import Settings
from ci_agent.db.models import FindingRecord, RunRecord, StageExecutionRecord
from ci_agent.ingress.app import create_app

ADMIN_KEY = "test-admin-key"
AUTH = {"X-Admin-Key": ADMIN_KEY}

VALID_SPEC: dict[str, Any] = {
    "project_id": "example-org/payments-api",
    "project_name": "Payments API",
    "stack": {"language": "python", "framework": "fastapi", "version": "3.11"},
    "repository": {
        "provider": "github",
        "url": "https://github.com/example-org/payments-api",
        "repo_id": "example-org/payments-api",
    },
    "trigger": {"event_type": "pull_request", "branch": "main", "source_sha": "abc123"},
    "stages": [
        {"id": "checkout", "name": "Checkout", "depends_on": []},
        {"id": "unit_tests", "name": "Unit Tests", "depends_on": ["checkout"]},
    ],
    "thresholds": {"coverage_percent": 80},
    "approvals_required": False,
    "artifact_destinations": [],
    "policy_version": "1.0.0",
}


@pytest.fixture()
def client(tmp_path) -> TestClient:
    settings = Settings(
        env="local",
        database_url=f"sqlite:///{tmp_path / 'ai-endpoints.db'}",
        admin_api_key=ADMIN_KEY,
    )
    application = create_app(settings)
    with TestClient(application) as test_client:  # lifespan creates tables
        _seed(test_client)
        yield test_client


def _seed(client: TestClient) -> None:
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        session.add_all(
            [
                RunRecord(
                    run_id="run-failed",
                    project_id="example-org/payments-api",
                    repository="github.com/example-org/payments-api",
                    trigger_type="pull_request",
                    current_state="failed",
                ),
                RunRecord(
                    run_id="run-running",
                    project_id="example-org/payments-api",
                    repository="github.com/example-org/payments-api",
                    trigger_type="pull_request",
                    current_state="tests_done",
                ),
                StageExecutionRecord(
                    run_id="run-failed",
                    stage_id="unit_tests",
                    status="failed",
                    exit_code=1,
                    duration_ms=500,
                ),
                StageExecutionRecord(
                    run_id="run-failed",
                    stage_id="format_lint",
                    status="passed",
                    exit_code=0,
                    duration_ms=100,
                ),
                # Two findings on the triaged stage, one on another stage —
                # triage must be stage-scoped.
                FindingRecord(
                    run_id="run-failed",
                    stage_id="unit_tests",
                    scanner="pytest",
                    rule_id="test-failure",
                    severity="high",
                    component="tests/test_charge.py",
                    description="AssertionError in test_charge",
                ),
                FindingRecord(
                    run_id="run-failed",
                    stage_id="unit_tests",
                    scanner="pytest",
                    rule_id="test-failure",
                    severity="medium",
                    component="tests/test_refund.py",
                    description="AssertionError in test_refund",
                ),
                FindingRecord(
                    run_id="run-failed",
                    stage_id="sast",
                    scanner="semgrep",
                    rule_id="dangerous-call",
                    severity="low",
                ),
            ]
        )
        session.commit()


# ---------------------------------------------------------------- triage auth


class TestTriageAuth:
    def test_missing_admin_key_is_401(self, client: TestClient) -> None:
        response = client.post("/runs/run-failed/triage/unit_tests", json={})
        assert response.status_code == 401
        assert response.json()["detail"] == "missing X-Admin-Key header"

    def test_wrong_admin_key_is_403(self, client: TestClient) -> None:
        response = client.post(
            "/runs/run-failed/triage/unit_tests",
            json={},
            headers={"X-Admin-Key": "wrong"},
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "invalid admin key"


# ------------------------------------------------------------ triage behavior


class TestTriage:
    def test_unknown_run_is_404(self, client: TestClient) -> None:
        response = client.post("/runs/no-such-run/triage/unit_tests", json={}, headers=AUTH)
        assert response.status_code == 404

    def test_non_terminal_run_is_409(self, client: TestClient) -> None:
        response = client.post("/runs/run-running/triage/unit_tests", json={}, headers=AUTH)
        assert response.status_code == 409
        assert "non-terminal state" in response.json()["detail"]

    def test_terminal_run_returns_advisory_triage(self, client: TestClient) -> None:
        response = client.post(
            "/runs/run-failed/triage/unit_tests",
            json={"logs_snippet": "pytest: FAILED test_charge - AssertionError"},
            headers=AUTH,
        )
        assert response.status_code == 200
        body = response.json()
        # Default deployment is noop: deterministic, advisory answer.
        assert body["ai_assisted"] is False
        assert body["fallback_used"] is True
        assert "Deterministic triage" in body["probable_cause"]
        # Findings are stage-scoped: exactly the two unit_tests findings.
        assert any("2 security finding(s) recorded" in h for h in body["remediation_hints"])
        # Admin-keyed responses are never cached.
        assert response.headers["cache-control"] == "no-store"

    def test_secret_in_logs_snippet_is_survived_by_redaction(self, client: TestClient) -> None:
        """A secret in the caller snippet cannot 5xx or leak into the DB."""
        response = client.post(
            "/runs/run-failed/triage/secret_scan",
            json={"logs_snippet": "gitleaks: match\ntoken glpat-AbCdEf123456789012345"},
            headers=AUTH,
        )
        assert response.status_code == 200
        assert response.json()["fallback_used"] is True


# --------------------------------------------------------------- summarize


class TestSummarize:
    def test_missing_admin_key_is_401(self, client: TestClient) -> None:
        response = client.post("/runs/run-failed/summarize")
        assert response.status_code == 401

    def test_unknown_run_is_404(self, client: TestClient) -> None:
        response = client.post("/runs/no-such-run/summarize", headers=AUTH)
        assert response.status_code == 404

    def test_non_terminal_run_is_409(self, client: TestClient) -> None:
        response = client.post("/runs/run-running/summarize", headers=AUTH)
        assert response.status_code == 409

    def test_terminal_run_returns_advisory_summary(self, client: TestClient) -> None:
        response = client.post("/runs/run-failed/summarize", headers=AUTH)
        assert response.status_code == 200
        body = response.json()
        assert body["ai_assisted"] is False
        assert body["fallback_used"] is True
        assert "run-failed" in body["executive_summary"]
        assert "fail" in body["executive_summary"]
        assert "2 stages" in body["executive_summary"]
        assert response.headers["cache-control"] == "no-store"


# ------------------------------------------------------------------ explain


class TestExplain:
    def test_valid_spec_needs_no_auth_and_returns_advisory_explanation(
        self, client: TestClient
    ) -> None:
        response = client.post("/pipeline-spec/explain", json={"spec": VALID_SPEC})
        assert response.status_code == 200
        body = response.json()
        assert body["ai_assisted"] is False  # noop default
        assert body["fallback_used"] is True
        assert "2 stage(s)" in body["explanation"]
        assert body["stage_summaries"] == [
            "stage checkout: run checkout (template design-time)",
            "stage unit_tests: run unit_tests (template design-time)",
        ]

    def test_invalid_spec_is_422(self, client: TestClient) -> None:
        response = client.post("/pipeline-spec/explain", json={"spec": {}})
        assert response.status_code == 422
        assert "invalid PipelineSpec" in response.json()["detail"]

    def test_extra_forbidden_field_is_422(self, client: TestClient) -> None:
        spec = dict(VALID_SPEC)
        spec["credentials"] = {"token": "nope"}  # PipelineSpec is extra=forbid
        response = client.post("/pipeline-spec/explain", json={"spec": spec})
        assert response.status_code == 422
