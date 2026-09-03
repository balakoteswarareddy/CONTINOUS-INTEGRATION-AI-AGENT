"""Unit tests for HMAC signature verification (Batch 2, Task B)."""

from __future__ import annotations

import hashlib
import hmac

from ci_agent.ingress.signature import compute_signature, verify_signature

SECRET = b"whsec-test-secret"
PAYLOAD = b'{"action": "opened"}'


def _sign(secret: bytes, payload: bytes) -> str:
    return "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()


class TestVerifySignature:
    def test_valid_signature_passes(self) -> None:
        assert verify_signature(SECRET, PAYLOAD, _sign(SECRET, PAYLOAD)) is True

    def test_tampered_payload_fails(self) -> None:
        signature = _sign(SECRET, PAYLOAD)
        tampered = PAYLOAD + b" "

        assert verify_signature(SECRET, tampered, signature) is False

    def test_wrong_secret_fails(self) -> None:
        signature = _sign(b"other-secret", PAYLOAD)

        assert verify_signature(SECRET, PAYLOAD, signature) is False

    def test_missing_prefix_fails(self) -> None:
        raw_hex = hmac.new(SECRET, PAYLOAD, hashlib.sha256).hexdigest()

        assert verify_signature(SECRET, PAYLOAD, raw_hex) is False
        assert verify_signature(SECRET, PAYLOAD, "md5=" + raw_hex) is False

    def test_wrong_case_prefix_fails(self) -> None:
        # GitHub sends lowercase "sha256=" exactly; anything else is invalid.
        raw_hex = hmac.new(SECRET, PAYLOAD, hashlib.sha256).hexdigest()

        assert verify_signature(SECRET, PAYLOAD, "SHA256=" + raw_hex) is False

    def test_truncated_digest_fails(self) -> None:
        signature = _sign(SECRET, PAYLOAD)

        assert verify_signature(SECRET, PAYLOAD, signature[:-4]) is False

    def test_empty_payload_is_signable(self) -> None:
        assert verify_signature(SECRET, b"", _sign(SECRET, b"")) is True

    def test_compute_signature_matches_manual_hmac(self) -> None:
        expected = "sha256=" + hmac.new(SECRET, PAYLOAD, hashlib.sha256).hexdigest()

        assert compute_signature(SECRET, PAYLOAD) == expected
