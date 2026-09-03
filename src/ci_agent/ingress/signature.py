"""HMAC-SHA256 webhook signature verification (Batch 2, Task B).

Pure functions, independently testable — no FastAPI, no DB. Implements the
GitHub ``X-Hub-Signature-256`` scheme with a constant-time comparison
(Report Section 4.2: "Validate ... event identity/signature").
"""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_PREFIX: str = "sha256="


def compute_signature(secret: bytes, payload: bytes) -> str:
    """Return the ``sha256=...`` signature header value for ``payload``."""
    digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify_signature(secret: bytes, payload: bytes, header_value: str) -> bool:
    """Verify a GitHub-style HMAC-SHA256 signature header against raw bytes.

    Returns ``False`` for any malformed header (wrong prefix, wrong length,
    non-hex digest) and for any mismatch. Uses ``hmac.compare_digest`` so the
    comparison is constant-time.
    """
    if not header_value or not header_value.lower().startswith(SIGNATURE_PREFIX):
        return False
    expected = compute_signature(secret, payload)
    return hmac.compare_digest(expected.encode("utf-8"), header_value.encode("utf-8"))
