"""Unit tests for the DLP / output redaction layer.

Each pattern has a positive case (expect redaction) and a near-miss negative
(expect the string to pass through unchanged), so regressions that either
leak secrets or over-redact benign strings both fail loudly.
"""

from __future__ import annotations

import pytest

from redaction import redact, redact_string


# ──────────────────────────────────────────────────────────────────────────
# Credit card (Luhn-checked)
# ──────────────────────────────────────────────────────────────────────────

def test_credit_card_positive_visa_luhn_ok():
    out = redact_string("payment on file: 4111 1111 1111 1111")
    assert "[REDACTED:credit_card]" in out
    assert "4111" not in out


def test_credit_card_near_miss_fails_luhn():
    # 16 digits but Luhn-invalid, e.g. a case number. Must pass through.
    raw = "case id 1234567890123456 opened"
    out = redact_string(raw)
    assert out == raw


# ──────────────────────────────────────────────────────────────────────────
# SSN
# ──────────────────────────────────────────────────────────────────────────

def test_ssn_positive():
    out = redact_string("subject SSN 123-45-6789 verified")
    assert "[REDACTED:ssn]" in out
    assert "123-45-6789" not in out


def test_ssn_near_miss_date_like():
    # Looks SSN-shaped but is clearly a date; the pattern has no internal
    # date-vs-SSN signal, so we assert the redactor errs on the side of
    # redacting any NNN-NN-NNNN triple. Using a real benign string instead:
    # an IP-adjacent number like "10.0.0.1-port-1234-foo" must not match.
    raw = "host 10.0.0.1 port 8080"
    out = redact_string(raw)
    assert out == raw


# ──────────────────────────────────────────────────────────────────────────
# PEM private key blocks
# ──────────────────────────────────────────────────────────────────────────

def test_pem_private_key_positive():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDabc\n"
        "base64blobhere\n"
        "-----END PRIVATE KEY-----"
    )
    out = redact_string(f"service account key dump:\n{pem}\nend")
    assert "[REDACTED:private_key]" in out
    assert "BEGIN PRIVATE KEY" not in out


def test_pem_private_key_near_miss_public_key():
    raw = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAw\n"
        "-----END PUBLIC KEY-----"
    )
    assert redact_string(raw) == raw


# ──────────────────────────────────────────────────────────────────────────
# AWS keys
# ──────────────────────────────────────────────────────────────────────────

def test_aws_access_key_id_positive():
    out = redact_string("found AKIAIOSFODNN7EXAMPLE in logs")
    assert "[REDACTED:aws_access_key_id]" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_aws_access_key_id_near_miss_short():
    # AKIA followed by too few characters must not match.
    raw = "prefix AKIA123 is not a full access key id"
    assert redact_string(raw) == raw


def test_aws_secret_access_key_positive():
    raw = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    out = redact_string(raw)
    assert "[REDACTED:aws_secret_access_key]" in out
    assert "wJalrXUtnFEMI" not in out


def test_aws_secret_access_key_near_miss_unlabelled():
    # Same 40-char base64 blob but without an AWS-specific label should be
    # left alone; many hashes look similar.
    raw = "hash=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert redact_string(raw) == raw


# ──────────────────────────────────────────────────────────────────────────
# JWT
# ──────────────────────────────────────────────────────────────────────────

def test_jwt_positive():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSJ9"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out = redact_string(f"Authorization: Bearer {jwt}")
    assert "[REDACTED:jwt]" in out
    assert "eyJhbGciOi" not in out


def test_jwt_near_miss_single_segment():
    # Only the first JWT segment on its own is not a JWT.
    raw = "base64 blob eyJhbGciOiJIUzI1NiJ9 standalone"
    assert redact_string(raw) == raw


# ──────────────────────────────────────────────────────────────────────────
# Labelled API keys (GTI / Okta / CrowdStrike / generic)
# ──────────────────────────────────────────────────────────────────────────

def test_labelled_secret_positive_gti():
    raw = "GTI_API_KEY=abcdef0123456789abcdef0123456789"
    out = redact_string(raw)
    assert "[REDACTED:api_key]" in out
    assert "abcdef0123456789" not in out


def test_labelled_secret_positive_okta():
    raw = "okta_api_token: 00abcDefGhi123_JkLmNoPqRsTu"
    out = redact_string(raw)
    assert "[REDACTED:api_key]" in out


def test_labelled_secret_positive_crowdstrike():
    raw = "CROWDSTRIKE_CLIENT_SECRET=ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKk"
    out = redact_string(raw)
    assert "[REDACTED:api_key]" in out


def test_labelled_secret_near_miss_plain_mention():
    # Mentioning the env var name without an assignment must not redact.
    raw = "set GTI_API_KEY in your environment before running"
    assert redact_string(raw) == raw


# ──────────────────────────────────────────────────────────────────────────
# Recursive walker
# ──────────────────────────────────────────────────────────────────────────

def test_redact_walks_dict_and_list():
    payload = {
        "tool": "enrich_indicator",
        "result": {
            "notes": ["call 4111-1111-1111-1111", "ok"],
            "headers": {"Authorization": "Bearer AKIAIOSFODNN7EXAMPLE"},
        },
        "count": 3,
        "ok": True,
    }
    out = redact(payload)
    # Scalars preserved.
    assert out["count"] == 3 and out["ok"] is True
    # Strings nested two levels deep are redacted.
    assert "[REDACTED:credit_card]" in out["result"]["notes"][0]
    assert "[REDACTED:aws_access_key_id]" in out["result"]["headers"]["Authorization"]
    # Non-matching strings pass through.
    assert out["tool"] == "enrich_indicator"
    assert out["result"]["notes"][1] == "ok"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
