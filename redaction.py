"""DLP / output redaction layer for MCP Boss.

Walks dict / list / string payloads and replaces matches of well-known
sensitive patterns with `[REDACTED:<type>]` placeholders so the Gemini
orchestrator never sees raw secrets or PII when the feature is enabled.

The module is deliberately dependency-free: only Python stdlib. It is imported
by `main.py` and exposed via the `ENABLE_OUTPUT_REDACTION` env var (default
OFF). Redaction is applied to tool results before they flow back to the LLM;
audit records go through the un-redacted path so the security team keeps a
truthful record.

Patterns covered:

- Credit-card-looking 16-digit numbers, Luhn-checked.
- SSN-looking `NNN-NN-NNNN` strings, with cheap guards against common
  false positives (IPv4-ish, dates).
- GCP / PEM private key blocks.
- AWS access-key IDs (AKIA...) and secret access keys (40-char base64-ish
  strings labelled `aws_secret_access_key=` or similar).
- JWTs (`eyJ...eyJ...`).
- Common API-key env vars followed by `=` or `:` and a value
  (GTI, Okta, CrowdStrike, generic `api_key` / `token` / `secret`).
"""

from __future__ import annotations

import os
import re
from typing import Any


# ──────────────────────────────────────────────────────────────────────────
# Pattern compilation
# ──────────────────────────────────────────────────────────────────────────

_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# SSN: three digits, two digits, four digits. Excludes obvious IPv4 octets
# and date-like patterns via the guard function below.
_SSN_RE = re.compile(r"\b(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)\b")

_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r"[\s\S]+?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
)

_AWS_AKID_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

# AWS secret access key: 40-char base64-ish preceded by an assignment-like
# indicator. We intentionally require the label to cut false positives, since
# 40-char base64 strings appear in plenty of benign contexts.
_AWS_SECRET_RE = re.compile(
    r"(aws[_-]?secret[_-]?access[_-]?key"
    r"|AWS_SECRET_ACCESS_KEY"
    r"|aws_secret)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# Labelled API-key style assignments. We match a whitelist of well-known env
# var / key names to avoid redacting every `x: y` pair in tool output.
_LABELLED_SECRET_RE = re.compile(
    r"(GTI_API_KEY"
    r"|OKTA_API_TOKEN"
    r"|CROWDSTRIKE_CLIENT_SECRET"
    r"|AZURE_AD_CLIENT_SECRET"
    r"|O365_CLIENT_SECRET"
    r"|APPROVAL_WEBHOOK_SECRET"
    r"|api[_-]?key"
    r"|bearer[_-]?token"
    r"|client[_-]?secret"
    r"|access[_-]?token)"
    r"\s*[:=]\s*['\"]?"
    r"([A-Za-z0-9._\-]{16,})"
    r"['\"]?",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _luhn_ok(digits: str) -> bool:
    """Standard Luhn mod-10 check on a digit-only string."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _looks_like_date(s: str) -> bool:
    # Cheap filter: YYYY-MM-DD-ish or MM-DD-YYYY-ish where the first field is 4 digits
    # or the last field is 4 digits and months/days are in range.
    parts = s.split("-")
    if len(parts) != 3:
        return False
    a, b, c = parts
    if len(a) == 4 and a.isdigit() and b.isdigit() and c.isdigit():
        return 1 <= int(b) <= 12 and 1 <= int(c) <= 31
    if len(c) == 4 and a.isdigit() and b.isdigit() and c.isdigit():
        return 1 <= int(a) <= 12 and 1 <= int(b) <= 31
    return False


# ──────────────────────────────────────────────────────────────────────────
# Scalar redaction
# ──────────────────────────────────────────────────────────────────────────

def _redact_pem_blocks(s: str) -> str:
    return _PEM_PRIVATE_KEY_RE.sub("[REDACTED:private_key]", s)


def _redact_jwt(s: str) -> str:
    return _JWT_RE.sub("[REDACTED:jwt]", s)


def _redact_aws(s: str) -> str:
    s = _AWS_AKID_RE.sub("[REDACTED:aws_access_key_id]", s)

    def _sub_secret(m: re.Match) -> str:
        return f"{m.group(1)}=[REDACTED:aws_secret_access_key]"

    s = _AWS_SECRET_RE.sub(_sub_secret, s)
    return s


def _redact_labelled_secrets(s: str) -> str:
    def _sub(m: re.Match) -> str:
        return f"{m.group(1)}=[REDACTED:api_key]"

    return _LABELLED_SECRET_RE.sub(_sub, s)


def _redact_ssn(s: str) -> str:
    def _sub(m: re.Match) -> str:
        full = m.group(0)
        if _looks_like_ip(full) or _looks_like_date(full):
            return full
        return "[REDACTED:ssn]"

    return _SSN_RE.sub(_sub, s)


def _redact_credit_card(s: str) -> str:
    def _sub(m: re.Match) -> str:
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return "[REDACTED:credit_card]"
        return raw

    return _CC_RE.sub(_sub, s)


def redact_string(s: str) -> str:
    """Apply every pattern to a single string."""
    if not s:
        return s
    s = _redact_pem_blocks(s)
    s = _redact_jwt(s)
    s = _redact_aws(s)
    s = _redact_labelled_secrets(s)
    s = _redact_ssn(s)
    s = _redact_credit_card(s)
    return s


# ──────────────────────────────────────────────────────────────────────────
# Recursive walker
# ──────────────────────────────────────────────────────────────────────────

def redact(obj: Any) -> Any:
    """Deep-walk `obj` and return a redacted copy.

    Strings are rewritten through every pattern. Dicts and lists are
    recursively processed. Everything else (numbers, bools, None) passes
    through untouched.
    """
    if isinstance(obj, str):
        return redact_string(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    return obj


def is_enabled() -> bool:
    """True iff ENABLE_OUTPUT_REDACTION is set to a truthy value."""
    v = os.environ.get("ENABLE_OUTPUT_REDACTION", "").strip().lower()
    return v in {"1", "true", "yes", "on"}


def maybe_redact(obj: Any) -> Any:
    """Redact only when the feature flag is on; otherwise return obj as-is."""
    if is_enabled():
        return redact(obj)
    return obj
