"""Arsenal Phase 1 — SecOps connector.

Reads detections and cases from a customer's own SecOps tenant and extracts
candidate remediation targets (users, hosts, IPs, mailboxes, AWS users, GCP SAs)
from arbitrarily-shaped detection payloads.

All tool invocation flows through an injected `tool_runner(tool_name, **args) -> str`
that returns the tool's JSON string. This module never imports main.py and makes no
network calls at import time, so it is unit-testable with a fake runner.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List

from .contracts import SecOpsTenant

ToolRunner = Callable[..., str]

# ── extraction heuristics ────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HOSTNAME_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9\-]+)*\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

# A GCP service-account email always ends in one of these suffixes.
_GCP_SA_SUFFIXES = (
    ".iam.gserviceaccount.com",
    ".gserviceaccount.com",
)

# Keys whose values tend to carry hostnames in real Chronicle/UDM detections.
_HOST_KEYS = {
    "hostname", "host", "host_name", "asset", "asset_id", "device", "device_name",
    "machine", "machine_name", "computer", "computer_name", "principal_hostname",
    "target_hostname", "src_hostname", "dst_hostname",
}
_MAILBOX_KEYS = {"mailbox", "target_mailbox", "recipient", "to", "to_address", "email_to"}


def _is_gcp_sa(email: str) -> bool:
    return any(email.endswith(sfx) for sfx in _GCP_SA_SUFFIXES)


def _looks_like_hostname(val: str) -> bool:
    if not val or len(val) > 253 or " " in val:
        return False
    if "@" in val:
        return False
    if _IPV4_RE.fullmatch(val):
        return False
    # require either a dot (FQDN) or a recognizable host-ish token without a dot
    return bool(_HOSTNAME_RE.fullmatch(val))


class SecOpsConnector:
    """Bring-your-own-SecOps reader/writer scoped to a single tenant."""

    def __init__(self, tenant: SecOpsTenant, tool_runner: ToolRunner):
        self.tenant = tenant
        self._run = tool_runner

    # ── tool plumbing ────────────────────────────────────────────────────────

    @staticmethod
    def _parse(raw: str) -> Any:
        if isinstance(raw, (dict, list)):
            return raw
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return {}

    @staticmethod
    def _unwrap_list(parsed: Any, *keys: str) -> List[dict]:
        """Pull a list out of a possibly-wrapped tool response."""
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
        if isinstance(parsed, dict):
            for k in keys:
                v = parsed.get(k)
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
            # fall back to the first list-valued field
            for v in parsed.values():
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
        return []

    # ── reads ────────────────────────────────────────────────────────────────

    def list_detections(self, hours_back: int = 24, max_results: int = 50) -> List[dict]:
        raw = self._run(
            "list_secops_detections", hours_back=hours_back, max_results=max_results
        )
        parsed = self._parse(raw)
        return self._unwrap_list(parsed, "detections", "alerts", "results")

    def list_cases(self) -> List[dict]:
        raw = self._run("list_cases")
        parsed = self._parse(raw)
        return self._unwrap_list(parsed, "cases", "results", "data")

    def get_case(self, case_id: str) -> dict:
        raw = self._run("get_case_alerts", case_id=case_id)
        parsed = self._parse(raw)
        if isinstance(parsed, dict):
            return parsed
        return {"alerts": parsed} if isinstance(parsed, list) else {}

    # ── the single write (advisory phase otherwise) ──────────────────────────

    def write_case_comment(self, case_id: str, comment: str) -> dict:
        raw = self._run("add_case_comment", case_id=case_id, comment=comment)
        parsed = self._parse(raw)
        return parsed if isinstance(parsed, dict) else {"result": parsed}

    # ── entity extraction ────────────────────────────────────────────────────

    def extract_entities(self, detection: dict) -> Dict[str, List[str]]:
        """Heuristically scan a detection for remediation targets.

        Returns deduped, order-preserved lists:
          {"users", "hosts", "mailboxes", "aws_users", "gcp_sas", "ips", "aws_keys"}
        """
        users: List[str] = []
        hosts: List[str] = []
        mailboxes: List[str] = []
        gcp_sas: List[str] = []
        aws_users: List[str] = []
        aws_keys: List[str] = []
        ips: List[str] = []

        def add(bucket: List[str], val: str) -> None:
            val = val.strip()
            if val and val not in bucket:
                bucket.append(val)

        def walk(node: Any, key_hint: str = "") -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    lk = str(k).lower()
                    walk(v, lk)
            elif isinstance(node, list):
                for item in node:
                    walk(item, key_hint)
            elif isinstance(node, str):
                _scan_scalar(node, key_hint)
            # ints/floats/bools/None: nothing to extract

        def _scan_scalar(s: str, key_hint: str) -> None:
            # emails first — classify into user / mailbox / gcp_sa
            for m in _EMAIL_RE.findall(s):
                if _is_gcp_sa(m):
                    add(gcp_sas, m)
                else:
                    add(users, m)
                    if any(h in key_hint for h in _MAILBOX_KEYS) or "mailbox" in key_hint:
                        add(mailboxes, m)
            # IPs
            for m in _IPV4_RE.findall(s):
                add(ips, m)
            # AWS access-key ids
            for m in _AWS_KEY_RE.findall(s):
                add(aws_keys, m)
            # AWS IAM usernames carried in aws-flavored keys
            if ("aws" in key_hint and ("user" in key_hint or "principal" in key_hint)) and "@" not in s:
                if _IPV4_RE.fullmatch(s) is None and " " not in s and s:
                    add(aws_users, s)
            # hostnames: only trust scalars sitting under a host-ish key, to avoid
            # treating every dotted token (domains, urls) as a host.
            if any(hk == key_hint or hk in key_hint for hk in _HOST_KEYS):
                if _looks_like_hostname(s):
                    add(hosts, s)

        walk(detection)

        return {
            "users": users,
            "hosts": hosts,
            "mailboxes": mailboxes,
            "aws_users": aws_users,
            "gcp_sas": gcp_sas,
            "ips": ips,
            "aws_keys": aws_keys,
        }
