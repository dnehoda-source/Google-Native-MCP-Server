#!/usr/bin/env python3
"""Standalone Phase 1 tests. Run: `python3 arsenal/tests/test_phase1.py` (exit 0 on pass).

Uses a fake tool_runner returning canned JSON; no network, no main.py import.
"""

from __future__ import annotations

import json
import os
import sys

# Make the repo root importable so `arsenal` is a package regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from arsenal.connector import SecOpsConnector
from arsenal.contracts import ActionKind, AutonomyClass, SecOpsTenant
from arsenal.planner import RemediationPlanner


# ── canned detection: a compromised user + a phishing mailbox + a host ───────
CANNED_DETECTION = {
    "id": "de_12345",
    "ruleName": "phishing_credential_harvest",
    "category": "PHISHING",
    "detection": {
        "outcomes": [
            {"principal_user_email": "alice@corp.example.com"},
            {"target_mailbox": "alice@corp.example.com"},
            {"message_id": "<abc123@mailer.evil.test>"},
            {"hostname": "WIN-DESKTOP-07.corp.example.com"},
            {"src_ip": "203.0.113.42"},
            {"aws_user": "svc-deploy"},
            {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
            {"service_account": "leaked-sa@my-project.iam.gserviceaccount.com"},
        ]
    },
    "project_id": "my-project",
}


def _fake_runner(tool_name: str, **args) -> str:
    if tool_name == "list_secops_detections":
        return json.dumps({"detections": [CANNED_DETECTION], "count": 1})
    if tool_name == "list_cases":
        return json.dumps({"cases": [{"id": "case-1"}, {"id": "case-2"}]})
    if tool_name == "get_case_alerts":
        return json.dumps({"case_id": args.get("case_id"), "alerts": [{"id": "al-1"}]})
    if tool_name == "add_case_comment":
        return json.dumps({"status": "ok", "case_id": args.get("case_id")})
    return json.dumps({"error": f"unexpected tool {tool_name}"})


def check(cond: bool, label: str) -> None:
    if cond:
        print(f"PASS: {label}")
    else:
        print(f"FAIL: {label}")
        raise AssertionError(label)


def main() -> int:
    tenant = SecOpsTenant(name="acme", project_id="my-project", customer_id="cust-1")
    conn = SecOpsConnector(tenant, _fake_runner)

    # ── connector reads ──────────────────────────────────────────────────────
    dets = conn.list_detections()
    check(len(dets) == 1 and dets[0]["id"] == "de_12345", "list_detections unwraps {detections:[...]}")

    cases = conn.list_cases()
    check(len(cases) == 2, "list_cases unwraps {cases:[...]}")

    case = conn.get_case("case-1")
    check(case.get("case_id") == "case-1", "get_case returns dict via get_case_alerts")

    wrote = conn.write_case_comment("case-1", "hello")
    check(wrote.get("status") == "ok", "write_case_comment posts via add_case_comment")

    # ── entity extraction ────────────────────────────────────────────────────
    ents = conn.extract_entities(CANNED_DETECTION)
    check("alice@corp.example.com" in ents["users"], "extract: user email found")
    check("alice@corp.example.com" in ents["mailboxes"], "extract: mailbox found")
    check("WIN-DESKTOP-07.corp.example.com" in ents["hosts"], "extract: hostname found")
    check("203.0.113.42" in ents["ips"], "extract: IP found")
    check("svc-deploy" in ents["aws_users"], "extract: aws_user found")
    check("AKIAIOSFODNN7EXAMPLE" in ents["aws_keys"], "extract: aws access key found")
    check(
        "leaked-sa@my-project.iam.gserviceaccount.com" in ents["gcp_sas"],
        "extract: gcp service account classified as gcp_sa (not user)",
    )
    check(
        "leaked-sa@my-project.iam.gserviceaccount.com" not in ents["users"],
        "extract: gcp SA NOT misclassified as user",
    )

    # ── planning ─────────────────────────────────────────────────────────────
    planner = RemediationPlanner()
    plan = planner.plan(CANNED_DETECTION, ents, tenant_name=tenant.name)

    kinds = [s.kind for s in plan.steps]
    expected = {
        ActionKind.OKTA_SUSPEND,
        ActionKind.AZURE_REVOKE_SESSIONS,
        ActionKind.AWS_REVOKE_KEYS,
        ActionKind.GCP_REVOKE_SA_KEYS,
        ActionKind.CROWDSTRIKE_ISOLATE,
        ActionKind.O365_PURGE,
        ActionKind.CREATE_CASE,
        ActionKind.ADD_COMMENT,
    }
    for k in expected:
        check(k in kinds, f"plan contains {k.name}")

    # CREATE_CASE then ADD_COMMENT are always the last two, in order
    check(
        kinds[-2] == ActionKind.CREATE_CASE and kinds[-1] == ActionKind.ADD_COMMENT,
        "plan ends with CREATE_CASE then ADD_COMMENT",
    )

    by_kind = {}
    for s in plan.steps:
        by_kind.setdefault(s.kind, s)

    # reversible flags align with tool_previews.py
    check(by_kind[ActionKind.OKTA_SUSPEND].reversible is True, "okta suspend reversible")
    check(by_kind[ActionKind.AZURE_REVOKE_SESSIONS].reversible is True, "azure revoke reversible")
    check(by_kind[ActionKind.CROWDSTRIKE_ISOLATE].reversible is True, "crowdstrike isolate reversible")
    check(by_kind[ActionKind.AWS_REVOKE_KEYS].reversible is True, "aws key revoke reversible (deactivate)")
    check(by_kind[ActionKind.GCP_REVOKE_SA_KEYS].reversible is False, "gcp SA revoke NOT reversible")

    # o365 purge defaults to reversible softDelete
    o365 = by_kind[ActionKind.O365_PURGE]
    check(o365.args.get("purge_type") == "softDelete", "o365 purge defaults to softDelete")
    check(o365.reversible is True, "o365 softDelete reversible")
    check(o365.args.get("message_id") == "<abc123@mailer.evil.test>", "o365 carries message_id")

    # autonomy: destructive GATED, case/comment AUTO
    check(by_kind[ActionKind.OKTA_SUSPEND].autonomy == AutonomyClass.GATED, "destructive step GATED")
    check(by_kind[ActionKind.CREATE_CASE].autonomy == AutonomyClass.AUTO, "create_case AUTO")
    check(by_kind[ActionKind.ADD_COMMENT].autonomy == AutonomyClass.AUTO, "add_comment AUTO")

    # gcp step carries project_id from the detection
    check(
        by_kind[ActionKind.GCP_REVOKE_SA_KEYS].args.get("project_id") == "my-project",
        "gcp step carries project_id",
    )

    # plan metadata
    check(plan.detection_id == "de_12345", "plan.detection_id set")
    check(plan.source_tenant == "acme", "plan.source_tenant set")

    # ── negative: a non-phishing detection with no mailbox -> no O365 purge ──
    benign = {"id": "de_999", "ruleName": "bruteforce", "detection": {"hostname": "srv-01.corp.example.com"}}
    bents = conn.extract_entities(benign)
    bplan = planner.plan(benign, bents)
    bkinds = [s.kind for s in bplan.steps]
    check(ActionKind.O365_PURGE not in bkinds, "no O365 purge when not phishing / no mailbox")
    check(ActionKind.CROWDSTRIKE_ISOLATE in bkinds, "host-only detection still isolates host")

    print("\nALL PHASE 1 TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
