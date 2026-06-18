"""Standalone Phase 3 tests. Run: python3 arsenal/tests/test_phase3.py (exit 0 on pass).

No pip install, no server, no main.py. Uses only contracts + the Phase 3 modules.
"""

import os
import sys

# Make the repo root importable so `import arsenal.*` works when run directly.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from arsenal.contracts import (
    ActionKind,
    AutonomyClass,
    RemediationPlan,
    RemediationStep,
)
from arsenal.autopilot import AutonomyGate, AutonomyPolicy
from arsenal.playbooks import match_playbook, get_playbook


def _build_plan():
    """One step per outcome we want to exercise."""
    add_comment = RemediationStep(
        kind=ActionKind.ADD_COMMENT,
        args={"case_id": "C-1", "comment": "auto-doc"},
        reversible=True,
        confidence=0.99,
        blast_radius={"cases": 1},
        rationale="document the case",
    )
    soft_purge = RemediationStep(
        kind=ActionKind.O365_PURGE,
        args={"target_mailbox": "a@x.com", "message_id": "m1", "purge_type": "softDelete"},
        reversible=True,
        confidence=0.95,
        blast_radius={"mailboxes": 3},
        rationale="recoverable phishing purge",
    )
    hard_purge = RemediationStep(
        kind=ActionKind.O365_PURGE,
        args={"target_mailbox": "a@x.com", "message_id": "m1", "purge_type": "hardDelete"},
        reversible=False,
        confidence=0.99,
        blast_radius={"mailboxes": 1},
        rationale="unrecoverable purge",
    )
    # GCP SA key revocation DELETES keys (permanent) -> the irreversible example.
    aws_revoke = RemediationStep(
        kind=ActionKind.GCP_REVOKE_SA_KEYS,
        args={"project_id": "p", "service_account_email": "sa@p.iam.gserviceaccount.com"},
        reversible=False,
        confidence=0.99,
        blast_radius={"keys": 1},
        rationale="revoke leaked keys (permanent delete)",
    )
    okta_suspend = RemediationStep(
        kind=ActionKind.OKTA_SUSPEND,
        args={"user_email": "u@x.com"},
        reversible=True,            # reversible, but NOT on the auto allow-list
        confidence=0.99,
        blast_radius={"users": 1},
        rationale="suspend compromised user",
    )
    low_conf = RemediationStep(
        kind=ActionKind.ADD_COMMENT,   # allow-listed kind, but confidence too low
        args={"case_id": "C-1", "comment": "maybe"},
        reversible=True,
        confidence=0.40,
        blast_radius={"cases": 1},
        rationale="uncertain note",
    )
    plan = RemediationPlan(
        detection_id="DET-1",
        summary="mixed remediation plan",
        steps=[add_comment, soft_purge, hard_purge, aws_revoke, okta_suspend, low_conf],
    )
    return plan, {
        "add_comment": add_comment,
        "soft_purge": soft_purge,
        "hard_purge": hard_purge,
        "aws_revoke": aws_revoke,
        "okta_suspend": okta_suspend,
        "low_conf": low_conf,
    }


def _eq(label, got, want):
    assert got == want, f"FAIL {label}: got {got!r}, want {want!r}"
    print(f"PASS {label}: {got}")


def test_classify():
    gate = AutonomyGate()
    _, s = _build_plan()
    _eq("classify add_comment", gate.classify(s["add_comment"]), AutonomyClass.AUTO)
    _eq("classify soft_purge", gate.classify(s["soft_purge"]), AutonomyClass.AUTO)
    _eq("classify hard_purge", gate.classify(s["hard_purge"]), AutonomyClass.BLOCKED)
    _eq("classify aws_revoke", gate.classify(s["aws_revoke"]), AutonomyClass.BLOCKED)
    _eq("classify okta_suspend", gate.classify(s["okta_suspend"]), AutonomyClass.GATED)
    _eq("classify low_conf", gate.classify(s["low_conf"]), AutonomyClass.GATED)


def test_split_plan():
    gate = AutonomyGate()
    plan, s = _build_plan()
    buckets = gate.split_plan(plan)

    _eq("auto bucket size", len(buckets["auto"]), 2)
    _eq("gated bucket size", len(buckets["gated"]), 2)
    _eq("blocked bucket size", len(buckets["blocked"]), 2)

    assert s["add_comment"] in buckets["auto"]
    assert s["soft_purge"] in buckets["auto"]
    assert s["hard_purge"] in buckets["blocked"]
    assert s["aws_revoke"] in buckets["blocked"]
    assert s["okta_suspend"] in buckets["gated"]
    assert s["low_conf"] in buckets["gated"]
    print("PASS split_plan: steps land in the right buckets")

    # Mutation: step.autonomy reflects the decided class.
    _eq("mutated add_comment.autonomy", s["add_comment"].autonomy, AutonomyClass.AUTO)
    _eq("mutated hard_purge.autonomy", s["hard_purge"].autonomy, AutonomyClass.BLOCKED)
    _eq("mutated okta_suspend.autonomy", s["okta_suspend"].autonomy, AutonomyClass.GATED)


def test_auto_cap_downgrades_overflow():
    # Cap of 1: only the first AUTO survives; the rest are downgraded to GATED.
    gate = AutonomyGate(AutonomyPolicy(max_auto_actions_per_run=1))
    plan, _ = _build_plan()
    buckets = gate.split_plan(plan)
    _eq("capped auto bucket size", len(buckets["auto"]), 1)
    # Two would-be-AUTO steps; one downgraded into gated. gated was 2, now 3.
    _eq("capped gated bucket size", len(buckets["gated"]), 3)
    _eq("capped blocked bucket size", len(buckets["blocked"]), 2)
    for st in buckets["auto"]:
        assert st.autonomy == AutonomyClass.AUTO
    print("PASS auto_cap: overflow AUTO downgraded to GATED")


def test_explain():
    gate = AutonomyGate()
    plan, _ = _build_plan()
    text = gate.explain(plan)
    assert "WOULD AUTO-RUN" in text
    assert "BLOCKED" in text
    assert "HELD FOR APPROVAL" in text
    print("PASS explain: produced a human-readable breakdown")


def test_match_playbook():
    pb = match_playbook(
        {"type": "PHISHING", "name": "Mass phishing campaign"},
        "Malicious email delivered to 30 mailboxes",
    )
    assert pb is not None, "FAIL match_playbook: expected a match for phishing detection"
    _eq("match_playbook phishing", pb.name, "phishing_blast")

    # Sanity: the other two templates match their own keywords.
    cred = match_playbook({"type": "Impossible travel"}, "credential theft suspected")
    _eq("match_playbook credential", cred.name, "credential_theft")
    mal = match_playbook({"category": "malware"}, "ransomware beacon on host-7")
    _eq("match_playbook malware", mal.name, "malware_host")

    # Phishing playbook's first step is an auto-eligible softDelete purge.
    phish = get_playbook("phishing_blast")
    _eq("phishing first step kind", phish.steps[0].kind, ActionKind.O365_PURGE)
    _eq("phishing first step autonomy", phish.steps[0].default_autonomy, AutonomyClass.AUTO)
    _eq("phishing softDelete default", phish.steps[0].arg_defaults.get("purge_type"), "softDelete")

    # No match returns None.
    assert match_playbook({"type": "benign"}, "nothing interesting") is None
    print("PASS match_playbook: no-match returns None")


def main():
    test_classify()
    test_split_plan()
    test_auto_cap_downgrades_overflow()
    test_explain()
    test_match_playbook()
    print("\nALL PHASE 3 TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
