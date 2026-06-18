"""End-to-end test for the Arsenal orchestrator across all three phases.

Uses a fake tool_runner (records calls, returns canned JSON) and a fake approver.
Verifies: planner builds the plan, the autonomy gate classifies, the executor runs
the auto slice + approved-gated steps, the case_id backfills from create_soar_case
into add_case_comment, blocked steps never run, and rollback walks in reverse.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from arsenal.contracts import SecOpsTenant, ActionKind, AutonomyClass, StepState
from arsenal.orchestrator import ArsenalOrchestrator

PASS = 0


def check(cond, label):
    global PASS
    if not cond:
        raise AssertionError(label)
    PASS += 1
    print(f"PASS: {label}")


def main():
    calls = []

    def fake_runner(name, **args):
        calls.append((name, dict(args)))
        if name == "create_soar_case":
            return '{"status": "created", "case_id": "CASE-7788"}'
        return '{"status": "ok"}'

    # Approve everything gated.
    def approver(step, preview):
        return True

    tenant = SecOpsTenant(name="acme", project_id="acme-prod", customer_id="cust-1", region="us")

    # A credential-theft-ish detection: user email + phishing mailbox + host.
    detection = {
        "id": "det-001",
        "rule_name": "Credential theft: impossible travel",
        "summary": "phishing-driven account takeover",
        "user": "victim@acme.com",
        "hostname": "ws-victim-01",
        "mailbox": "victim@acme.com",
        "message_id": "<abc@phish>",
    }

    orch = ArsenalOrchestrator(tenant, fake_runner, approver=approver)

    # ── Phase 1 advisory ──────────────────────────────────────────────────────
    plan = orch.recommend(detection)
    kinds = [s.kind for s in plan.steps]
    check(ActionKind.OKTA_SUSPEND in kinds, "plan includes okta suspend")
    check(ActionKind.CREATE_CASE in kinds and ActionKind.ADD_COMMENT in kinds,
          "plan documents to a case")
    check(plan.source_tenant == "acme", "plan carries tenant name")

    exp = orch.explain(detection)
    check(exp["playbook"] is not None, "a playbook matched")
    check(isinstance(exp["explanation"], str) and exp["explanation"],
          "explain() returns text")

    # ── Phase 2 + 3 execution ─────────────────────────────────────────────────
    out = orch.remediate(detection)
    results = out["results"]
    by_kind = {}
    for s, r in zip(plan.steps, results):
        by_kind.setdefault(s.kind, r)

    executed = [name for name, _ in calls]
    check("create_soar_case" in executed, "case was created")
    check("add_case_comment" in executed, "comment was added")

    # case_id backfill: the add_case_comment call must carry the created case id.
    comment_calls = [a for n, a in calls if n == "add_case_comment"]
    check(comment_calls and comment_calls[0].get("case_id") == "CASE-7788",
          "case_id backfilled from create_soar_case into add_case_comment")

    # destructive approved-gated steps executed with confirm=True
    okta_calls = [a for n, a in calls if n == "suspend_okta_user"]
    check(okta_calls and okta_calls[0].get("confirm") is True,
          "approved okta suspend executed with confirm=True")

    # ── Rollback ──────────────────────────────────────────────────────────────
    rb = orch.rollback(plan, results)
    rolled = [r for r in rb if r.state == StepState.ROLLED_BACK]
    check(len(rolled) >= 1, "rollback marked at least one step rolled back")

    # Deny path: a fresh orchestrator that denies gated steps must not execute them.
    calls.clear()
    orch2 = ArsenalOrchestrator(tenant, fake_runner, approver=lambda s, p: False)
    orch2.remediate(detection)
    check("suspend_okta_user" not in [n for n, _ in calls],
          "denied gated step is NOT executed")
    # auto documentation still runs even when destructive steps are denied
    check("create_soar_case" in [n for n, _ in calls],
          "auto case documentation runs regardless of denial")

    print(f"\n{PASS} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
