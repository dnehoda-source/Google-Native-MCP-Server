"""Standalone Phase 2 tests: `python3 arsenal/tests/test_phase2.py` (exit 0 on pass).

Uses fakes for the tool runner, approver, and audit sink. No network, no main.py.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable so `arsenal` and `policy_and_approvals` resolve
# whether run from the repo root or from inside arsenal/tests/.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from arsenal.contracts import (
    ActionKind,
    AutonomyClass,
    RemediationPlan,
    RemediationStep,
    StepState,
)
from arsenal.executor import PlanExecutor
from arsenal.rollback import RollbackRegistry


# ── fakes ────────────────────────────────────────────────────────────────────

class FakeRunner:
    """Records every (tool_name, kwargs) call; returns a canned ok payload."""

    def __init__(self):
        self.calls = []

    def __call__(self, tool_name, **kwargs):
        self.calls.append((tool_name, kwargs))
        return '{"status":"ok"}'

    def names(self):
        return [c[0] for c in self.calls]


def make_approver(approve_emails):
    """Approve only gated steps whose user_email is in approve_emails."""
    def approver(step, preview):
        return step.args.get("user_email") in approve_emails
    return approver


# ── assertion helper ─────────────────────────────────────────────────────────

_passed = 0

def check(cond, label):
    global _passed
    if not cond:
        print(f"FAIL: {label}")
        raise SystemExit(1)
    _passed += 1
    print(f"PASS: {label}")


# ── tests ────────────────────────────────────────────────────────────────────

def main():
    registry = RollbackRegistry()

    # --- inverse map sanity ---------------------------------------------------
    okta_step = RemediationStep(
        kind=ActionKind.OKTA_SUSPEND,
        args={"user_email": "alice@corp.com"},
        autonomy=AutonomyClass.GATED,
    )
    okta_inv = registry.inverse(okta_step)
    check(okta_inv.reversible and "unsuspend" in okta_inv.note.lower(),
          "OKTA_SUSPEND inverse is reversible w/ unsuspend note")

    aws_step = RemediationStep(kind=ActionKind.AWS_REVOKE_KEYS, args={"target_user": "svc"})
    check(registry.inverse(aws_step).reversible is True,
          "AWS_REVOKE_KEYS reversible (deactivate -> reactivate)")

    gcp_step = RemediationStep(kind=ActionKind.GCP_REVOKE_SA_KEYS,
                               args={"project_id": "p", "service_account_email": "sa@p"})
    check(registry.inverse(gcp_step).reversible is False,
          "GCP_REVOKE_SA_KEYS marked irreversible")

    hard = RemediationStep(kind=ActionKind.O365_PURGE,
                           args={"target_mailbox": "m", "message_id": "x", "purge_type": "hardDelete"})
    check(registry.inverse(hard).reversible is False,
          "O365_PURGE hardDelete marked irreversible")

    soft = RemediationStep(kind=ActionKind.O365_PURGE,
                           args={"target_mailbox": "m", "message_id": "x", "purge_type": "softDelete"})
    check(registry.inverse(soft).reversible is True,
          "O365_PURGE softDelete marked reversible")

    # prefer_reversible forces softDelete
    nudged = registry.prefer_reversible(hard)
    check(nudged["purge_type"] == "softDelete" and hard.args["purge_type"] == "hardDelete",
          "prefer_reversible forces O365 softDelete without mutating step")

    azure = RemediationStep(kind=ActionKind.AZURE_REVOKE_SESSIONS, args={"user_email": "bob@corp.com"})
    check(registry.inverse(azure).reversible is True,
          "AZURE_REVOKE_SESSIONS reversible (re-auth)")

    comment = RemediationStep(kind=ActionKind.ADD_COMMENT, args={"case_id": "C-1", "comment": "hi"})
    check(registry.inverse(comment).reversible is True,
          "ADD_COMMENT reversible trivial inverse")

    # --- plan execution -------------------------------------------------------
    runner = FakeRunner()
    audit_records = []

    plan = RemediationPlan(
        detection_id="DET-42",
        summary="Contain compromised identity",
        steps=[
            RemediationStep(
                kind=ActionKind.ADD_COMMENT,
                args={"case_id": "C-1", "comment": "auto-triage"},
                autonomy=AutonomyClass.AUTO,
            ),
            RemediationStep(
                kind=ActionKind.OKTA_SUSPEND,
                args={"user_email": "alice@corp.com", "clear_sessions": True},
                autonomy=AutonomyClass.GATED,
            ),
            RemediationStep(
                kind=ActionKind.OKTA_SUSPEND,
                args={"user_email": "denied@corp.com", "clear_sessions": True},
                autonomy=AutonomyClass.GATED,
            ),
        ],
    )

    approver = make_approver(approve_emails={"alice@corp.com"})
    execu = PlanExecutor(runner, registry, approver=approver, audit_sink=audit_records.append)
    results = execu.execute_plan(plan)

    auto_res, approved_res, denied_res = results

    check(auto_res.state is StepState.EXECUTED, "AUTO add_comment executed")
    check(approved_res.state is StepState.EXECUTED, "approved gated okta executed")
    check(denied_res.state is StepState.GATED, "denied gated okta NOT executed (GATED)")

    # denied step must not appear as a tool call
    runner_names = runner.names()
    check(runner_names == ["add_case_comment", "suspend_okta_user"],
          "only the auto + approved-gated steps reached the runner")

    # every executed call used confirm=True
    for name, kwargs in runner.calls:
        check(kwargs.get("confirm") is True, f"{name} invoked with confirm=True")

    # the denied user_email was never passed to any tool call
    check(all(kw.get("user_email") != "denied@corp.com" for _, kw in runner.calls),
          "denied user never passed to a tool")

    # snapshots captured for executed steps
    check(auto_res.snapshot is not None and approved_res.snapshot is not None,
          "snapshots captured for executed steps")
    check(approved_res.snapshot.target.get("user_email") == "alice@corp.com",
          "okta snapshot records target identity")
    check(denied_res.snapshot is None, "denied step has no snapshot")

    # inverse attached to executed steps
    check(approved_res.rollback is not None and approved_res.rollback.reversible,
          "executed okta step has reversible inverse attached")

    # audit sink received executed + denied events
    events = [r["event_type"] for r in audit_records]
    check("step_executed" in events and "step_denied" in events,
          "audit sink captured executed + denied events")

    # --- rollback (reverse order) ---------------------------------------------
    calls_before = len(runner.calls)
    execu.rollback_plan(plan, results)

    # okta inverse is "manual" → marked ROLLED_BACK, no extra tool call
    check(approved_res.state is StepState.ROLLED_BACK,
          "okta executed step marked ROLLED_BACK (manual inverse)")
    check(auto_res.state is StepState.ROLLED_BACK,
          "add_comment executed step marked ROLLED_BACK (noop inverse)")
    check(len(runner.calls) == calls_before,
          "manual/noop inverses made no extra tool calls")
    check(denied_res.state is StepState.GATED,
          "denied step untouched by rollback")

    # --- rollback ordering with an automatable inverse ------------------------
    # Build a plan with a fake automatable inverse to assert REVERSE walk order.
    reg2 = RollbackRegistry()
    runner2 = FakeRunner()

    from arsenal.contracts import RollbackAction

    class OrderedRegistry(RollbackRegistry):
        def inverse(self, step):
            # give each step an automatable inverse named after its comment tag
            return RollbackAction(
                step_id=step.step_id,
                kind=step.kind.value,
                inverse_tool=f"undo_{step.args.get('tag')}",
                inverse_args={"tag": step.args.get("tag")},
                reversible=True,
                note="auto inverse",
            )

    ordered_plan = RemediationPlan(
        detection_id="DET-ORDER",
        summary="ordering",
        steps=[
            RemediationStep(kind=ActionKind.ADD_COMMENT, args={"case_id": "C", "tag": "first"}, autonomy=AutonomyClass.AUTO),
            RemediationStep(kind=ActionKind.ADD_COMMENT, args={"case_id": "C", "tag": "second"}, autonomy=AutonomyClass.AUTO),
        ],
    )
    execu2 = PlanExecutor(runner2, OrderedRegistry(), approver=None)
    res2 = execu2.execute_plan(ordered_plan)
    execu2.rollback_plan(ordered_plan, res2)

    rollback_calls = [c[0] for c in runner2.calls if c[0].startswith("undo_")]
    check(rollback_calls == ["undo_second", "undo_first"],
          "rollback runs inverses in REVERSE execution order")

    print(f"\nALL {_passed} CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
