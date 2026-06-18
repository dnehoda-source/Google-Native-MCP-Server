"""Arsenal Phase 2 — governed plan executor.

Drives a RemediationPlan through the approval gate and on to execution, then can
walk EXECUTED steps back via the RollbackRegistry. Reuses policy_and_approvals'
DryRunPreview for the approver-facing preview.

All side effects flow through an injected `tool_runner(tool_name, **args) -> str`
and an injected `approver(step, preview) -> bool`, so the whole thing is unit
testable with fakes. This module never imports main.py.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from arsenal.contracts import (
    ActionKind,
    AutonomyClass,
    ExecutionResult,
    RemediationPlan,
    RemediationStep,
    RollbackAction,
    StepState,
)
from arsenal.rollback import RollbackRegistry

from policy_and_approvals.models import DryRunPreview

ToolRunner = Callable[..., str]
Approver = Callable[[RemediationStep, DryRunPreview], bool]
AuditSink = Callable[[Dict[str, Any]], None]


class PlanExecutor:
    def __init__(
        self,
        tool_runner: ToolRunner,
        registry: RollbackRegistry,
        approver: Optional[Approver] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self.tool_runner = tool_runner
        self.registry = registry
        self.approver = approver
        self.audit_sink = audit_sink

    # ── previews ────────────────────────────────────────────────────────────
    def build_preview(self, step: RemediationStep) -> DryRunPreview:
        """Build the approver-facing DryRunPreview from the step itself.

        Side effects, reversibility, reversal hint and entities are derived from
        the step + its inverse so the approver sees exactly what will happen and
        whether it can be undone.
        """
        action = self.registry.inverse(step)
        entities = self.registry._target(step)
        side_effects = [self._describe(step)]
        # The inverse is the authoritative source for reversibility.
        reversible = action.reversible
        reversal_hint = action.note if reversible else ""
        # Honor an explicit per-step reversal hint if the planner set one.
        if step.reversal_hint:
            reversal_hint = step.reversal_hint
        return DryRunPreview(
            tool_name=step.kind.value,
            args=dict(step.args or {}),
            entities=entities,
            side_effects=side_effects,
            reversible=reversible,
            reversal_hint=reversal_hint,
        )

    # ── execution ───────────────────────────────────────────────────────────
    def execute_plan(self, plan: RemediationPlan) -> List[ExecutionResult]:
        results: List[ExecutionResult] = []
        for step in plan.steps:
            try:
                results.append(self._execute_step(plan, step))
            except Exception as exc:  # a bad step must never abort the loop
                step.state = StepState.FAILED
                result = ExecutionResult(
                    plan_id=plan.plan_id,
                    step_id=step.step_id,
                    state=StepState.FAILED,
                    output=f"executor error: {exc}",
                    rollback=self._safe_inverse(step),
                )
                self._audit("step_failed", plan, step, result)
                results.append(result)
        return results

    def _execute_step(self, plan: RemediationPlan, step: RemediationStep) -> ExecutionResult:
        gated = step.autonomy is AutonomyClass.GATED
        blocked = step.autonomy is AutonomyClass.BLOCKED

        if blocked:
            step.state = StepState.SKIPPED
            result = ExecutionResult(
                plan_id=plan.plan_id,
                step_id=step.step_id,
                state=StepState.SKIPPED,
                output="autonomy=BLOCKED; not executed",
                rollback=self._safe_inverse(step),
            )
            self._audit("step_blocked", plan, step, result)
            return result

        if gated:
            preview = self.build_preview(step)
            approved = False
            if self.approver is not None:
                try:
                    approved = bool(self.approver(step, preview))
                except Exception:
                    approved = False
            if not approved:
                step.state = StepState.GATED
                result = ExecutionResult(
                    plan_id=plan.plan_id,
                    step_id=step.step_id,
                    state=StepState.GATED,
                    output="approval denied or absent; not executed",
                    rollback=self._safe_inverse(step),
                )
                self._audit("step_denied", plan, step, result, preview=preview)
                return result
            # approved → fall through to execute

        # AUTO, or GATED+approved → snapshot then execute.
        snapshot = None
        try:
            snapshot = self.registry.snapshot(step, self.tool_runner)
        except Exception:
            snapshot = None  # snapshot is best-effort; never block execution

        inverse = self._safe_inverse(step)

        try:
            # Override confirm rather than pass it twice (planner ships confirm=False
            # in args so a raw call would naturally hit the tool's own gate).
            call_args = {**(step.args or {}), "confirm": True}
            output = self.tool_runner(step.kind.value, **call_args)
            step.state = StepState.EXECUTED
            result = ExecutionResult(
                plan_id=plan.plan_id,
                step_id=step.step_id,
                state=StepState.EXECUTED,
                output=output if isinstance(output, str) else json.dumps(output, default=str),
                snapshot=snapshot,
                rollback=inverse,
            )
            self._audit("step_executed", plan, step, result)
            return result
        except Exception as exc:
            step.state = StepState.FAILED
            result = ExecutionResult(
                plan_id=plan.plan_id,
                step_id=step.step_id,
                state=StepState.FAILED,
                output=f"tool error: {exc}",
                snapshot=snapshot,
                rollback=inverse,
            )
            self._audit("step_failed", plan, step, result)
            return result

    # ── rollback ────────────────────────────────────────────────────────────
    def rollback_plan(
        self, plan: RemediationPlan, results: List[ExecutionResult]
    ) -> List[ExecutionResult]:
        """Walk EXECUTED results in REVERSE order and run each inverse.

        Manual / no-op inverses are marked ROLLED_BACK with a note (no tool call).
        Irreversible inverses are left as-is with a note. A failing rollback does
        not abort the walk.
        """
        for result in reversed(results):
            if result.state is not StepState.EXECUTED:
                continue
            action = result.rollback
            if action is None:
                result.output = (result.output or "") + " | rollback: no inverse available"
                continue

            if not action.reversible:
                result.output = (result.output or "") + f" | rollback skipped (irreversible): {action.note}"
                self._audit_rollback(plan, result, action, "rollback_irreversible")
                continue

            if action.inverse_tool in ("manual", "none", "", None):
                result.state = StepState.ROLLED_BACK
                result.output = (result.output or "") + f" | rolled back (manual): {action.note}"
                self._audit_rollback(plan, result, action, "rollback_manual")
                continue

            # An automatable inverse tool exists → invoke it.
            try:
                inv_args = {k: v for k, v in (action.inverse_args or {}).items() if v is not None}
                inv_args["confirm"] = True
                out = self.tool_runner(action.inverse_tool, **inv_args)
                result.state = StepState.ROLLED_BACK
                result.output = (result.output or "") + f" | rolled back via {action.inverse_tool}: {out}"
                self._audit_rollback(plan, result, action, "rollback_executed")
            except Exception as exc:
                result.output = (result.output or "") + f" | rollback FAILED: {exc}"
                self._audit_rollback(plan, result, action, "rollback_failed")
        return results

    # ── helpers ─────────────────────────────────────────────────────────────
    def _safe_inverse(self, step: RemediationStep) -> Optional[RollbackAction]:
        try:
            return self.registry.inverse(step)
        except Exception:
            return None

    def _describe(self, step: RemediationStep) -> str:
        a = step.args or {}
        kind = step.kind
        if kind is ActionKind.OKTA_SUSPEND:
            return f"Suspend Okta user {a.get('user_email')}"
        if kind is ActionKind.AZURE_REVOKE_SESSIONS:
            return f"Revoke Azure AD sessions for {a.get('user_email')}"
        if kind is ActionKind.AWS_REVOKE_KEYS:
            return f"Deactivate AWS access keys for {a.get('target_user')}"
        if kind is ActionKind.GCP_REVOKE_SA_KEYS:
            return f"Delete GCP SA keys for {a.get('service_account_email')} in {a.get('project_id')}"
        if kind is ActionKind.CROWDSTRIKE_ISOLATE:
            return f"Network-isolate host {a.get('hostname') or a.get('device_id')}"
        if kind is ActionKind.O365_PURGE:
            return f"{a.get('purge_type', 'hardDelete')} email {a.get('message_id')} from {a.get('target_mailbox')}"
        if kind is ActionKind.CREATE_CASE:
            return "Create SOAR case"
        if kind is ActionKind.ADD_COMMENT:
            return f"Add comment to case {a.get('case_id')}"
        return f"{kind.value} {a}"

    def _audit(
        self,
        event: str,
        plan: RemediationPlan,
        step: RemediationStep,
        result: ExecutionResult,
        preview: Optional[DryRunPreview] = None,
    ) -> None:
        if self.audit_sink is None:
            return
        record: Dict[str, Any] = {
            "event_type": event,
            "plan_id": plan.plan_id,
            "detection_id": plan.detection_id,
            "step_id": step.step_id,
            "tool_name": step.kind.value,
            "args": dict(step.args or {}),
            "autonomy": step.autonomy.value,
            "state": result.state.value,
            "outcome": result.output,
            "reversible": result.rollback.reversible if result.rollback else None,
            "timestamp": result.executed_at,
        }
        if preview is not None:
            record["side_effects"] = preview.side_effects
            record["reversal_hint"] = preview.reversal_hint
        try:
            self.audit_sink(record)
        except Exception:
            pass  # auditing must never break execution

    def _audit_rollback(
        self,
        plan: RemediationPlan,
        result: ExecutionResult,
        action: RollbackAction,
        event: str,
    ) -> None:
        if self.audit_sink is None:
            return
        try:
            self.audit_sink(
                {
                    "event_type": event,
                    "plan_id": plan.plan_id,
                    "step_id": result.step_id,
                    "tool_name": action.kind,
                    "inverse_tool": action.inverse_tool,
                    "inverse_args": action.inverse_args,
                    "reversible": action.reversible,
                    "note": action.note,
                    "state": result.state.value,
                }
            )
        except Exception:
            pass
