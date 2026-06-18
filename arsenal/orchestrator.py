"""Arsenal orchestrator — ties the three phases into one flow.

  detection ──► connector.extract_entities
            ──► planner.plan                 (Phase 1, advisory)
            ──► AutonomyGate.split_plan       (Phase 3, decides auto/gated/blocked)
            ──► PlanExecutor.execute_plan      (Phase 2, runs auto + approved-gated)
            ──► PlanExecutor.rollback_plan     (Phase 2, one-click undo)

This is the single object main.py constructs per request. It takes an injected
`tool_runner(tool_name, **args) -> str` (dispatching to the real MCP tools) and an
optional `approver(step, preview) -> bool` bound to the human approval gate.

The `tool_runner` is wrapped so a CREATE_CASE result backfills the case_id of any
later ADD_COMMENT step (the planner ships those with case_id="" on purpose).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from arsenal.contracts import RemediationPlan, SecOpsTenant
from arsenal.connector import SecOpsConnector
from arsenal.planner import RemediationPlanner
from arsenal.autopilot import AutonomyGate, AutonomyPolicy
from arsenal.playbooks import match_playbook
from arsenal.rollback import RollbackRegistry
from arsenal.executor import PlanExecutor


def _case_backfill_runner(inner: Callable[..., str]) -> Callable[..., str]:
    """Wrap a tool_runner so a CREATE_CASE result fills later ADD_COMMENT case_id."""
    state: Dict[str, Optional[str]] = {"case_id": None}

    def runner(name: str, **args: Any) -> str:
        if name == "add_case_comment" and not args.get("case_id") and state["case_id"]:
            args["case_id"] = state["case_id"]
        out = inner(name, **args)
        if name == "create_soar_case":
            try:
                d = json.loads(out) if isinstance(out, str) else out
                if isinstance(d, dict):
                    state["case_id"] = d.get("case_id") or d.get("id") or d.get("caseId")
            except Exception:
                pass
        return out

    return runner


def _detection_summary(detection: dict) -> str:
    for k in ("summary", "description", "rule_name", "name", "title"):
        v = detection.get(k)
        if v:
            return str(v)
    return ""


class ArsenalOrchestrator:
    def __init__(
        self,
        tenant: SecOpsTenant,
        tool_runner: Callable[..., str],
        approver: Optional[Callable] = None,
        audit_sink: Optional[Callable] = None,
        policy: Optional[AutonomyPolicy] = None,
    ) -> None:
        self.tenant = tenant
        self.runner = _case_backfill_runner(tool_runner)
        self.connector = SecOpsConnector(tenant, self.runner)
        self.planner = RemediationPlanner()
        self.gate = AutonomyGate(policy or AutonomyPolicy())
        self.registry = RollbackRegistry()
        self.executor = PlanExecutor(
            self.runner, self.registry, approver=approver, audit_sink=audit_sink
        )

    # ── Phase 1: advisory recommendation ─────────────────────────────────────
    def recommend(self, detection: dict) -> RemediationPlan:
        """Build a plan and classify each step's autonomy. Executes nothing."""
        entities = self.connector.extract_entities(detection)
        plan = self.planner.plan(detection, entities, tenant_name=self.tenant.name)
        self.gate.split_plan(plan)  # mutates each step.autonomy in place
        return plan

    def explain(self, detection: dict) -> Dict[str, Any]:
        """Human-readable recommendation: the plan, the matched playbook, autonomy."""
        plan = self.recommend(detection)
        pb = match_playbook(detection, _detection_summary(detection))
        buckets = self.gate.split_plan(plan)
        return {
            "plan_id": plan.plan_id,
            "summary": plan.summary,
            "playbook": pb.name if pb else None,
            "auto": [s.kind.value for s in buckets["auto"]],
            "gated": [s.kind.value for s in buckets["gated"]],
            "blocked": [s.kind.value for s in buckets["blocked"]],
            "explanation": self.gate.explain(plan),
        }

    # ── Phase 2 + 3: govern + execute ────────────────────────────────────────
    def remediate(self, detection: dict) -> Dict[str, Any]:
        """Recommend, then execute: AUTO runs unattended, GATED waits on approver,
        BLOCKED is skipped. Returns the plan + per-step results."""
        plan = self.recommend(detection)
        pb = match_playbook(detection, _detection_summary(detection))
        results = self.executor.execute_plan(plan)
        return {
            "plan": plan,
            "playbook": pb.name if pb else None,
            "results": results,
        }

    def rollback(self, plan: RemediationPlan, results: List) -> List:
        """One-click undo: walk executed steps in reverse, run each inverse."""
        return self.executor.rollback_plan(plan, results)
