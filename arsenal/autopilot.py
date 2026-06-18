"""Arsenal Phase 3 — the AutonomyGate.

Phase 1 produces a RemediationPlan. Phase 3 decides, per step, whether it is safe
to run UNATTENDED (AUTO), must wait for a human (GATED), or must NEVER auto-run
(BLOCKED). The rule is deliberately conservative: a step is AUTO only when it is
reversible AND high-confidence AND low-blast AND its action kind is on an explicit
allow-list (and, for O365 purges, only when the purge is a recoverable softDelete).
Anything irreversible is BLOCKED. Everything else stays GATED.

A run-level cap (max_auto_actions_per_run) limits how many steps may auto-run; any
overflow is downgraded to GATED so a single noisy detection can't trigger a flood of
unattended actions.

Pure Python. No network, no main.py import.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from arsenal.contracts import (
    ActionKind,
    AutonomyClass,
    RemediationPlan,
    RemediationStep,
)


# Action kinds that can never be cleanly undone, regardless of confidence/blast.
# These are hard-BLOCKED so autopilot will never fire them unattended.
IRREVERSIBLE_KINDS: Set[ActionKind] = {
    ActionKind.AWS_REVOKE_KEYS,
    ActionKind.GCP_REVOKE_SA_KEYS,
}


def _default_auto_allowed() -> Set[ActionKind]:
    # Low-risk, reversible set. O365_PURGE is allowed here but gated again at
    # classify() time on purge_type == "softDelete".
    return {
        ActionKind.CREATE_CASE,
        ActionKind.ADD_COMMENT,
        ActionKind.O365_PURGE,
    }


@dataclass
class AutonomyPolicy:
    """Tunable thresholds for what may run unattended."""
    min_confidence: float = 0.85
    max_blast_entities: int = 5
    auto_allowed_kinds: Set[ActionKind] = field(default_factory=_default_auto_allowed)
    max_auto_actions_per_run: int = 10


def _total_blast_entities(step: RemediationStep) -> int:
    """Sum the integer entity counts in a step's blast_radius dict.

    blast_radius looks like {"users": 1, "hosts": 0}. Non-numeric values are
    ignored. An empty blast_radius counts as 0 entities.
    """
    total = 0
    for val in (step.blast_radius or {}).values():
        if isinstance(val, bool):
            continue
        if isinstance(val, int):
            total += val
        elif isinstance(val, float):
            total += int(val)
    return total


def _is_soft_delete(step: RemediationStep) -> bool:
    return str((step.args or {}).get("purge_type", "")).lower() == "softdelete"


class AutonomyGate:
    def __init__(self, policy: AutonomyPolicy = None):
        self.policy = policy or AutonomyPolicy()

    # -- per-step classification ------------------------------------------
    def classify(self, step: RemediationStep) -> AutonomyClass:
        p = self.policy

        # 1. Hard block: irreversible kinds and irreversible (hardDelete) purges.
        if step.kind in IRREVERSIBLE_KINDS:
            return AutonomyClass.BLOCKED
        if step.kind == ActionKind.O365_PURGE and not _is_soft_delete(step):
            # hardDelete (or unspecified) purge is unrecoverable.
            return AutonomyClass.BLOCKED
        if not step.reversible:
            # Anything the planner flagged as non-reversible can never auto-run.
            # If it is also an explicitly irreversible kind we already blocked it;
            # otherwise hold it for a human.
            return AutonomyClass.GATED

        # 2. AUTO requires ALL safety conditions.
        if (
            step.reversible
            and step.confidence >= p.min_confidence
            and _total_blast_entities(step) <= p.max_blast_entities
            and step.kind in p.auto_allowed_kinds
            and (step.kind != ActionKind.O365_PURGE or _is_soft_delete(step))
        ):
            return AutonomyClass.AUTO

        # 3. Everything reversible-but-not-auto is held for a human.
        return AutonomyClass.GATED

    # -- whole-plan split --------------------------------------------------
    def split_plan(self, plan: RemediationPlan) -> Dict[str, List[RemediationStep]]:
        buckets: Dict[str, List[RemediationStep]] = {
            "auto": [],
            "gated": [],
            "blocked": [],
        }
        auto_budget = self.policy.max_auto_actions_per_run

        for step in plan.steps:
            decided = self.classify(step)
            if decided == AutonomyClass.AUTO:
                if len(buckets["auto"]) < auto_budget:
                    step.autonomy = AutonomyClass.AUTO
                    buckets["auto"].append(step)
                else:
                    # Over the per-run cap: downgrade overflow to GATED.
                    step.autonomy = AutonomyClass.GATED
                    buckets["gated"].append(step)
            elif decided == AutonomyClass.BLOCKED:
                step.autonomy = AutonomyClass.BLOCKED
                buckets["blocked"].append(step)
            else:
                step.autonomy = AutonomyClass.GATED
                buckets["gated"].append(step)

        return buckets

    # -- human-readable rationale -----------------------------------------
    def explain(self, plan: RemediationPlan) -> str:
        buckets = self.split_plan(plan)
        p = self.policy
        lines: List[str] = []
        lines.append(f"Autonomy decision for plan {plan.plan_id} ({plan.summary!r})")
        lines.append(
            f"  policy: min_confidence={p.min_confidence}, "
            f"max_blast_entities={p.max_blast_entities}, "
            f"max_auto_actions_per_run={p.max_auto_actions_per_run}"
        )
        lines.append(
            f"  result: {len(buckets['auto'])} auto, "
            f"{len(buckets['gated'])} gated, {len(buckets['blocked'])} blocked"
        )

        if buckets["auto"]:
            lines.append("  WOULD AUTO-RUN (reversible + confident + low-blast + allow-listed):")
            for s in buckets["auto"]:
                lines.append(
                    f"    - {s.kind.value}: conf={s.confidence:.2f}, "
                    f"blast={_total_blast_entities(s)} entity(ies) — {s.rationale or 'no rationale'}"
                )
        else:
            lines.append("  WOULD AUTO-RUN: none")

        if buckets["gated"]:
            lines.append("  HELD FOR APPROVAL (needs a human):")
            for s in buckets["gated"]:
                lines.append(f"    - {s.kind.value}: {self._gated_reason(s)}")

        if buckets["blocked"]:
            lines.append("  BLOCKED (never auto — irreversible):")
            for s in buckets["blocked"]:
                lines.append(f"    - {s.kind.value}: {self._blocked_reason(s)}")

        return "\n".join(lines)

    # -- reason helpers ----------------------------------------------------
    def _blocked_reason(self, step: RemediationStep) -> str:
        if step.kind in IRREVERSIBLE_KINDS:
            return "key/credential revocation cannot be cleanly reversed"
        if step.kind == ActionKind.O365_PURGE and not _is_soft_delete(step):
            return "hardDelete purge is unrecoverable"
        return "irreversible action"

    def _gated_reason(self, step: RemediationStep) -> str:
        p = self.policy
        if not step.reversible:
            return "step is not reversible"
        if step.kind not in p.auto_allowed_kinds:
            return f"{step.kind.value} is not on the auto allow-list"
        if step.confidence < p.min_confidence:
            return f"confidence {step.confidence:.2f} < {p.min_confidence}"
        if _total_blast_entities(step) > p.max_blast_entities:
            return (
                f"blast {_total_blast_entities(step)} entities "
                f"> {p.max_blast_entities}"
            )
        return "downgraded to honor the per-run auto cap"
