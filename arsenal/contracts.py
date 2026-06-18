"""Shared data model for Arsenal remediation. ALL three phases import from here.

Do not fork these types. If a phase needs a new field, add it here so the other
phases see it. ActionKind values are EXACTLY the MCP tool names in main.py, so a
planner step, an executor call, and a rollback inverse all speak the same names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ActionKind(str, Enum):
    """Each value is an exact tool name registered in main.py."""
    # Destructive containment
    OKTA_SUSPEND = "suspend_okta_user"
    AZURE_REVOKE_SESSIONS = "revoke_azure_ad_sessions"
    AWS_REVOKE_KEYS = "revoke_aws_access_keys"
    GCP_REVOKE_SA_KEYS = "revoke_gcp_sa_keys"
    CROWDSTRIKE_ISOLATE = "isolate_crowdstrike_host"
    O365_PURGE = "purge_email_o365"
    # Low-blast-radius documentation
    CREATE_CASE = "create_soar_case"
    ADD_COMMENT = "add_case_comment"


class AutonomyClass(str, Enum):
    AUTO = "auto"        # safe to execute unattended (reversible + low blast radius + high confidence)
    GATED = "gated"      # requires human approval (default for anything destructive)
    BLOCKED = "blocked"  # never auto; high blast radius or irreversible


class StepState(str, Enum):
    PLANNED = "planned"
    GATED = "gated"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


@dataclass
class RemediationStep:
    kind: ActionKind
    args: Dict[str, Any]
    rationale: str = ""
    reversible: bool = False
    reversal_hint: str = ""
    autonomy: AutonomyClass = AutonomyClass.GATED
    blast_radius: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0          # 0..1, planner's confidence this step is correct
    state: StepState = StepState.PLANNED
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class RemediationPlan:
    detection_id: str
    summary: str
    steps: List[RemediationStep] = field(default_factory=list)
    source_tenant: str = ""          # which customer SecOps tenant this came from
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=now_iso)


@dataclass
class StateSnapshot:
    """Captured BEFORE a destructive step so rollback can restore prior state."""
    step_id: str
    kind: str
    target: Dict[str, Any]
    prior_state: Dict[str, Any] = field(default_factory=dict)
    captured_at: str = field(default_factory=now_iso)


@dataclass
class RollbackAction:
    """The inverse of a step. inverse_tool is an MCP tool name, or 'manual'."""
    step_id: str
    kind: str
    inverse_tool: str
    inverse_args: Dict[str, Any] = field(default_factory=dict)
    reversible: bool = True
    note: str = ""


@dataclass
class ExecutionResult:
    plan_id: str
    step_id: str
    state: StepState
    output: str = ""
    snapshot: Optional[StateSnapshot] = None
    rollback: Optional[RollbackAction] = None
    executed_at: str = field(default_factory=now_iso)


# Tenant config for Phase 1 bring-your-own-SecOps. A customer points Arsenal at
# THEIR Chronicle/SecOps instance; these fields scope every read/write.
@dataclass
class SecOpsTenant:
    name: str
    project_id: str
    customer_id: str
    region: str = "us"
