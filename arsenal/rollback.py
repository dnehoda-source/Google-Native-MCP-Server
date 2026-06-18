"""Arsenal Phase 2 — rollback registry.

Maps each destructive RemediationStep to its inverse (RollbackAction) and captures
best-effort StateSnapshots BEFORE a step runs so the executor can walk EXECUTED
steps back in reverse order.

Embodies "reversible by default": `prefer_reversible` nudges a step toward a safer
reversible variant (e.g. forces an O365 purge to softDelete) where one exists.

Pure-Python. Tool invocation is via an injected `tool_runner(tool_name, **args) -> str`;
this module never imports main.py.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from arsenal.contracts import (
    ActionKind,
    RemediationStep,
    RollbackAction,
    StateSnapshot,
)

ToolRunner = Callable[..., str]


class RollbackRegistry:
    """Knows the inverse of every ActionKind and how to snapshot prior state."""

    # ── snapshotting ────────────────────────────────────────────────────────
    def snapshot(self, step: RemediationStep, tool_runner: Optional[ToolRunner] = None) -> StateSnapshot:
        """Capture the target identity (and any cheaply-readable prior state) before
        a destructive step. Best-effort and defensive: a snapshot must never raise
        or itself cause a side effect, so any read attempt is wrapped and failures
        are recorded rather than propagated.
        """
        target = self._target(step)
        prior: Dict[str, Any] = {}

        # Best-effort read of prior state. We do NOT invoke destructive tools here;
        # most containment tools have no cheap read inverse, so for the common case
        # we simply record the target identity. If a caller wires a read tool we try
        # it defensively.
        reader = self._read_tool(step)
        if reader and tool_runner is not None:
            try:
                raw = tool_runner(reader["tool"], **reader["args"])
                prior["read_tool"] = reader["tool"]
                try:
                    prior["state"] = json.loads(raw) if isinstance(raw, str) else raw
                except (ValueError, TypeError):
                    prior["state"] = raw
            except Exception as exc:  # defensive: never let snapshot abort a plan
                prior["read_error"] = str(exc)

        return StateSnapshot(
            step_id=step.step_id,
            kind=step.kind.value,
            target=target,
            prior_state=prior,
        )

    # ── inverse map ─────────────────────────────────────────────────────────
    def inverse(self, step: RemediationStep) -> RollbackAction:
        """Map an ActionKind to its inverse RollbackAction."""
        kind = step.kind
        args = dict(step.args or {})

        if kind is ActionKind.OKTA_SUSPEND:
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual",
                inverse_args={"user_email": args.get("user_email")},
                reversible=True,
                note="POST /api/v1/users/{id}/lifecycle/unsuspend to restore the user",
            )

        if kind is ActionKind.CROWDSTRIKE_ISOLATE:
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual",
                inverse_args={
                    "hostname": args.get("hostname"),
                    "device_id": args.get("device_id"),
                },
                reversible=True,
                note="POST /devices/entities/devices-actions/v2?action_name=lift_containment",
            )

        if kind is ActionKind.AZURE_REVOKE_SESSIONS:
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual",
                inverse_args={"user_email": args.get("user_email")},
                reversible=True,
                note="user re-authenticates; no explicit inverse",
            )

        if kind is ActionKind.O365_PURGE:
            soft = args.get("purge_type") == "softDelete"
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual" if soft else "none",
                inverse_args={
                    "target_mailbox": args.get("target_mailbox"),
                    "message_id": args.get("message_id"),
                },
                reversible=soft,
                note=(
                    "softDelete lands in Deleted Items; restore from Deleted Items / Graph"
                    if soft
                    else "hardDelete is permanent; not reversible"
                ),
            )

        if kind == ActionKind.AWS_REVOKE_KEYS:
            # The tool DEACTIVATES keys (update_access_key Status=Inactive), which
            # is reversible: reactivate to restore. No MCP tool for it yet, so manual.
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual",
                inverse_args=args,
                reversible=True,
                note="reactivate: aws iam update-access-key --status Active",
            )

        if kind == ActionKind.GCP_REVOKE_SA_KEYS:
            # The tool DELETES keys permanently. Not reversible; keys must be re-issued.
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="manual",
                inverse_args=args,
                reversible=False,
                note="key delete is permanent; re-issue required",
            )

        if kind in (ActionKind.CREATE_CASE, ActionKind.ADD_COMMENT):
            return RollbackAction(
                step_id=step.step_id,
                kind=kind.value,
                inverse_tool="none",
                inverse_args={},
                reversible=True,
                note="documentation action; trivial no-op inverse",
            )

        # Unknown kind: conservative, treat as non-reversible manual.
        return RollbackAction(
            step_id=step.step_id,
            kind=getattr(kind, "value", str(kind)),
            inverse_tool="manual",
            inverse_args=args,
            reversible=False,
            note="no known inverse for this action kind",
        )

    # ── reversible-by-default nudge ─────────────────────────────────────────
    def prefer_reversible(self, step: RemediationStep) -> Dict[str, Any]:
        """Return an args dict adjusted toward the safest reversible variant.

        Does not mutate the input step. Currently the only kind with a safer
        reversible variant is O365_PURGE (force softDelete over hardDelete).
        """
        args = dict(step.args or {})
        if step.kind is ActionKind.O365_PURGE:
            if args.get("purge_type") != "softDelete":
                args["purge_type"] = "softDelete"
        return args

    # ── helpers ─────────────────────────────────────────────────────────────
    def _target(self, step: RemediationStep) -> Dict[str, Any]:
        """Extract the target identity from a step's args, keyed by kind."""
        a = step.args or {}
        kind = step.kind
        if kind is ActionKind.OKTA_SUSPEND:
            return {"user_email": a.get("user_email")}
        if kind is ActionKind.AZURE_REVOKE_SESSIONS:
            return {"user_email": a.get("user_email")}
        if kind is ActionKind.AWS_REVOKE_KEYS:
            return {"target_user": a.get("target_user")}
        if kind is ActionKind.GCP_REVOKE_SA_KEYS:
            return {
                "project_id": a.get("project_id"),
                "service_account_email": a.get("service_account_email"),
            }
        if kind is ActionKind.CROWDSTRIKE_ISOLATE:
            return {"hostname": a.get("hostname"), "device_id": a.get("device_id")}
        if kind is ActionKind.O365_PURGE:
            return {
                "target_mailbox": a.get("target_mailbox"),
                "message_id": a.get("message_id"),
                "purge_type": a.get("purge_type", "hardDelete"),
            }
        if kind is ActionKind.ADD_COMMENT:
            return {"case_id": a.get("case_id")}
        if kind is ActionKind.CREATE_CASE:
            return {"summary": a.get("summary") or a.get("title")}
        return dict(a)

    def _read_tool(self, step: RemediationStep) -> Optional[Dict[str, Any]]:
        """Most containment tools have no cheap, side-effect-free read available
        through the injected runner, so we return None and snapshot identity only.
        Hook returns are kept for future wiring of read tools.
        """
        return None
