"""Arsenal Phase 1 — remediation planner (ADVISORY).

Maps the signals extracted from a SecOps detection to a `RemediationPlan` of
`RemediationStep`s. This phase RECOMMENDS only: `plan()` builds the plan and
returns it. Nothing is executed here (that is Phase 2's executor, behind the
approval gate).

Reversibility / reversal hints are aligned with
`policy_and_approvals/tool_previews.py`:
  - okta suspend, azure revoke, crowdstrike isolate -> reversible
  - aws key revoke, gcp SA key revoke              -> NOT cleanly reversible
  - o365 purge                                     -> reversible only if softDelete
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .contracts import (
    ActionKind,
    AutonomyClass,
    RemediationPlan,
    RemediationStep,
)


def _phishing_message_id(detection: dict) -> str:
    """Best-effort scrape of a mail/message id from a detection."""
    candidates = ("message_id", "mail_id", "internet_message_id", "messageId", "mailId")

    def walk(node: Any) -> str:
        if isinstance(node, dict):
            for k, v in node.items():
                if str(k) in candidates and isinstance(v, (str, int)) and str(v):
                    return str(v)
            for v in node.values():
                found = walk(v)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = walk(item)
                if found:
                    return found
        return ""

    return walk(detection)


def _is_phishing(detection: dict) -> bool:
    blob = json.dumps(detection, default=str).lower()
    return any(t in blob for t in ("phish", "phishing", "credential harvest"))


class RemediationPlanner:
    """Turns (detection, entities) into a recommended, governed RemediationPlan."""

    def plan(
        self,
        detection: dict,
        entities: Dict[str, List[str]],
        tenant_name: str = "",
    ) -> RemediationPlan:
        det_id = (
            str(detection.get("id"))
            or str(detection.get("detection_id"))
            or str(detection.get("name"))
            or "unknown-detection"
        )
        rule_name = (
            detection.get("ruleName")
            or detection.get("rule_name")
            or detection.get("rule")
            or det_id
        )

        users = entities.get("users", [])
        hosts = entities.get("hosts", [])
        mailboxes = entities.get("mailboxes", [])
        aws_users = entities.get("aws_users", [])
        aws_keys = entities.get("aws_keys", [])
        gcp_sas = entities.get("gcp_sas", [])

        steps: List[RemediationStep] = []

        # ── compromised user -> Okta suspend + Azure session revoke ──────────
        for user in users:
            steps.append(
                RemediationStep(
                    kind=ActionKind.OKTA_SUSPEND,
                    args={"user_email": user, "clear_sessions": True, "confirm": False},
                    rationale=f"User {user} appears in detection {rule_name!r}; suspend to contain account takeover.",
                    reversible=True,
                    reversal_hint="POST /api/v1/users/{id}/lifecycle/unsuspend to restore",
                    autonomy=AutonomyClass.GATED,
                    blast_radius={"users": 1},
                    confidence=0.8,
                )
            )
            steps.append(
                RemediationStep(
                    kind=ActionKind.AZURE_REVOKE_SESSIONS,
                    args={"user_email": user, "confirm": False},
                    rationale=f"Revoke Azure AD sign-in sessions for {user} to invalidate stolen tokens.",
                    reversible=True,
                    reversal_hint="User can re-authenticate; revocation does not disable the account",
                    autonomy=AutonomyClass.GATED,
                    blast_radius={"users": 1},
                    confidence=0.75,
                )
            )

        # ── exposed AWS access key / aws users -> revoke keys ────────────────
        targets_aws = aws_users or (["(detected-key-owner)"] if aws_keys else [])
        for target in targets_aws:
            steps.append(
                RemediationStep(
                    kind=ActionKind.AWS_REVOKE_KEYS,
                    args={"target_user": target, "confirm": False},
                    rationale=(
                        f"AWS credential exposure for {target}"
                        + (f" (key {aws_keys[0]})" if aws_keys else "")
                        + "; deactivate IAM access keys."
                    ),
                    reversible=True,
                    reversal_hint="Keys are deactivated (Inactive), not deleted; reactivate to restore.",
                    autonomy=AutonomyClass.GATED,
                    blast_radius={"aws_users": 1, "aws_keys": len(aws_keys) or 1},
                    confidence=0.7,
                )
            )

        # ── GCP service account keys -> revoke ───────────────────────────────
        project_id = detection.get("project_id") or detection.get("gcp_project") or ""
        for sa in gcp_sas:
            steps.append(
                RemediationStep(
                    kind=ActionKind.GCP_REVOKE_SA_KEYS,
                    args={"project_id": project_id, "service_account_email": sa, "confirm": False},
                    rationale=f"Service account {sa} implicated; delete USER_MANAGED keys to cut off access.",
                    reversible=False,
                    reversal_hint="Keys are permanently deleted. New keys must be generated.",
                    autonomy=AutonomyClass.GATED,
                    blast_radius={"gcp_sas": 1},
                    confidence=0.7,
                )
            )

        # ── malicious / affected host -> CrowdStrike isolate ─────────────────
        for host in hosts:
            steps.append(
                RemediationStep(
                    kind=ActionKind.CROWDSTRIKE_ISOLATE,
                    args={"hostname": host, "device_id": "", "confirm": False},
                    rationale=f"Host {host} affected by detection {rule_name!r}; network-isolate to stop lateral movement.",
                    reversible=True,
                    reversal_hint="POST /devices/entities/devices-actions/v2?action_name=lift_containment",
                    autonomy=AutonomyClass.GATED,
                    blast_radius={"hosts": 1},
                    confidence=0.75,
                )
            )

        # ── phishing mailbox + message -> O365 purge (reversible softDelete) ─
        if _is_phishing(detection) and mailboxes:
            message_id = _phishing_message_id(detection)
            if message_id:
                for mailbox in mailboxes:
                    steps.append(
                        RemediationStep(
                            kind=ActionKind.O365_PURGE,
                            args={
                                "target_mailbox": mailbox,
                                "message_id": message_id,
                                "purge_type": "softDelete",
                                "confirm": False,
                            },
                            rationale=f"Phishing message {message_id} in {mailbox}; soft-delete (reversible) to remove the lure.",
                            reversible=True,
                            reversal_hint="softDelete lands in Deleted Items and is restorable via Graph",
                            autonomy=AutonomyClass.GATED,
                            blast_radius={"mailboxes": 1, "messages": 1},
                            confidence=0.7,
                        )
                    )

        # ── ALWAYS: document the plan via case + comment (AUTO) ──────────────
        action_summary = self._summarize_actions(steps)
        case_title = f"[Arsenal] Remediation for {rule_name}"
        case_desc = (
            f"Auto-generated remediation plan for detection {det_id} "
            f"on tenant {tenant_name or '(unspecified)'}.\nProposed actions: {action_summary}"
        )
        steps.append(
            RemediationStep(
                kind=ActionKind.CREATE_CASE,
                args={
                    "title": case_title,
                    "description": case_desc,
                    "priority": "HIGH",
                    "alert_source": "ARSENAL",
                },
                rationale="Open a SOAR case to track and govern this remediation.",
                reversible=True,
                reversal_hint="Close/delete the case via SOAR if opened in error.",
                autonomy=AutonomyClass.AUTO,
                blast_radius={"cases": 1},
                confidence=0.95,
            )
        )
        steps.append(
            RemediationStep(
                kind=ActionKind.ADD_COMMENT,
                args={
                    "case_id": "",  # filled in by executor with the created case id
                    "comment": f"Arsenal proposed plan for {det_id}: {action_summary}",
                },
                rationale="Document the proposed plan on the case for the approver/audit trail.",
                reversible=True,
                reversal_hint="Comments are append-only; no rollback needed.",
                autonomy=AutonomyClass.AUTO,
                blast_radius={"comments": 1},
                confidence=0.95,
            )
        )

        summary = (
            f"Detection {rule_name}: {len(users)} user(s), {len(hosts)} host(s), "
            f"{len(mailboxes)} mailbox(es), {len(aws_users) or (1 if aws_keys else 0)} aws, "
            f"{len(gcp_sas)} gcp SA(s) -> {len(steps)} step(s)."
        )

        return RemediationPlan(
            detection_id=det_id,
            summary=summary,
            steps=steps,
            source_tenant=tenant_name,
        )

    @staticmethod
    def _summarize_actions(steps: List[RemediationStep]) -> str:
        if not steps:
            return "(no containment actions)"
        return ", ".join(s.kind.name for s in steps) or "(none)"
