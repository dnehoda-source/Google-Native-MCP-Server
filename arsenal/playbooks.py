"""Arsenal Phase 3 — pre-approved playbook registry.

A Playbook is a named, pre-vetted template describing the ordered set of action
kinds Arsenal should propose for a recognized detection pattern, together with the
default autonomy each step should carry and any caps. Playbooks do NOT execute;
they shape the plan. The AutonomyGate in autopilot.py still has the final say on
what may run unattended, so a playbook marking a step "auto-eligible" is a
recommendation, not a bypass.

Pure Python. No network, no main.py import.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Union

from arsenal.contracts import ActionKind, AutonomyClass


@dataclass
class StepTemplate:
    """One step in a playbook, before the planner fills in concrete targets."""
    kind: ActionKind
    default_autonomy: AutonomyClass = AutonomyClass.GATED
    # Per-step cap on the entities this step is allowed to touch when auto-running.
    # None == no playbook-level cap (the AutonomyGate's global cap still applies).
    max_blast_entities: Optional[int] = None
    # Static arg defaults the planner can merge in (e.g. purge_type=softDelete).
    arg_defaults: Dict[str, Any] = field(default_factory=dict)
    note: str = ""


# A detection matcher is either a set of keywords (matched case-insensitively
# against the detection's type/name/summary) or a predicate callable.
DetectionMatch = Union[Set[str], Callable[[Dict[str, Any], str], bool]]


@dataclass
class Playbook:
    name: str
    detection_match: DetectionMatch
    steps: List[StepTemplate]
    description: str = ""

    def matches(self, detection: Dict[str, Any], summary: str) -> bool:
        if callable(self.detection_match):
            try:
                return bool(self.detection_match(detection, summary))
            except Exception:
                return False
        haystack = _detection_haystack(detection, summary)
        return any(kw.lower() in haystack for kw in self.detection_match)


def _detection_haystack(detection: Dict[str, Any], summary: str) -> str:
    """Flatten the detection's salient text fields into one lowercase string."""
    parts: List[str] = [summary or ""]
    for key in ("type", "name", "rule_name", "category", "tactic", "technique",
                "description", "title", "threat_category"):
        val = detection.get(key)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, (list, tuple)):
            parts.extend(str(v) for v in val)
    return " ".join(parts).lower()


# ---------------------------------------------------------------------------
# The pre-approved templates.
# ---------------------------------------------------------------------------

CREDENTIAL_THEFT = Playbook(
    name="credential_theft",
    detection_match={
        "credential", "credentials", "credential theft", "credential access",
        "password spray", "impossible travel", "stolen credential", "session hijack",
        "account takeover", "ato", "mfa fatigue",
    },
    description=(
        "Suspected account takeover / stolen credentials. Suspend the user and "
        "revoke active sessions (both GATED — they lock a human out), and "
        "auto-document the case for the analyst."
    ),
    steps=[
        StepTemplate(
            kind=ActionKind.OKTA_SUSPEND,
            default_autonomy=AutonomyClass.GATED,
            max_blast_entities=1,
            note="Reversible (unsuspend) but locks a real user out — keep gated.",
        ),
        StepTemplate(
            kind=ActionKind.AZURE_REVOKE_SESSIONS,
            default_autonomy=AutonomyClass.GATED,
            max_blast_entities=1,
            note="Forces re-auth across sessions — keep gated.",
        ),
        StepTemplate(
            kind=ActionKind.CREATE_CASE,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
        StepTemplate(
            kind=ActionKind.ADD_COMMENT,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
    ],
)

MALWARE_HOST = Playbook(
    name="malware_host",
    detection_match={
        "malware", "ransomware", "trojan", "beacon", "c2", "command and control",
        "endpoint compromise", "host compromise", "infected host", "edr",
        "crowdstrike", "lateral movement",
    },
    description=(
        "Malware / active threat on an endpoint. Network-isolate the host (GATED — "
        "it cuts the machine off the network) and auto-document the case."
    ),
    steps=[
        StepTemplate(
            kind=ActionKind.CROWDSTRIKE_ISOLATE,
            default_autonomy=AutonomyClass.GATED,
            max_blast_entities=1,
            note="Reversible (lift containment) but cuts the host off — keep gated.",
        ),
        StepTemplate(
            kind=ActionKind.CREATE_CASE,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
        StepTemplate(
            kind=ActionKind.ADD_COMMENT,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
    ],
)

PHISHING_BLAST = Playbook(
    name="phishing_blast",
    detection_match={
        "phishing", "phish", "malicious email", "malicious mail", "spear phishing",
        "spearphishing", "credential harvesting email", "mass mail", "email blast",
        "o365", "exchange online", "quarantine email",
    },
    description=(
        "A phishing email landed in many mailboxes. soft-Delete-purge the message "
        "(AUTO-eligible — recoverable from Deleted Items and low blast per mailbox) "
        "and auto-document the case."
    ),
    steps=[
        StepTemplate(
            kind=ActionKind.O365_PURGE,
            default_autonomy=AutonomyClass.AUTO,
            max_blast_entities=5,
            arg_defaults={"purge_type": "softDelete"},
            note="softDelete is reversible (recoverable items) — auto-eligible.",
        ),
        StepTemplate(
            kind=ActionKind.CREATE_CASE,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
        StepTemplate(
            kind=ActionKind.ADD_COMMENT,
            default_autonomy=AutonomyClass.AUTO,
            note="Documentation only — safe to auto-run.",
        ),
    ],
)


REGISTRY: List[Playbook] = [CREDENTIAL_THEFT, MALWARE_HOST, PHISHING_BLAST]


def match_playbook(detection: Dict[str, Any], summary: str) -> Optional[Playbook]:
    """Return the first registered playbook whose matcher fires, else None."""
    for pb in REGISTRY:
        if pb.matches(detection or {}, summary or ""):
            return pb
    return None


def get_playbook(name: str) -> Optional[Playbook]:
    for pb in REGISTRY:
        if pb.name == name:
            return pb
    return None
