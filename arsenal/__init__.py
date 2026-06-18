"""Arsenal — the unified SecOps action layer.

Governed, reversible remediation driven off a customer's own SecOps detections.
Three phases:
  1. Connect  (arsenal/connector.py, arsenal/planner.py)   — read detections, recommend a plan
  2. Approve  (arsenal/rollback.py, arsenal/executor.py)    — execute behind the gate, with rollback
  3. Autopilot(arsenal/autopilot.py, arsenal/playbooks.py)  — auto-run the safe slice

All phases share arsenal/contracts.py and reuse policy_and_approvals/ for the
approval gate, dry-run previews, and hash-chained audit log.
"""
