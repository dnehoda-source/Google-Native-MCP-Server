# Arsenal build spec (read before editing)

Arsenal = the unified SecOps action layer. Governed, reversible remediation driven
off a customer's own SecOps detections. Built as a new `arsenal/` package that REUSES
the existing `policy_and_approvals/` subsystem (approval gate, dry-run previews,
hash-chained audit) and calls the containment tools defined in `main.py`.

## Shared contracts
Everything imports `arsenal/contracts.py`. Do not fork those types.

## Existing tools to call (signatures in main.py)
- `suspend_okta_user(user_email, clear_sessions=True, confirm=False)` — reversible (unsuspend)
- `revoke_azure_ad_sessions(user_email, confirm=False)` — reversible-ish (sessions re-auth)
- `revoke_aws_access_keys(target_user, confirm=False)` — NOT cleanly reversible (re-issue)
- `revoke_gcp_sa_keys(project_id, service_account_email, confirm=False)` — NOT cleanly reversible
- `isolate_crowdstrike_host(hostname/device_id, confirm=False)` — reversible (lift containment)
- `purge_email_o365(target_mailbox, message_id, purge_type='hardDelete', confirm=False)` — reversible only if softDelete
- `create_soar_case(...)`, `add_case_comment(case_id, comment)` — low blast radius
- `list_secops_detections(hours_back, max_results, start_time, end_time)` — read detections
- `list_cases()`, `get_case_alerts(case_id)` — read cases

## Existing subsystem to reuse (do not duplicate)
- `policy_and_approvals/models.py` — DryRunPreview(reversible, reversal_hint), ApprovalRequest, ApprovalState
- `policy_and_approvals/tool_previews.py` — per-tool preview_* and entities_* builders with reversal hints
- `policy_and_approvals/audit.py` — hash-chained audit log

## File ownership (each agent edits ONLY its files; never main.py / policy_and_approvals/ / static/)
- Phase 1: `arsenal/connector.py`, `arsenal/planner.py`, `arsenal/tests/test_phase1.py`
- Phase 2: `arsenal/rollback.py`, `arsenal/executor.py`, `arsenal/tests/test_phase2.py`
- Phase 3: `arsenal/autopilot.py`, `arsenal/playbooks.py`, `arsenal/tests/test_phase3.py`

## Rules
- Pure-Python, no network calls at import time. Tool invocation goes through an injected
  callable `tool_runner(tool_name: str, **args) -> str` so modules are unit-testable with a
  fake. Do NOT import main.py (it has heavy side effects); depend only on contracts + the
  injected runner + policy_and_approvals models.
- Syntax-check your files (`python3 -m py_compile <file>`) and run your test file with a fake
  tool_runner before returning. Do not pip install. Do not start the server.
