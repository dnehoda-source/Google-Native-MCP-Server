# MCP Boss Benchmark Scorecard

- last_run: 2026-04-23T19:39:16.675759+00:00
- model: gemini-2.5-flash
- scenarios_run: 6

## Headline numbers

- correct_verdict_pct: 83.3
- correct_containment_pct: 30.5
- destructive_fp_rate_pct: 0.0
- median_alert_to_containment_s: 47.14

## Per-scenario detail

| scenario | verdict | containment | destructive FP | a2c (s) |
|----------|---------|-------------|----------------|---------|
| s001-aws-key-exposure | MISS | 0.00 | no | - |
| s002-phish-okta-compromise | OK | 0.33 | no | 49.611406326293945 |
| s003-bigquery-exfil | OK | 0.50 | no | 44.67233061790466 |
| s004-ransomware-mass-encrypt | OK | 0.00 | no | 59.97063970565796 |
| s005-apt-lateral-sa-impersonation | OK | 1.00 | no | 32.393266439437866 |
| s006-bec-inbox-rule | OK | 0.00 | no | - |
