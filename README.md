# 🔒 Google-Native Autonomous MCP Server — Full Security Operations Suite

A production-ready Model Context Protocol (MCP) server with **22 tools** spanning the complete security operations lifecycle — from discovery and hunting through intelligence enrichment, automated containment, and case management.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   MCP Client (LLM)                      │
│          Vertex AI / Claude / GPT / Custom              │
└──────────────────────┬──────────────────────────────────┘
                       │ SSE (Server-Sent Events)
                       ▼
┌─────────────────────────────────────────────────────────┐
│           Google-Native MCP Server v2.0                 │
│           (Cloud Run — 22 Tools — Serverless)           │
│                                                         │
│  🔍 DISCOVERY        🧠 INTELLIGENCE    📋 MANAGEMENT  │
│  ├─ SCC Findings     ├─ GTI/VT Enrich   ├─ Data Tables │
│  ├─ Cloud Logging    ├─ IOC Extraction   ├─ YARA-L Rules│
│  ├─ UDM Search       └─ Vertex AI        └─ SOAR Cases │
│  ├─ Detections                                          │
│  └─ Ingestion Health                                    │
│                                                         │
│  📧 EMAIL            🔑 IDENTITY        ☁️ CLOUD       │
│  └─ O365 Purge       ├─ Okta Suspend    ├─ AWS Key Kill│
│                      └─ Azure AD Revoke ├─ AWS STS Kill│
│  🖥️ ENDPOINT                            └─ GCP SA Kill │
│  └─ CrowdStrike                                        │
│     Isolate                                             │
│                                                         │
│  Auth: Workload Identity + ADC (zero embedded secrets)  │
└─────────────────────────────────────────────────────────┘
```

## 22 Tools — Complete Reference

### 🔍 Discovery & Hunting
| Tool | API | Description |
|---|---|---|
| `get_scc_findings` | Security Command Center | Active vulnerabilities & misconfigurations |
| `query_cloud_logging` | Cloud Logging | IAM changes, compute events, audit trail |
| `search_secops_udm` | Google SecOps | UDM search & YARA-L query execution |
| `list_secops_detections` | Google SecOps | Recent detection alerts with outcomes |
| `check_ingestion_health` | Google SecOps | Unparsed log volume monitoring |

### 🧠 Intelligence & Enrichment
| Tool | API | Description |
|---|---|---|
| `enrich_indicator` | GTI / VirusTotal | Auto-detect & enrich IP, domain, hash, URL |
| `extract_iocs_from_detections` | Google SecOps | Bulk IOC extraction (IPs, domains, hashes, emails) |
| `vertex_ai_investigate` | Vertex AI (Gemini) | AI-powered threat analysis & report generation |

### 📋 Data Table Management
| Tool | API | Description |
|---|---|---|
| `list_data_tables` | Google SecOps | List all Data Tables |
| `get_data_table` | Google SecOps | Read a Data Table's contents |
| `update_data_table` | Google SecOps | Write rows to a Data Table (VIP lists, blocklists, TI feeds) |

### 🛡️ Detection Management
| Tool | API | Description |
|---|---|---|
| `list_rules` | Google SecOps | List all YARA-L rules with status |
| `toggle_rule` | Google SecOps | Enable or disable a YARA-L rule |

### 📧 Email Containment
| Tool | API | Description |
|---|---|---|
| `purge_email_o365` | Microsoft Graph | Hard Delete email from any mailbox by Message-ID |

### 🔑 Identity Containment
| Tool | API | Description |
|---|---|---|
| `suspend_okta_user` | Okta | Suspend user + clear all active sessions |
| `revoke_azure_ad_sessions` | Microsoft Graph | Revoke all Entra ID sign-in sessions |

### ☁️ Cloud Credential Containment
| Tool | API | Description |
|---|---|---|
| `revoke_aws_access_keys` | AWS IAM | Disable all active access keys |
| `revoke_aws_sts_sessions` | AWS IAM | Deny all pre-existing assumed-role sessions |
| `revoke_gcp_sa_keys` | GCP IAM | Delete all user-managed service account keys |

### 🖥️ Endpoint Containment
| Tool | API | Description |
|---|---|---|
| `isolate_crowdstrike_host` | CrowdStrike Falcon | Network-isolate host (by hostname or device ID) |

### 📂 SOAR Case Management
| Tool | API | Description |
|---|---|---|
| `create_soar_case` | Google SecOps SOAR | Create a new investigation case |
| `update_soar_case` | Google SecOps SOAR | Add comments, change priority, close cases |

## Quick Start

```bash
export GCP_PROJECT_ID="your-project-id"
export SECOPS_CUSTOMER_ID="your-customer-id"
chmod +x deploy.sh && ./deploy.sh
```

## Integrations

All integrations are optional. The server degrades gracefully — unconfigured tools return helpful error messages instead of crashing.

| Integration | Environment Variables | Required For |
|---|---|---|
| **Google SecOps** | `SECOPS_PROJECT_ID`, `SECOPS_CUSTOMER_ID`, `SECOPS_REGION` | All SecOps tools |
| **GTI / VirusTotal** | `GTI_API_KEY` | `enrich_indicator` |
| **Microsoft Graph** | `O365_TENANT_ID`, `O365_CLIENT_ID`, `O365_CLIENT_SECRET` | `purge_email_o365` |
| **Okta** | `OKTA_DOMAIN`, `OKTA_API_TOKEN` | `suspend_okta_user` |
| **Azure AD** | `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET` | `revoke_azure_ad_sessions` |
| **AWS** | `SOAR_AWS_KEY`, `SOAR_AWS_SECRET` | `revoke_aws_access_keys`, `revoke_aws_sts_sessions` |
| **CrowdStrike** | `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | `isolate_crowdstrike_host` |

## Documentation

See [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) for detailed deployment, security hardening, and troubleshooting.

## Files

```
├── main.py              # MCP server (22 tools, 40KB)
├── requirements.txt     # Python dependencies
├── Dockerfile           # Production container (non-root)
├── deploy.sh            # One-command deployment
├── test_local.sh        # Local development runner
├── .env.example         # Environment variable template
├── .gitignore           # Git ignore rules
├── README.md            # This file
└── docs/
    └── DEPLOYMENT_GUIDE.md
```

## Security

- **Zero embedded secrets** — Workload Identity + ADC + Secret Manager
- **Non-root container** — dedicated `mcpuser`
- **Authenticated endpoints** — `--no-allow-unauthenticated`
- **Input validation** — all parameters validated before API calls
- **Graceful degradation** — unconfigured integrations return errors, not crashes
- **Structured logging** — JSON format for Cloud Logging ingestion

## Author

David Adohen — Google SecOps, Google Threat Intel, Google Security
