variable "project_id" {
  description = "Target GCP project ID for MCP Boss deployment"
  type        = string
}

variable "region" {
  description = "Cloud Run region"
  type        = string
  default     = "us-central1"
}

variable "secops_customer_id" {
  description = "Chronicle / SecOps tenant customer ID"
  type        = string
}

variable "secops_region" {
  description = "Chronicle region (us, europe, asia)"
  type        = string
  default     = "us"
}

variable "service_name" {
  description = "Cloud Run service name"
  type        = string
  default     = "mcp-boss"
}

variable "image_repo" {
  description = "Artifact Registry repo name"
  type        = string
  default     = "mcp-boss"
}

variable "compute_sa" {
  description = "Service account to run Cloud Run as. Defaults to Compute Engine default SA."
  type        = string
  default     = ""
}

variable "google_chat_webhook_url" {
  description = "Google Chat space webhook URL for approval cards (empty disables the adapter)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "approval_webhook_url" {
  description = "Generic approval webhook URL (PagerDuty / Opsgenie / ServiceNow / home-grown)"
  type        = string
  default     = ""
}

variable "audit_path" {
  description = "Container path for the hash-chained audit log"
  type        = string
  default     = "/var/log/mcp-boss/audit.jsonl"
}

variable "container_image" {
  description = "Full Artifact Registry image URI to deploy. Leave empty to default to <region>-docker.pkg.dev/<project>/<repo>/<service>:latest."
  type        = string
  default     = ""
}

variable "oauth_client_id" {
  description = "Google OAuth client ID. When set, the server requires Google OIDC ID tokens whose aud matches this value."
  type        = string
  default     = ""
}

variable "allowed_emails" {
  description = "Comma-separated list of principal emails allowed past the OAuth check. Empty disables the allowlist."
  type        = string
  default     = ""
}

variable "role_map_json" {
  description = "Inline JSON mapping emails or domains to approver roles (see policy_and_approvals/policies.yaml). Empty disables inline role mapping."
  type        = string
  default     = ""
}

variable "enable_output_redaction" {
  description = "Toggle DLP-style redaction of tool results before they flow back to the LLM. OFF by default."
  type        = bool
  default     = false
}

# Sensitive credentials. Leave empty to skip creating a secret for that key;
# the installer can upload values after `terraform apply` via `add_keys.sh`.
variable "sensitive_secrets" {
  description = "Map of integration credential name to initial plaintext value. Empty values create the secret stub but no version."
  type        = map(string)
  default = {
    GTI_API_KEY               = ""
    OKTA_API_TOKEN            = ""
    AZURE_AD_CLIENT_SECRET    = ""
    AWS_SECRET_ACCESS_KEY     = ""
    CROWDSTRIKE_CLIENT_SECRET = ""
    O365_CLIENT_SECRET        = ""
    APPROVAL_WEBHOOK_SECRET   = ""
  }
  sensitive = true
}
