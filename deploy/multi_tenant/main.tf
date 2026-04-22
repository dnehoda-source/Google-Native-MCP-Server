terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  required_apis = [
    "securitycenter.googleapis.com",
    "securitycentermanagement.googleapis.com",
    "logging.googleapis.com",
    "bigquery.googleapis.com",
    "bigqueryconnection.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.required_apis)
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "mcp_boss" {
  location      = var.region
  repository_id = var.image_repo
  format        = "DOCKER"
  description   = "MCP Boss container images"
  depends_on    = [google_project_service.apis]
}

locals {
  # Always create the stub secret for every declared credential slot so the
  # Cloud Run service can reference it. Secret *versions* are only created when
  # an initial plaintext value is supplied; the installer / operator can add
  # versions later via add_keys.sh or gcloud.
  secret_stubs = var.sensitive_secrets
  seeded_secrets = {
    for k, v in var.sensitive_secrets : k => v if v != ""
  }
  # Secret name convention: mcp-boss-<lowercased-hyphened-key>
  secret_name = {
    for k, _ in var.sensitive_secrets :
    k => "mcp-boss-${replace(lower(k), "_", "-")}"
  }
  image_uri = coalesce(
    var.container_image,
    "${var.region}-docker.pkg.dev/${var.project_id}/${var.image_repo}/${var.service_name}:latest",
  )
}

resource "google_secret_manager_secret" "credentials" {
  for_each  = local.secret_stubs
  project   = var.project_id
  secret_id = local.secret_name[each.key]
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "credentials" {
  for_each    = local.seeded_secrets
  secret      = google_secret_manager_secret.credentials[each.key].id
  secret_data = each.value
}

resource "google_secret_manager_secret_iam_member" "sa_accessor" {
  for_each  = local.secret_stubs
  project   = var.project_id
  secret_id = google_secret_manager_secret.credentials[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.compute_sa_email}"
}

# Cloud Run service. The installer must build and push the image to the
# Artifact Registry repo before the service becomes healthy.
resource "google_cloud_run_v2_service" "mcp_boss" {
  name     = var.service_name
  location = var.region
  template {
    service_account = local.compute_sa_email
    containers {
      image = local.image_uri
      env {
        name  = "SECOPS_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "SECOPS_CUSTOMER_ID"
        value = var.secops_customer_id
      }
      env {
        name  = "SECOPS_REGION"
        value = var.secops_region
      }
      env {
        name  = "OAUTH_CLIENT_ID"
        value = var.oauth_client_id
      }
      env {
        name  = "ALLOWED_EMAILS"
        value = var.allowed_emails
      }
      env {
        name  = "ROLE_MAP_JSON"
        value = var.role_map_json
      }
      env {
        name  = "ENABLE_OUTPUT_REDACTION"
        value = var.enable_output_redaction ? "1" : "0"
      }
      env {
        name  = "GOOGLE_CHAT_WEBHOOK_URL"
        value = var.google_chat_webhook_url
      }
      env {
        name  = "APPROVAL_WEBHOOK_URL"
        value = var.approval_webhook_url
      }
      env {
        name  = "MCP_BOSS_AUDIT_PATH"
        value = var.audit_path
      }

      # Pull each seeded secret into the container via Secret Manager refs.
      # Stubs without a version are left unreferenced until populated; the
      # server treats missing integration creds as "integration disabled".
      dynamic "env" {
        for_each = local.seeded_secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.credentials[env.key].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }
  depends_on = [
    google_artifact_registry_repository.mcp_boss,
    google_secret_manager_secret_iam_member.sa_accessor,
    google_secret_manager_secret_version.credentials,
  ]
}

output "service_url" {
  value = google_cloud_run_v2_service.mcp_boss.uri
}

output "approvals_url" {
  value       = "${google_cloud_run_v2_service.mcp_boss.uri}/api/approvals"
  description = "Point Google Chat / webhook approvers at this URL"
}

output "image_uri" {
  value       = local.image_uri
  description = "Tag to build and push to"
}

output "created_secrets" {
  value       = [for k, _ in local.secret_stubs : local.secret_name[k]]
  description = "Secret Manager secret stubs created for sensitive credentials"
}

output "seeded_secrets" {
  value       = [for k, _ in local.seeded_secrets : local.secret_name[k]]
  description = "Secret Manager secrets that have an initial version populated"
}
