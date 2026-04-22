#!/usr/bin/env bash
# MCP Boss multi-tenant installer.
#
# Runs terraform apply, builds/pushes the container image, rolls the Cloud Run
# service onto the new digest, and prints the service + approvals URLs.
#
# Usage:
#   ./install.sh --project <GCP_PROJECT_ID> --customer-id <CHRONICLE_UUID> \
#                [--region us-central1] [--secops-region us] \
#                [--service mcp-boss] [--repo mcp-boss]
#
# Prerequisites: gcloud (authenticated), terraform >= 1.5, docker (optional;
# we prefer `gcloud builds submit` so no local Docker is needed).

set -euo pipefail

PROJECT=""
REGION="us-central1"
CUSTOMER_ID=""
SECOPS_REGION="us"
SERVICE="mcp-boss"
REPO="mcp-boss"
OAUTH_CLIENT_ID=""
ALLOWED_EMAILS=""
ROLE_MAP_JSON=""
CONTAINER_IMAGE=""
ENABLE_OUTPUT_REDACTION="false"
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --project)          PROJECT="$2";          shift 2 ;;
    --region)           REGION="$2";           shift 2 ;;
    --customer-id)      CUSTOMER_ID="$2";      shift 2 ;;
    --secops-region)    SECOPS_REGION="$2";    shift 2 ;;
    --service)          SERVICE="$2";          shift 2 ;;
    --repo)             REPO="$2";             shift 2 ;;
    --oauth-client-id)  OAUTH_CLIENT_ID="$2";  shift 2 ;;
    --allowed-emails)   ALLOWED_EMAILS="$2";   shift 2 ;;
    --role-map-json)    ROLE_MAP_JSON="$2";    shift 2 ;;
    --container-image)  CONTAINER_IMAGE="$2";  shift 2 ;;
    --enable-redaction) ENABLE_OUTPUT_REDACTION="true"; shift ;;
    --skip-build)       SKIP_BUILD=1;          shift ;;
    -h|--help)
      sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$PROJECT" || -z "$CUSTOMER_ID" ]]; then
  echo "Missing --project or --customer-id" >&2
  exit 1
fi

command -v gcloud    >/dev/null || { echo "gcloud not found in PATH" >&2; exit 1; }
command -v terraform >/dev/null || { echo "terraform not found in PATH" >&2; exit 1; }

TF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TF_DIR/../.." && pwd)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/${SERVICE}:latest"

echo "=========================================="
echo "  MCP Boss installer"
echo "  project  : $PROJECT"
echo "  region   : $REGION  (SecOps region: $SECOPS_REGION)"
echo "  customer : $CUSTOMER_ID"
echo "  service  : $SERVICE"
echo "  repo     : $REPO"
echo "=========================================="

echo ""
echo "[0/4] enabling required GCP APIs"
gcloud services enable \
  securitycenter.googleapis.com \
  securitycentermanagement.googleapis.com \
  logging.googleapis.com \
  bigquery.googleapis.com \
  bigqueryconnection.googleapis.com \
  cloudresourcemanager.googleapis.com \
  aiplatform.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  --project "$PROJECT" --quiet

echo ""
echo "[1/4] terraform init + apply"
cd "$TF_DIR"
terraform init -input=false
TF_VARS=(
  -var "project_id=${PROJECT}"
  -var "region=${REGION}"
  -var "secops_customer_id=${CUSTOMER_ID}"
  -var "secops_region=${SECOPS_REGION}"
  -var "service_name=${SERVICE}"
  -var "image_repo=${REPO}"
  -var "oauth_client_id=${OAUTH_CLIENT_ID}"
  -var "allowed_emails=${ALLOWED_EMAILS}"
  -var "role_map_json=${ROLE_MAP_JSON}"
  -var "enable_output_redaction=${ENABLE_OUTPUT_REDACTION}"
)
if [[ -n "$CONTAINER_IMAGE" ]]; then
  TF_VARS+=(-var "container_image=${CONTAINER_IMAGE}")
fi
terraform apply -input=false -auto-approve "${TF_VARS[@]}"

if [[ $SKIP_BUILD -eq 0 ]]; then
  echo ""
  echo "[2/4] building and pushing image: $IMAGE"
  gcloud builds submit "$REPO_ROOT" --tag "$IMAGE" --project "$PROJECT" --quiet
else
  echo ""
  echo "[2/4] --skip-build set, leaving existing image in place"
fi

echo ""
echo "[3/4] rolling Cloud Run revision onto latest image"
gcloud run services update "$SERVICE" \
  --image "$IMAGE" \
  --region "$REGION" \
  --project "$PROJECT" \
  --quiet

echo ""
echo "[4/4] reading outputs"
SERVICE_URL=$(terraform output -raw service_url)
APPROVALS_URL=$(terraform output -raw approvals_url)
SERVICE_ACCOUNT=$(terraform output -raw service_account)

echo ""
echo "=========================================="
echo "  Installed"
echo "  Cloud Run URL   : $SERVICE_URL"
echo "  Approvals URL   : $APPROVALS_URL"
echo "  Runtime SA      : $SERVICE_ACCOUNT"
echo "=========================================="
echo ""
echo "CLOUD_RUN_URL=$SERVICE_URL"
echo ""
echo "Next steps:"
echo "  1. Upload integration credentials (Secret Manager-backed):"
echo "       SECOPS_PROJECT_ID=$PROJECT SECOPS_CUSTOMER_ID=$CUSTOMER_ID \\"
echo "         $REPO_ROOT/add_keys.sh --use-secret-manager"
echo "  2. Point your Google Chat webhook / approver at: $APPROVALS_URL"
echo "  3. Health check:"
echo "       curl -sS $SERVICE_URL/health | python3 -m json.tool"
