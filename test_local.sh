#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Google-Native MCP Server — Local Testing Script
# ═══════════════════════════════════════════════════════════════
#
# Runs the MCP server locally for development and testing.
# Uses your local ADC credentials (gcloud auth application-default login).
#
# Usage:
#   chmod +x test_local.sh
#   ./test_local.sh
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

echo "═══════════════════════════════════════════════════════════"
echo "  Google-Native MCP Server — Local Development"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check ADC
if [ ! -f "${HOME}/.config/gcloud/application_default_credentials.json" ]; then
    echo "[!] No ADC credentials found. Running setup..."
    gcloud auth application-default login
fi

# Set environment variables
export SECOPS_PROJECT_ID="${SECOPS_PROJECT_ID:-your-project-id}"
export SECOPS_CUSTOMER_ID="${SECOPS_CUSTOMER_ID:-your-customer-id}"
export SECOPS_REGION="${SECOPS_REGION:-us}"
export GTI_API_KEY="${GTI_API_KEY:-}"
export PORT=8080

echo "[+] Project:  ${SECOPS_PROJECT_ID}"
echo "[+] Customer: ${SECOPS_CUSTOMER_ID}"
echo "[+] Region:   ${SECOPS_REGION}"
echo "[+] GTI Key:  $([ -n "${GTI_API_KEY}" ] && echo "configured" || echo "not set")"
echo "[+] Port:     ${PORT}"
echo ""
echo "[+] Starting server..."
echo "[+] Health:   http://localhost:${PORT}/health"
echo "[+] SSE:      http://localhost:${PORT}/sse"
echo ""

# Install deps if needed
pip install -q -r requirements.txt 2>/dev/null

# Run the server
python3 main.py
