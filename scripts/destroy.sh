#!/bin/bash
###############################################################################
# Teardown Script
#
# Destroys all deployed resources in reverse order:
# 1. AgentCore resources (Runtime, Gateway, Identities)
# 2. Terraform infrastructure
#
# WARNING: This is destructive and irreversible.
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="${PROJECT_DIR}/terraform"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo -e "${RED}WARNING: This will destroy ALL deployed resources.${NC}"
echo "This action is irreversible."
echo ""
read -p "Type 'destroy' to confirm: " CONFIRM

if [ "$CONFIRM" != "destroy" ]; then
    log_info "Aborted."
    exit 0
fi

REGION=${AWS_REGION:-us-east-1}

###############################################################################
# Step 1: Delete AgentCore Resources
###############################################################################

log_info "=== Step 1: Deleting AgentCore resources ==="

# Delete Gateway (must delete targets first)
log_info "Deleting Gateway..."
GATEWAY_ID=$(aws bedrock-agentcore-control list-gateways \
    --region "${REGION}" \
    --query "gateways[?name=='owasp-demo-gateway'].gatewayId" \
    --output text 2>/dev/null) || true

if [ -n "$GATEWAY_ID" ] && [ "$GATEWAY_ID" != "None" ]; then
    # Delete targets first
    TARGETS=$(aws bedrock-agentcore-control list-gateway-targets \
        --gateway-identifier "${GATEWAY_ID}" \
        --region "${REGION}" \
        --query "targets[].targetId" \
        --output text 2>/dev/null) || true

    for target in $TARGETS; do
        log_info "  Deleting target: ${target}"
        aws bedrock-agentcore-control delete-gateway-target \
            --gateway-identifier "${GATEWAY_ID}" \
            --target-id "${target}" \
            --region "${REGION}" 2>/dev/null || true
    done

    aws bedrock-agentcore-control delete-gateway \
        --gateway-identifier "${GATEWAY_ID}" \
        --region "${REGION}" 2>/dev/null || true
    log_info "  Gateway deleted"
fi

# Delete Runtime
log_info "Deleting Runtime..."
RUNTIME_ID=$(aws bedrock-agentcore-control list-agent-runtimes \
    --region "${REGION}" \
    --query "agentRuntimeSummaries[?agentRuntimeName=='owasp_mitigation_demo'].agentRuntimeId" \
    --output text 2>/dev/null) || true

if [ -n "$RUNTIME_ID" ] && [ "$RUNTIME_ID" != "None" ]; then
    # Delete non-default endpoints first
    ENDPOINTS=$(aws bedrock-agentcore-control list-agent-runtime-endpoints \
        --agent-runtime-id "${RUNTIME_ID}" \
        --region "${REGION}" \
        --query "agentRuntimeEndpoints[?name!='DEFAULT'].name" \
        --output text 2>/dev/null) || true

    for endpoint in $ENDPOINTS; do
        log_info "  Deleting endpoint: ${endpoint}"
        aws bedrock-agentcore-control delete-agent-runtime-endpoint \
            --agent-runtime-id "${RUNTIME_ID}" \
            --endpoint-name "${endpoint}" \
            --region "${REGION}" 2>/dev/null || true
    done

    aws bedrock-agentcore-control delete-agent-runtime \
        --agent-runtime-id "${RUNTIME_ID}" \
        --region "${REGION}" 2>/dev/null || true
    log_info "  Runtime deleted"
fi

# Delete workload identities
log_info "Deleting workload identities..."
for identity in triage-agent-identity finance-agent-identity knowledge-agent-identity; do
    aws bedrock-agentcore-control delete-workload-identity \
        --name "${identity}" \
        --region "${REGION}" 2>/dev/null || true
    log_info "  Deleted: ${identity}"
done

###############################################################################
# Step 2: Destroy Terraform Infrastructure
###############################################################################

log_info "=== Step 2: Destroying Terraform infrastructure ==="

cd "${TERRAFORM_DIR}"

terraform destroy -auto-approve

log_info "=== Teardown Complete ==="
