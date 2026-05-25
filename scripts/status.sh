#!/bin/bash
###############################################################################
# Status Check - Verify Deployment State
#
# Checks the status of all deployed AgentCore resources.
# Run after deploy.sh to confirm everything reached READY state.
#
# Usage:
#   bash scripts/status.sh
###############################################################################

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

REGION="${AWS_REGION:-us-east-1}"

status_icon() {
    case "$1" in
        READY|ACTIVE|AVAILABLE) echo -e "${GREEN}✓ $1${NC}" ;;
        CREATING|UPDATING|SYNCHRONIZING) echo -e "${YELLOW}⟳ $1${NC}" ;;
        *FAILED*|ERROR) echo -e "${RED}✗ $1${NC}" ;;
        *) echo -e "${YELLOW}? $1${NC}" ;;
    esac
}

echo "=== AgentCore OWASP Demo — Deployment Status ==="
echo "Region: ${REGION}"
echo ""

###############################################################################
# Terraform State
###############################################################################

echo "--- Terraform Infrastructure ---"
TERRAFORM_DIR="$(dirname "$(dirname "$(realpath "$0")")")/terraform"

if [ -f "${TERRAFORM_DIR}/backend.hcl" ]; then
    echo -e "  State backend:  ${GREEN}✓ configured${NC}"
else
    echo -e "  State backend:  ${RED}✗ not bootstrapped (run scripts/bootstrap.sh)${NC}"
fi

###############################################################################
# AgentCore Runtime
###############################################################################

echo ""
echo "--- AgentCore Runtime ---"

RUNTIME_INFO=$(aws bedrock-agentcore-control list-agent-runtimes \
    --region "${REGION}" \
    --query "agentRuntimeSummaries[?agentRuntimeName=='owasp_mitigation_demo'] | [0]" \
    --output json 2>/dev/null) || true

if [ -n "${RUNTIME_INFO}" ] && [ "${RUNTIME_INFO}" != "null" ]; then
    RUNTIME_STATUS=$(echo "${RUNTIME_INFO}" | jq -r '.status // "UNKNOWN"')
    RUNTIME_ID=$(echo "${RUNTIME_INFO}" | jq -r '.agentRuntimeId // "N/A"')
    echo -e "  Name:    owasp_mitigation_demo"
    echo -e "  ID:      ${RUNTIME_ID}"
    echo -e "  Status:  $(status_icon "${RUNTIME_STATUS}")"
else
    echo -e "  Status:  ${RED}✗ not deployed${NC}"
fi

###############################################################################
# AgentCore Gateway
###############################################################################

echo ""
echo "--- AgentCore Gateway ---"

GATEWAY_INFO=$(aws bedrock-agentcore-control list-gateways \
    --region "${REGION}" \
    --query "gateways[?name=='owasp-demo-gateway'] | [0]" \
    --output json 2>/dev/null) || true

if [ -n "${GATEWAY_INFO}" ] && [ "${GATEWAY_INFO}" != "null" ]; then
    GATEWAY_STATUS=$(echo "${GATEWAY_INFO}" | jq -r '.status // "UNKNOWN"')
    GATEWAY_ID=$(echo "${GATEWAY_INFO}" | jq -r '.gatewayId // "N/A"')
    GATEWAY_AUTH=$(echo "${GATEWAY_INFO}" | jq -r '.authorizerType // "N/A"')
    echo -e "  Name:    owasp-demo-gateway"
    echo -e "  ID:      ${GATEWAY_ID}"
    echo -e "  Auth:    ${GATEWAY_AUTH}"
    echo -e "  Status:  $(status_icon "${GATEWAY_STATUS}")"
else
    echo -e "  Status:  ${RED}✗ not deployed${NC}"
fi

###############################################################################
# Policy Engine
###############################################################################

echo ""
echo "--- Policy Engine ---"

PE_INFO=$(aws bedrock-agentcore-control list-policy-engines \
    --region "${REGION}" \
    --query "policyEngineSummaries[?name=='owasp_demo_policy_engine'] | [0]" \
    --output json 2>/dev/null) || true

if [ -n "${PE_INFO}" ] && [ "${PE_INFO}" != "null" ]; then
    PE_STATUS=$(echo "${PE_INFO}" | jq -r '.status // "UNKNOWN"')
    PE_ID=$(echo "${PE_INFO}" | jq -r '.policyEngineId // "N/A"')
    echo -e "  Name:    owasp_demo_policy_engine"
    echo -e "  ID:      ${PE_ID}"
    echo -e "  Status:  $(status_icon "${PE_STATUS}")"

    # Count policies
    POLICY_COUNT=$(aws bedrock-agentcore-control list-policies \
        --policy-engine-id "${PE_ID}" \
        --region "${REGION}" \
        --query "length(policySummaries)" \
        --output text 2>/dev/null) || POLICY_COUNT="?"
    echo -e "  Policies: ${POLICY_COUNT}"
else
    echo -e "  Status:  ${RED}✗ not deployed${NC}"
fi

###############################################################################
# Workload Identities
###############################################################################

echo ""
echo "--- Workload Identities ---"

for identity in triage-agent-identity finance-agent-identity knowledge-agent-identity; do
    EXISTS=$(aws bedrock-agentcore-control get-workload-identity \
        --name "${identity}" \
        --region "${REGION}" \
        --query "name" \
        --output text 2>/dev/null) || true

    if [ -n "${EXISTS}" ] && [ "${EXISTS}" != "None" ]; then
        echo -e "  ${identity}: ${GREEN}✓ exists${NC}"
    else
        echo -e "  ${identity}: ${RED}✗ missing${NC}"
    fi
done

###############################################################################
# Cognito
###############################################################################

echo ""
echo "--- Cognito (OAuth 2.1) ---"

POOL_COUNT=$(aws cognito-idp list-user-pools --max-results 20 \
    --region "${REGION}" \
    --query "length(UserPools[?contains(Name, 'owasp-mitigation')])" \
    --output text 2>/dev/null) || POOL_COUNT="0"

if [ "${POOL_COUNT}" != "0" ]; then
    echo -e "  User Pool: ${GREEN}✓ deployed${NC}"
else
    echo -e "  User Pool: ${RED}✗ not deployed${NC}"
fi

###############################################################################
# Summary
###############################################################################

echo ""
echo "--- Summary ---"

ALL_READY=true

if [ "${RUNTIME_INFO}" = "null" ] || [ -z "${RUNTIME_INFO}" ]; then
    ALL_READY=false
elif [ "$(echo "${RUNTIME_INFO}" | jq -r '.status')" != "READY" ]; then
    ALL_READY=false
fi

if [ "${GATEWAY_INFO}" = "null" ] || [ -z "${GATEWAY_INFO}" ]; then
    ALL_READY=false
elif [ "$(echo "${GATEWAY_INFO}" | jq -r '.status')" != "READY" ]; then
    ALL_READY=false
fi

if [ "${ALL_READY}" = true ]; then
    echo -e "${GREEN}All resources are READY. Deployment is complete.${NC}"
    echo ""
    echo "You can now invoke the agent via the Gateway."
else
    echo -e "${YELLOW}Some resources are still provisioning or missing.${NC}"
    echo "Re-run this script in a minute to check again."
fi
