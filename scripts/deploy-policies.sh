#!/bin/bash
###############################################################################
# Deploy Cedar Policies to AgentCore Policy Engine
#
# Creates a Policy Engine and deploys all Cedar policies from policies/*.cedar
# to enforce tool access control, data boundaries, and behavioral constraints.
#
# Prerequisites:
#   - Gateway must be in READY state
#   - AWS CLI configured with appropriate permissions
#
# Usage:
#   export AWS_REGION=us-east-1
#   bash scripts/deploy-policies.sh
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
POLICIES_DIR="${PROJECT_DIR}/policies"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

REGION="${AWS_REGION:-us-east-1}"
POLICY_ENGINE_NAME="owasp_demo_policy_engine"

###############################################################################
# Pre-flight
###############################################################################

log_info "Deploying Cedar policies to AgentCore Policy Engine"
log_info "  Region: ${REGION}"
log_info "  Policies directory: ${POLICIES_DIR}"
echo ""

# Verify policies directory exists and has .cedar files
if [ ! -d "${POLICIES_DIR}" ] || [ -z "$(ls ${POLICIES_DIR}/*.cedar 2>/dev/null)" ]; then
    log_error "No .cedar files found in ${POLICIES_DIR}"
    exit 1
fi

###############################################################################
# Step 1: Create or find the Policy Engine
###############################################################################

log_info "Step 1: Checking for existing Policy Engine..."

POLICY_ENGINE_ID=$(aws bedrock-agentcore-control list-policy-engines \
    --region "${REGION}" \
    --query "policyEngineSummaries[?name=='${POLICY_ENGINE_NAME}'].policyEngineId" \
    --output text 2>/dev/null) || true

if [ -n "${POLICY_ENGINE_ID}" ] && [ "${POLICY_ENGINE_ID}" != "None" ]; then
    log_info "  Found existing Policy Engine: ${POLICY_ENGINE_ID}"
else
    log_info "  Creating Policy Engine: ${POLICY_ENGINE_NAME}"

    POLICY_ENGINE_ID=$(aws bedrock-agentcore-control create-policy-engine \
        --name "${POLICY_ENGINE_NAME}" \
        --description "Cedar policy engine for OWASP risk mitigation demo" \
        --region "${REGION}" \
        --query "policyEngineId" \
        --output text 2>/dev/null)

    log_info "  Created Policy Engine: ${POLICY_ENGINE_ID}"
    log_info "  Waiting for engine to become ACTIVE..."

    # Poll until active (max 60 seconds)
    for i in $(seq 1 12); do
        STATUS=$(aws bedrock-agentcore-control get-policy-engine \
            --policy-engine-id "${POLICY_ENGINE_ID}" \
            --region "${REGION}" \
            --query "status" \
            --output text 2>/dev/null) || true

        if [ "${STATUS}" = "ACTIVE" ]; then
            log_info "  Policy Engine is ACTIVE"
            break
        fi
        echo -n "."
        sleep 5
    done

    if [ "${STATUS}" != "ACTIVE" ]; then
        log_error "Policy Engine did not become ACTIVE (status: ${STATUS})"
        exit 1
    fi
fi

###############################################################################
# Step 2: Deploy each Cedar policy
###############################################################################

echo ""
log_info "Step 2: Deploying Cedar policies..."

DEPLOYED=0
FAILED=0

for policy_file in "${POLICIES_DIR}"/*.cedar; do
    policy_name=$(basename "${policy_file}" .cedar | tr '-' '_')
    policy_content=$(cat "${policy_file}")

    log_info "  Deploying: ${policy_name}"

    # Check if policy already exists
    EXISTING_POLICY_ID=$(aws bedrock-agentcore-control list-policies \
        --policy-engine-id "${POLICY_ENGINE_ID}" \
        --region "${REGION}" \
        --query "policySummaries[?name=='${policy_name}'].policyId" \
        --output text 2>/dev/null) || true

    if [ -n "${EXISTING_POLICY_ID}" ] && [ "${EXISTING_POLICY_ID}" != "None" ]; then
        # Update existing policy
        log_info "    Updating existing policy: ${EXISTING_POLICY_ID}"
        aws bedrock-agentcore-control update-policy \
            --policy-engine-id "${POLICY_ENGINE_ID}" \
            --policy-id "${EXISTING_POLICY_ID}" \
            --definition "{\"cedar\":{\"statement\":$(echo "${policy_content}" | jq -Rs .)}}" \
            --region "${REGION}" >/dev/null 2>&1 && {
            DEPLOYED=$((DEPLOYED + 1))
        } || {
            log_warn "    Failed to update ${policy_name}"
            FAILED=$((FAILED + 1))
        }
    else
        # Create new policy
        aws bedrock-agentcore-control create-policy \
            --policy-engine-id "${POLICY_ENGINE_ID}" \
            --name "${policy_name}" \
            --definition "{\"cedar\":{\"statement\":$(echo "${policy_content}" | jq -Rs .)}}" \
            --region "${REGION}" >/dev/null 2>&1 && {
            DEPLOYED=$((DEPLOYED + 1))
            log_info "    Created successfully"
        } || {
            log_warn "    Failed to create ${policy_name}"
            FAILED=$((FAILED + 1))
        }
    fi
done

###############################################################################
# Step 3: Associate with Gateway (if available)
###############################################################################

echo ""
log_info "Step 3: Checking for Gateway to associate..."

GATEWAY_ID=$(aws bedrock-agentcore-control list-gateways \
    --region "${REGION}" \
    --query "gateways[?name=='owasp-demo-gateway'].gatewayId" \
    --output text 2>/dev/null) || true

if [ -n "${GATEWAY_ID}" ] && [ "${GATEWAY_ID}" != "None" ]; then
    POLICY_ENGINE_ARN="arn:aws:bedrock-agentcore:${REGION}:$(aws sts get-caller-identity --query Account --output text):policy-engine/${POLICY_ENGINE_ID}"

    log_info "  Associating Policy Engine with Gateway: ${GATEWAY_ID}"
    log_info "  (Update Gateway to add policyEngineConfiguration)"
    log_warn "  Note: Gateway update requires all original fields. Skipping auto-association."
    log_info "  To associate manually, update the Gateway with:"
    echo "    --policy-engine-configuration '{\"arn\": \"${POLICY_ENGINE_ARN}\", \"mode\": \"ENFORCE\"}'"
else
    log_warn "  No Gateway found. Deploy the Gateway first, then re-run this script."
fi

###############################################################################
# Summary
###############################################################################

echo ""
log_info "=== Policy Deployment Complete ==="
echo ""
echo "  Policy Engine: ${POLICY_ENGINE_ID}"
echo "  Deployed: ${DEPLOYED} policies"
echo "  Failed:   ${FAILED} policies"
echo ""
echo "  Policies enforce:"
echo "    • tool_access.cedar    — Least-privilege tool access per agent (ASI02, ASI03)"
echo "    • data_scope.cedar     — Memory namespace isolation (ASI06)"
echo "    • agent_behavior.cedar — Rate limits and behavioral constraints (ASI08, ASI10)"
