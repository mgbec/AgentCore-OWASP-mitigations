#!/bin/bash
###############################################################################
# Deploy AgentCore Resources
#
# Uses the AgentCore CLI (@aws/agentcore) to deploy:
#   - Agent Runtime (with code)
#   - Gateway
#   - Workload Identities
#
# Prerequisites:
#   - npm install -g @aws/agentcore
#   - Terraform already applied (VPC, IAM, etc. exist)
#   - AWS credentials configured
#
# Usage:
#   export AWS_REGION=us-east-1
#   bash scripts/deploy-agentcore.sh
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="${PROJECT_DIR}/terraform"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

REGION="${AWS_REGION:-us-east-1}"

###############################################################################
# Pre-flight checks
###############################################################################

log_info "Checking prerequisites..."

# Check AgentCore CLI
if ! command -v agentcore >/dev/null 2>&1; then
    log_error "AgentCore CLI not found."
    echo ""
    echo "Install it with:"
    echo "  npm install -g @aws/agentcore"
    echo ""
    echo "Then verify:"
    echo "  agentcore --version"
    exit 1
fi

log_info "  AgentCore CLI: $(agentcore --version 2>/dev/null || echo 'installed')"

# Check AWS credentials
if ! aws sts get-caller-identity >/dev/null 2>&1; then
    log_error "AWS credentials not configured"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
log_info "  AWS Account: ${ACCOUNT_ID}"
log_info "  Region: ${REGION}"

# Check Terraform outputs are available
if [ ! -d "${TERRAFORM_DIR}/.terraform" ]; then
    log_error "Terraform not initialized. Run 'terraform apply' first."
    exit 1
fi

cd "${TERRAFORM_DIR}"

RUNTIME_ROLE_ARN=$(terraform output -raw runtime_role_arn 2>/dev/null) || {
    log_error "Cannot read Terraform outputs. Run 'terraform apply' first."
    exit 1
}

GATEWAY_ROLE_ARN=$(terraform output -raw gateway_role_arn 2>/dev/null)
SUBNET_IDS=$(terraform output -json private_subnet_ids 2>/dev/null | jq -r 'join(",")')
SG_ID=$(terraform output -raw security_group_id 2>/dev/null)
INPUT_VALIDATOR_ARN=$(terraform output -raw input_validator_lambda_arn 2>/dev/null)
OUTPUT_FILTER_ARN=$(terraform output -raw output_filter_lambda_arn 2>/dev/null)
COGNITO_ISSUER=$(terraform output -raw cognito_issuer_url 2>/dev/null) || true
COGNITO_AGENT_CLIENT=$(terraform output -raw cognito_agent_client_id 2>/dev/null) || true
COGNITO_USER_CLIENT=$(terraform output -raw cognito_user_client_id 2>/dev/null) || true

log_info "  Runtime Role: ${RUNTIME_ROLE_ARN}"
log_info "  Gateway Role: ${GATEWAY_ROLE_ARN}"
echo ""

###############################################################################
# Step 1: Initialize AgentCore project (if not already done)
###############################################################################

cd "${PROJECT_DIR}"

log_info "=== Step 1: Setting up AgentCore project ==="

if [ ! -d "agentcore" ]; then
    log_info "Initializing AgentCore project..."
    agentcore create --name owasp_mitigation_demo --defaults 2>/dev/null || true
fi

###############################################################################
# Step 2: Configure the agent
###############################################################################

log_info "=== Step 2: Configuring agent ==="

# Write the agentcore config
mkdir -p agentcore
cat > agentcore/agentcore.json <<EOF
{
  "agents": [{
    "name": "owasp_mitigation_demo",
    "language": "Python",
    "framework": "Strands",
    "type": "create",
    "codeLocation": "src",
    "entrypoint": "main.py",
    "build": "CodeZip",
    "modelProvider": "Bedrock",
    "protocol": "HTTP",
    "networkMode": "VPC",
    "memory": "longAndShortTerm"
  }],
  "agentCoreGateways": [{
    "name": "owasp-demo-gateway",
    "description": "Secure gateway with JWT auth, Cedar policies, and DLP interceptors",
    "targets": []
  }]
}
EOF

log_info "  Config written to agentcore/agentcore.json"

###############################################################################
# Step 3: Add identities
###############################################################################

log_info "=== Step 3: Creating workload identities ==="

for identity in triage-agent-identity finance-agent-identity knowledge-agent-identity; do
    log_info "  Adding identity: ${identity}"
    agentcore add identity --name "${identity}" 2>/dev/null || log_warn "  ${identity} may already exist"
done

###############################################################################
# Step 4: Add gateway with JWT auth
###############################################################################

log_info "=== Step 4: Configuring gateway ==="

if [ -n "${COGNITO_ISSUER}" ]; then
    DISCOVERY_URL="${COGNITO_ISSUER}/.well-known/openid-configuration"
    log_info "  Using Cognito JWT: ${DISCOVERY_URL}"

    agentcore add gateway \
        --name owasp-demo-gateway \
        --authorizer-type CUSTOM_JWT \
        --discovery-url "${DISCOVERY_URL}" \
        --allowed-clients "${COGNITO_AGENT_CLIENT},${COGNITO_USER_CLIENT}" \
        --exception-level DEBUG 2>/dev/null || log_warn "  Gateway may already exist"
else
    log_warn "  Cognito not available, using AWS_IAM auth"
    agentcore add gateway \
        --name owasp-demo-gateway 2>/dev/null || log_warn "  Gateway may already exist"
fi

###############################################################################
# Step 5: Deploy
###############################################################################

echo ""
log_info "=== Step 5: Deploying to AWS ==="
log_info "This will package the code and deploy to AgentCore Runtime."
log_info "It may take 3-5 minutes..."
echo ""

agentcore deploy -y

###############################################################################
# Done
###############################################################################

echo ""
log_info "=== AgentCore Deployment Complete ==="
echo ""
echo "Check status with:"
echo "  agentcore status"
echo "  bash scripts/status.sh"
echo ""
echo "Invoke the agent with:"
echo "  agentcore invoke \"What is my account balance?\""
echo ""
echo "Stream responses:"
echo "  agentcore invoke --stream \"Show my recent transactions\""
