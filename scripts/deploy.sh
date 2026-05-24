#!/bin/bash
###############################################################################
# Full Deployment Script
#
# Deploys the complete OWASP mitigation demo:
# 1. Terraform infrastructure (VPC, IAM, KMS, Lambda, S3, Monitoring)
# 2. AgentCore resources (Runtime, Gateway, Identity, Policy Engine)
# 3. Agent code package
#
# Prerequisites:
# - AWS CLI configured with appropriate permissions
# - Terraform >= 1.5.0 installed
# - AgentCore CLI installed (npm install -g @aws/agentcore)
# - Python 3.13+ for packaging
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="${PROJECT_DIR}/terraform"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

###############################################################################
# Pre-flight checks
###############################################################################

log_info "Running pre-flight checks..."

command -v terraform >/dev/null 2>&1 || { log_error "terraform not found. Install from https://terraform.io"; exit 1; }
command -v aws >/dev/null 2>&1 || { log_error "aws CLI not found. Install from https://aws.amazon.com/cli/"; exit 1; }
command -v python3 >/dev/null 2>&1 || { log_error "python3 not found."; exit 1; }

# Verify AWS credentials
aws sts get-caller-identity >/dev/null 2>&1 || { log_error "AWS credentials not configured"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=${AWS_REGION:-us-east-1}

log_info "Deploying to account ${ACCOUNT_ID} in region ${REGION}"

###############################################################################
# Step 1: Deploy Terraform Infrastructure
###############################################################################

log_info "=== Step 1: Deploying Terraform infrastructure ==="

cd "${TERRAFORM_DIR}"

# Initialize Terraform
terraform init -input=false

# Plan and apply
terraform plan -out=tfplan -input=false
terraform apply -input=false tfplan

# Capture outputs
VPC_ID=$(terraform output -raw vpc_id)
SUBNET_IDS=$(terraform output -json private_subnet_ids | jq -r 'join(",")')
SG_ID=$(terraform output -raw security_group_id)
RUNTIME_ROLE_ARN=$(terraform output -raw runtime_role_arn)
GATEWAY_ROLE_ARN=$(terraform output -raw gateway_role_arn)
CODE_BUCKET=$(terraform output -raw agent_code_bucket)
INPUT_VALIDATOR_ARN=$(terraform output -raw input_validator_lambda_arn)
OUTPUT_FILTER_ARN=$(terraform output -raw output_filter_lambda_arn)
KMS_KEY_ARN=$(terraform output -raw kms_key_arn)

log_info "Infrastructure deployed successfully"
log_info "  VPC: ${VPC_ID}"
log_info "  Subnets: ${SUBNET_IDS}"
log_info "  Runtime Role: ${RUNTIME_ROLE_ARN}"

###############################################################################
# Step 2: Package and Upload Agent Code
###############################################################################

log_info "=== Step 2: Packaging agent code ==="

cd "${PROJECT_DIR}"

# Create deployment package
PACKAGE_DIR=$(mktemp -d)
cp -r src/ "${PACKAGE_DIR}/"
cp requirements.txt "${PACKAGE_DIR}/"

# Install dependencies into package
pip install -r requirements.txt -t "${PACKAGE_DIR}/lib" --quiet

# Create zip
TIMESTAMP=$(date +%Y%m%d%H%M%S)
ZIP_FILE="/tmp/agent-code-${TIMESTAMP}.zip"
cd "${PACKAGE_DIR}"
zip -r "${ZIP_FILE}" . -x "*.pyc" "__pycache__/*" >/dev/null

# Upload to S3
S3_KEY="agent-code/${TIMESTAMP}/agent.zip"
aws s3 cp "${ZIP_FILE}" "s3://${CODE_BUCKET}/${S3_KEY}" --quiet

log_info "Agent code uploaded to s3://${CODE_BUCKET}/${S3_KEY}"

# Cleanup
rm -rf "${PACKAGE_DIR}" "${ZIP_FILE}"

###############################################################################
# Step 3: Deploy AgentCore Resources
###############################################################################

log_info "=== Step 3: Deploying AgentCore resources ==="

cd "${PROJECT_DIR}"

# Create workload identities (ASI03 mitigation)
log_info "Creating workload identities..."
for identity in triage-agent-identity finance-agent-identity knowledge-agent-identity; do
    log_info "  Creating identity: ${identity}"
    aws bedrock-agentcore-control create-workload-identity \
        --name "${identity}" \
        --region "${REGION}" 2>/dev/null || log_warn "  Identity ${identity} may already exist"
done

# Create AgentCore Runtime (ASI05, ASI08 mitigation)
log_info "Creating AgentCore Runtime..."
RUNTIME_RESPONSE=$(aws bedrock-agentcore-control create-agent-runtime \
    --agent-runtime-name "owasp_mitigation_demo" \
    --role-arn "${RUNTIME_ROLE_ARN}" \
    --network-configuration "{\"networkMode\":\"VPC\",\"vpcConfiguration\":{\"subnetIds\":[$(echo ${SUBNET_IDS} | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')]},\"securityGroupIds\":[\"${SG_ID}\"]}}" \
    --code-source "{\"s3\":{\"bucketName\":\"${CODE_BUCKET}\",\"objectKey\":\"${S3_KEY}\"}}" \
    --code-entry-point "src/main.py" \
    --code-runtime "PYTHON_3_13" \
    --idle-runtime-session-timeout 300 \
    --maximum-runtime-session-timeout 1800 \
    --server-protocol "HTTP" \
    --description "Secure Financial Assistant - OWASP risk mitigations demo" \
    --region "${REGION}" 2>&1) || true

log_info "Runtime creation initiated"

# Create Gateway (ASI01, ASI02 mitigation)
log_info "Creating AgentCore Gateway..."
GATEWAY_RESPONSE=$(aws bedrock-agentcore-control create-gateway \
    --name "owasp-demo-gateway" \
    --role-arn "${GATEWAY_ROLE_ARN}" \
    --protocol-type "MCP" \
    --authorizer-type "AWS_IAM" \
    --protocol-configuration "{\"mcp\":{\"searchType\":\"SEMANTIC\",\"instructions\":\"Only expose tools appropriate for the authenticated user role and scope.\"}}" \
    --interceptor-configurations "[{\"interceptor\":{\"lambda\":{\"arn\":\"${INPUT_VALIDATOR_ARN}\"}},\"interceptionPoints\":[\"REQUEST\"]},{\"interceptor\":{\"lambda\":{\"arn\":\"${OUTPUT_FILTER_ARN}\"}},\"interceptionPoints\":[\"RESPONSE\"]}]" \
    --exception-level "DEBUG" \
    --region "${REGION}" 2>&1) || true

log_info "Gateway creation initiated"

###############################################################################
# Step 4: Deploy Cedar Policies
###############################################################################

log_info "=== Step 4: Deploying Cedar policies ==="

# Note: Policy Engine creation and policy deployment requires the
# Gateway to be in READY state. In production, use a waiter or
# separate pipeline step.

log_info "Cedar policies are defined in policies/*.cedar"
log_info "Deploy them after Gateway reaches READY state using:"
log_info "  agentcore policy create --name <policy-name> --definition-file policies/<file>.cedar"

###############################################################################
# Summary
###############################################################################

echo ""
log_info "=== Deployment Complete ==="
echo ""
echo "Infrastructure:"
echo "  VPC:              ${VPC_ID}"
echo "  Subnets:          ${SUBNET_IDS}"
echo "  Security Group:   ${SG_ID}"
echo "  Code Bucket:      ${CODE_BUCKET}"
echo ""
echo "IAM Roles:"
echo "  Runtime:          ${RUNTIME_ROLE_ARN}"
echo "  Gateway:          ${GATEWAY_ROLE_ARN}"
echo ""
echo "Security Controls:"
echo "  KMS Key:          ${KMS_KEY_ARN}"
echo "  Input Validator:  ${INPUT_VALIDATOR_ARN}"
echo "  Output Filter:    ${OUTPUT_FILTER_ARN}"
echo ""
echo "Next steps:"
echo "  1. Wait for Runtime and Gateway to reach READY state"
echo "  2. Deploy Cedar policies to the Policy Engine"
echo "  3. Configure JWT issuer if using CUSTOM_JWT auth"
echo "  4. Run: pytest tests/ -v  to validate security controls"
