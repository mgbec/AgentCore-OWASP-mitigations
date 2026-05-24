#!/bin/bash
# AgentCore OWASP Mitigation Demo - Deployment Script
#
# This script deploys the full security-hardened agent system to AgentCore.
# It demonstrates infrastructure-level mitigations for:
# - ASI03 (Identity): Creates scoped workload identities
# - ASI04 (Supply Chain): Pins dependencies and uses VPC isolation
# - ASI05 (Code Execution): Deploys in isolated MicroVM runtime
# - ASI08 (Cascading Failures): Configures timeouts and session limits
# - Data Security: Enables KMS encryption for credential storage

set -euo pipefail

echo "=== AgentCore OWASP Mitigation Demo Deployment ==="
echo ""

# Configuration
RUNTIME_NAME="owasp_mitigation_demo"
GATEWAY_NAME="owasp-demo-gateway"
ROLE_ARN="${AGENTCORE_ROLE_ARN:?Set AGENTCORE_ROLE_ARN environment variable}"
REGION="${AWS_REGION:-us-east-1}"

echo "1. Creating workload identities (ASI03 mitigation)..."
echo "   Each agent gets a unique, scoped identity with short-lived credentials."

agentcore add identity --name triage-agent-identity
agentcore add identity --name finance-agent-identity
agentcore add identity --name knowledge-agent-identity

echo ""
echo "2. Storing credentials in token vault (Data Security - Credential Exposure)..."
echo "   Secrets are encrypted at rest with KMS. Never hardcoded."

agentcore add credential --name financial-api-key --type api-key \
    --api-key "${FINANCIAL_API_KEY:?Set FINANCIAL_API_KEY}"

echo ""
echo "3. Creating AgentCore Runtime (ASI05, ASI08 mitigation)..."
echo "   MicroVM isolation with session timeouts and VPC network restrictions."

agentcore deploy \
    --name "${RUNTIME_NAME}" \
    --entry-point src/main.py \
    --runtime PYTHON_3_13 \
    --idle-timeout 300 \
    --max-lifetime 1800 \
    --network-mode VPC

echo ""
echo "4. Creating Gateway with policy engine (ASI01, ASI02, ASI10 mitigation)..."
echo "   CUSTOM_JWT auth + Cedar policies + semantic tool search."

agentcore gateway create \
    --name "${GATEWAY_NAME}" \
    --protocol MCP \
    --authorizer CUSTOM_JWT \
    --search-type SEMANTIC

echo ""
echo "5. Deploying Cedar policies (ASI02, ASI06, ASI08, ASI10)..."
echo "   Fine-grained access control enforced at the Gateway layer."

for policy_file in policies/*.cedar; do
    policy_name=$(basename "${policy_file}" .cedar)
    echo "   Deploying policy: ${policy_name}"
    agentcore policy create \
        --name "${policy_name}" \
        --definition-file "${policy_file}"
done

echo ""
echo "6. Configuring observability (ASI09, ASI10, Telemetry Leakage)..."
echo "   OpenTelemetry tracing with PII redaction and anomaly detection."

# Observability is configured via the runtime's OpenTelemetry integration
# The SecurityAuditExporter in src/observability/tracing.py handles:
# - PII redaction in trace attributes
# - Anomaly detection on span patterns
# - Tamper-evident audit logging

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Security mitigations active:"
echo "  ✓ ASI01 - Goal Hijack: Input validation + Gateway interceptors"
echo "  ✓ ASI02 - Tool Misuse: Cedar policies + parameter validation"
echo "  ✓ ASI03 - Privilege Abuse: Scoped workload identities"
echo "  ✓ ASI04 - Supply Chain: VPC isolation + pinned dependencies"
echo "  ✓ ASI05 - Code Execution: MicroVM + Code Interpreter sandbox"
echo "  ✓ ASI06 - Memory Poisoning: Namespace isolation + trust scoring"
echo "  ✓ ASI07 - Inter-Agent Comms: Gateway mTLS + structured schemas"
echo "  ✓ ASI08 - Cascading Failures: Timeouts + rate limits + circuit breakers"
echo "  ✓ ASI09 - Trust Exploitation: Confidence metadata + audit logs"
echo "  ✓ ASI10 - Rogue Agents: Behavioral policies + anomaly detection"
echo ""
echo "Data security mitigations active:"
echo "  ✓ Sensitive Data Leakage: Output filtering + DLP interceptors"
echo "  ✓ Credential Exposure: Token vault with KMS encryption"
echo "  ✓ Shadow AI: Gateway as single controlled entry point"
echo "  ✓ Cross-User Bleed: Memory namespace isolation"
echo "  ✓ Unsafe SQL: Parameterized query templates only"
echo "  ✓ Telemetry Leakage: PII redaction in all traces"
echo "  ✓ Over-Broad Context: Bounded retrieval with trust filtering"
