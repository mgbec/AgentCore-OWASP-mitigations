# AgentCore OWASP Risk Mitigation Demo

A demonstration project showing how **Amazon Bedrock AgentCore** services mitigate risks identified in:

- **OWASP Top 10 for Agentic Applications (2026)** — 10 agentic security risks (ASI01–ASI10)
- **OWASP GenAI Data Security Risks and Mitigations (2026 v1.0)** — 21 data-security risk categories

## Architecture Overview

This project implements a **Secure Financial Assistant** — a multi-agent system that processes customer requests, executes financial operations, and retrieves knowledge from documents. It deliberately exercises the full AgentCore platform to demonstrate mitigations for each risk category.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AgentCore Gateway                             │
│  (MCP protocol, CUSTOM_JWT auth, Cedar policy engine, semantic search)│
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │  Triage Agent │──▶│ Finance Agent │──▶│ Knowledge Retrieval  │    │
│  │  (Orchestrator)│   │ (Executor)    │   │ Agent (RAG)          │    │
│  └──────────────┘   └──────────────┘   └──────────────────────┘    │
│         │                    │                      │                 │
│         ▼                    ▼                      ▼                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │  AgentCore   │   │  AgentCore   │   │  AgentCore Memory    │    │
│  │  Identity    │   │  Code        │   │  (Semantic + Event)  │    │
│  │              │   │  Interpreter │   │                      │    │
│  └──────────────┘   └──────────────┘   └──────────────────────┘    │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              AgentCore Observability (OpenTelemetry)           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │              AgentCore Runtime (Serverless MicroVMs)           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Risk-to-Service Mapping

### OWASP Agentic Top 10 Mitigations

| Risk | Description | AgentCore Mitigation |
|------|-------------|---------------------|
| **ASI01** | Agent Goal Hijack | Gateway Cedar policies + Lambda interceptors; **structural separation** (user input wrapped in data boundaries) |
| **ASI02** | Tool Misuse & Exploitation | Gateway tool filtering + policy engine enforcement; Code Interpreter sandboxing |
| **ASI03** | Identity & Privilege Abuse | Identity service with scoped workload identities and short-lived credentials |
| **ASI04** | Supply Chain Vulnerabilities | Gateway target pinning; Runtime container isolation; VPC network restrictions |
| **ASI05** | Unexpected Code Execution | Code Interpreter isolated sandboxes; Runtime MicroVM isolation |
| **ASI06** | Memory & Context Poisoning | Memory service with namespace segmentation and trust-scored writes |
| **ASI07** | Insecure Inter-Agent Communication | Gateway mTLS; Runtime session isolation; signed message schemas |
| **ASI08** | Cascading Failures | Runtime session timeouts; circuit breakers; blast-radius caps via policy |
| **ASI09** | Human-Agent Trust Exploitation | Observability audit trails; confidence metadata in responses |
| **ASI10** | Rogue Agents | Policy engine behavioral constraints; Observability anomaly detection |

### OWASP GenAI Data Security Mitigations

| Data Risk Category | AgentCore Mitigation |
|-------------------|---------------------|
| Sensitive Data Leakage | Gateway interceptors for DLP scanning; output filtering |
| Agent Identity & Credential Exposure | Identity service token vault with KMS encryption |
| Shadow AI | Gateway as single controlled entry point; resource policies |
| Poisoning & Tampering | Memory provenance tracking; Gateway target attestation |
| Governance & Compliance | Policy engine Cedar policies; Observability audit logs |
| Cross-User Conversation Bleed | Memory namespace isolation per user/session |
| Unsafe LLM-to-SQL Gateways | Code Interpreter sandboxed execution; parameterized queries |
| Vector-Store Risks | Memory service managed embeddings with access controls |
| Telemetry Leakage | Observability with least-logging principles; PII redaction |
| Over-Broad Context Windows | Memory selective retrieval; Gateway semantic search scoping |
| Inference & Reconstruction Attacks | Runtime session isolation; credential rotation |
| Model Exfiltration | VPC network controls; Runtime egress restrictions |

## Project Structure

```
agentcore-owasp-mitigations/
├── README.md
├── SECURITY.md                       # Vulnerability disclosure policy
├── LICENSE
├── pyproject.toml                    # Python/pytest configuration
├── requirements.txt
├── agentcore.json                    # AgentCore deployment config
├── conftest.py                       # Test path setup
├── docs/
│   └── data-flow-diagram.md         # Security controls walkthrough
├── src/
│   ├── agents/
│   │   ├── triage_agent.py          # Orchestrator with structural separation
│   │   ├── finance_agent.py         # Executor with tool constraints
│   │   └── knowledge_agent.py       # RAG agent with memory isolation
│   ├── tools/
│   │   └── financial_tools.py       # Scoped financial operations
│   ├── security/
│   │   ├── input_validator.py       # Prompt injection detection
│   │   ├── output_filter.py         # PII/sensitive data redaction
│   │   ├── prompt_sanitizer.py      # Structural separation (data boundaries)
│   │   ├── policy_definitions.py    # Cedar policy templates
│   │   └── memory_guard.py          # Memory write validation
│   ├── observability/
│   │   └── tracing.py               # OpenTelemetry instrumentation
│   └── main.py                      # Entry point
├── policies/
│   ├── tool_access.cedar            # Tool-level access control
│   ├── data_scope.cedar             # Data boundary enforcement
│   └── agent_behavior.cedar         # Behavioral constraints
├── lambda/
│   ├── input_validator/handler.py   # Gateway REQUEST interceptor
│   └── output_filter/handler.py     # Gateway RESPONSE interceptor
├── terraform/
│   ├── main.tf                      # Provider and backend config
│   ├── variables.tf                 # All configurable inputs
│   ├── outputs.tf                   # Values for AgentCore deployment
│   ├── vpc.tf                       # Network isolation
│   ├── iam.tf                       # Least-privilege roles
│   ├── kms.tf                       # Encryption keys
│   ├── s3.tf                        # Code storage
│   ├── secrets.tf                   # Credential storage
│   ├── lambda.tf                    # Gateway interceptors
│   ├── cognito.tf                   # OAuth 2.1 JWT provider
│   ├── monitoring.tf                # CloudWatch alarms
│   └── terraform.tfvars.example     # Configuration template
├── scripts/
│   ├── bootstrap.sh                 # Create S3 state bucket (one-time)
│   ├── deploy.sh                    # Full deployment pipeline
│   ├── deploy-policies.sh           # Cedar policy deployment
│   ├── package-agent.sh             # Build agent zip package
│   ├── validate.sh                  # Pre-deployment checks
│   └── destroy.sh                   # Teardown with confirmation
├── infrastructure/
│   ├── deploy.sh                    # Legacy AgentCore CLI deployment
│   └── iam_roles.json               # IAM role reference
├── tests/
│   ├── test_goal_hijack.py          # ASI01 attack simulation
│   ├── test_tool_misuse.py          # ASI02 attack simulation
│   ├── test_memory_poisoning.py     # ASI06 attack simulation
│   ├── test_data_leakage.py         # Data security validation
│   └── test_prompt_sanitizer.py     # Structural separation tests
└── .github/
    ├── CODEOWNERS                   # Security review requirements
    ├── dependabot.yml               # Automated dependency updates
    ├── pull_request_template.md     # Security checklist for PRs
    └── workflows/security.yml       # CI: SAST, audit, tests
```

## Getting Started

### Prerequisites

- Python 3.13+
- AWS CLI configured with appropriate permissions
- AgentCore CLI (`npm install -g @aws/agentcore`)
- Terraform >= 1.5.0 (for infrastructure deployment)

### Installation

```bash
cd agentcore-owasp-mitigations

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install dev/test dependencies
pip install bandit pip-audit pytest
```

To deactivate the virtual environment when you're done:

```bash
deactivate
```

### Local Development

```bash
source .venv/bin/activate
python src/main.py
```

### Deploy to AgentCore (Full Deployment)

The project includes Terraform for infrastructure and scripts for the full deployment pipeline:

```bash
# 0. Bootstrap (one-time): create S3 state bucket and DynamoDB lock table
export AWS_REGION=us-east-1
bash scripts/bootstrap.sh

# 1. Validate everything before deploying
bash scripts/validate.sh

# 2. Deploy infrastructure + agent (one command)
bash scripts/deploy.sh

# 3. Or deploy step-by-step:
#    a. Bootstrap state bucket (one-time)
bash scripts/bootstrap.sh

#    b. Infrastructure
cd terraform
cp terraform.tfvars.example terraform.tfvars  # Edit with your values
terraform init -backend-config=backend.hcl
terraform plan
terraform apply

#    c. Package and upload agent code
bash scripts/package-agent.sh

#    c. Deploy AgentCore resources using outputs from Terraform
#       (see terraform output agentcore_deploy_command)
```

### Teardown

```bash
bash scripts/destroy.sh
```

### Terraform Infrastructure

The `terraform/` directory provisions:

| Resource | Purpose | OWASP Mitigation |
|----------|---------|-----------------|
| VPC + Private Subnets | Network isolation, no internet | ASI04, ASI05, Model Exfiltration |
| VPC Endpoints | AWS service access without internet | ASI04 |
| Security Groups | Restricted egress | ASI10 |
| IAM Roles | Least-privilege per component | ASI03 |
| KMS Key | Encryption at rest for secrets | Credential Exposure |
| S3 Buckets | Encrypted code storage | ASI04 |
| Lambda Interceptors | Input/output filtering at Gateway | ASI01, Data Leakage |
| Cognito User Pool | OAuth 2.1 JWT authentication (PKCE + client_credentials) | ASI03, ASI09 |
| CloudWatch + Alarms | Security monitoring & alerting | ASI09, ASI10 |
| VPC Flow Logs | Network anomaly detection | ASI10 |

## How Each Component Demonstrates Mitigations

### 1. AgentCore Gateway — Controlled Entry Point (ASI01, ASI02, ASI04, Data Leakage)

The Gateway acts as the single entry point for all agent interactions:
- **CUSTOM_JWT authorization** via Cognito (OAuth 2.1) prevents unauthorized access
- **Cedar policy engine** enforces fine-grained tool-level permissions
- **Lambda interceptors** scan inputs/outputs for prompt injection and PII
- **Semantic search** scopes tool discovery to prevent tool confusion attacks
- **Target pinning** ensures only attested MCP servers are reachable

### 2. Structural Separation — Prompt Injection Containment (ASI01)

User input is architecturally isolated from agent instructions:
- **PromptSanitizer** strips invisible characters and escapes boundary-breaking sequences
- User text is wrapped in `<user_request>` tags with `trust_level: untrusted` metadata
- Agent system prompts explicitly declare tagged content as DATA, not instructions
- Even if injection passes detection, it cannot escape its structural container

See [docs/data-flow-diagram.md](docs/data-flow-diagram.md) for the full walkthrough.

### 3. AgentCore Identity + Cognito — Scoped Credentials (ASI03, Credential Exposure)

Each agent gets a unique workload identity:
- **Cognito User Pool** issues OAuth 2.1 JWTs with custom scopes (`finance.read`, `finance.write`, `knowledge.read`)
- **Short-lived tokens** (1 hour) prevent credential reuse across sessions
- **Token vault with KMS** encrypts secrets at rest
- **PKCE** required for browser-based clients (OAuth 2.1 mandate)
- **Resource policies** restrict which identities can invoke which runtimes

### 4. AgentCore Runtime — Isolated Execution (ASI05, ASI08, ASI10)

Agents run in isolated MicroVMs:
- **Session isolation** prevents cross-agent contamination
- **Idle timeouts** automatically terminate runaway agents
- **VPC mode** restricts network egress to prevent data exfiltration
- **Container-level isolation** prevents sandbox escape

### 5. AgentCore Memory — Safe Context (ASI06, Cross-User Bleed, Vector Risks)

Memory is segmented and validated:
- **Namespace isolation** per user, session, and agent
- **Provenance tracking** on all memory writes
- **Trust scoring** to decay unverified entries
- **Event memory** for audit trail of all interactions

### 6. AgentCore Code Interpreter — Sandboxed Execution (ASI05, Unsafe SQL)

Code runs in hardened sandboxes:
- **No network access** by default
- **Resource limits** (CPU, memory, time)
- **No persistent state** between executions
- **Output validation** before returning results

### 7. AgentCore Observability — Detection & Audit (ASI09, ASI10, Telemetry Leakage)

Full tracing with security focus:
- **Tamper-evident logs** of all agent actions
- **Anomaly detection** for behavioral drift
- **PII redaction** in telemetry data
- **Confidence scoring** exposed to end users

## Security Testing

Run the attack simulation tests:

```bash
source .venv/bin/activate
pytest tests/ -v
```

These tests validate that (52 tests, 3 skipped without SDK):
- Prompt injection attempts are detected and blocked
- Structural boundaries prevent tag escape and invisible char injection
- Tool access is denied when policy violations occur
- SQL injection in tool parameters is blocked
- Memory poisoning attempts are rejected
- Sensitive data (SSN, credit cards, emails, API keys) is redacted from outputs
- Trust scores decay over time for unverified memory entries

## Documentation

- [Data Flow Diagram](docs/data-flow-diagram.md) — Full walkthrough of request flow, attack scenarios, and 8-layer defense model

## References

- [OWASP Top 10 for Agentic Applications 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Data Security Risks and Mitigations 2026 v1.0](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Amazon Bedrock AgentCore Documentation](https://docs.aws.amazon.com/bedrock-agentcore/)
