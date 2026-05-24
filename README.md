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
| **ASI01** | Agent Goal Hijack | Gateway Cedar policies restrict allowed actions; input validation via interceptors |
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
├── requirements.txt
├── agentcore.json                    # AgentCore deployment config
├── src/
│   ├── agents/
│   │   ├── triage_agent.py          # Orchestrator with goal validation
│   │   ├── finance_agent.py         # Executor with tool constraints
│   │   └── knowledge_agent.py       # RAG agent with memory isolation
│   ├── tools/
│   │   ├── financial_tools.py       # Scoped financial operations
│   │   └── data_retrieval_tools.py  # Document retrieval with DLP
│   ├── security/
│   │   ├── input_validator.py       # Prompt injection detection
│   │   ├── output_filter.py         # PII/sensitive data redaction
│   │   ├── policy_definitions.py    # Cedar policy templates
│   │   └── memory_guard.py          # Memory write validation
│   ├── observability/
│   │   └── tracing.py               # OpenTelemetry instrumentation
│   └── main.py                      # Entry point
├── policies/
│   ├── tool_access.cedar            # Tool-level access control
│   ├── data_scope.cedar             # Data boundary enforcement
│   └── agent_behavior.cedar         # Behavioral constraints
├── infrastructure/
│   ├── deploy.sh                    # Deployment script
│   └── iam_roles.json               # Least-privilege IAM policies
└── tests/
    ├── test_goal_hijack.py          # ASI01 attack simulation
    ├── test_tool_misuse.py          # ASI02 attack simulation
    ├── test_memory_poisoning.py     # ASI06 attack simulation
    └── test_data_leakage.py         # Data security validation
```

## Getting Started

### Prerequisites

- Python 3.13+
- AWS CLI configured with appropriate permissions
- AgentCore CLI (`pip install bedrock-agentcore-sdk`)

### Installation

```bash
cd agentcore-owasp-mitigations
pip install -r requirements.txt
```

### Local Development

```bash
python src/main.py
```

### Deploy to AgentCore

```bash
bash infrastructure/deploy.sh
```

## How Each Component Demonstrates Mitigations

### 1. AgentCore Gateway — Controlled Entry Point (ASI01, ASI02, ASI04, Data Leakage)

The Gateway acts as the single entry point for all agent interactions:
- **CUSTOM_JWT authorization** prevents unauthorized access
- **Cedar policy engine** enforces fine-grained tool-level permissions
- **Lambda interceptors** scan inputs/outputs for prompt injection and PII
- **Semantic search** scopes tool discovery to prevent tool confusion attacks
- **Target pinning** ensures only attested MCP servers are reachable

### 2. AgentCore Identity — Scoped Credentials (ASI03, Credential Exposure)

Each agent gets a unique workload identity:
- **Short-lived tokens** prevent credential reuse across sessions
- **Token vault with KMS** encrypts secrets at rest
- **OAuth2 providers** enable secure third-party integrations
- **Resource policies** restrict which identities can invoke which runtimes

### 3. AgentCore Runtime — Isolated Execution (ASI05, ASI08, ASI10)

Agents run in isolated MicroVMs:
- **Session isolation** prevents cross-agent contamination
- **Idle timeouts** automatically terminate runaway agents
- **VPC mode** restricts network egress to prevent data exfiltration
- **Container-level isolation** prevents sandbox escape

### 4. AgentCore Memory — Safe Context (ASI06, Cross-User Bleed, Vector Risks)

Memory is segmented and validated:
- **Namespace isolation** per user, session, and agent
- **Provenance tracking** on all memory writes
- **Trust scoring** to decay unverified entries
- **Event memory** for audit trail of all interactions

### 5. AgentCore Code Interpreter — Sandboxed Execution (ASI05, Unsafe SQL)

Code runs in hardened sandboxes:
- **No network access** by default
- **Resource limits** (CPU, memory, time)
- **No persistent state** between executions
- **Output validation** before returning results

### 6. AgentCore Observability — Detection & Audit (ASI09, ASI10, Telemetry Leakage)

Full tracing with security focus:
- **Tamper-evident logs** of all agent actions
- **Anomaly detection** for behavioral drift
- **PII redaction** in telemetry data
- **Confidence scoring** exposed to end users

## Security Testing

Run the attack simulation tests:

```bash
pytest tests/ -v
```

These tests validate that:
- Prompt injection attempts are blocked at the Gateway
- Tool access is denied when policy violations occur
- Memory poisoning attempts are rejected
- Sensitive data is redacted from outputs
- Rogue agent behavior triggers containment

## References

- [OWASP Top 10 for Agentic Applications 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Data Security Risks and Mitigations 2026 v1.0](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Amazon Bedrock AgentCore Documentation](https://docs.aws.amazon.com/bedrock-agentcore/)
