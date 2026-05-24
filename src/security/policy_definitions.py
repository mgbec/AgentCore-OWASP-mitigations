"""
Policy Definitions - Cedar Policy Templates for AgentCore Policy Engine

Mitigates:
- ASI01 (Agent Goal Hijack): Policies restrict which actions agents can take
- ASI02 (Tool Misuse): Fine-grained tool-level access control
- ASI08 (Cascading Failures): Blast-radius caps via policy constraints
- ASI10 (Rogue Agents): Behavioral constraints enforced at policy layer
- Data Security - Governance & Compliance: Auditable policy enforcement

These Cedar policies are deployed to the AgentCore Policy Engine and
enforced at the Gateway level before any tool invocation reaches an agent.
"""

# Cedar policy: Restrict triage agent to classification only (ASI01, ASI02)
TRIAGE_AGENT_POLICY = """
permit(
    principal == AgentCore::Agent::"triage-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "classify_intent"
};

forbid(
    principal == AgentCore::Agent::"triage-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in ["transfer_funds", "check_balance", "get_transactions"]
} unless {
    false
};
"""

# Cedar policy: Finance agent tool restrictions (ASI02, ASI08)
FINANCE_AGENT_POLICY = """
permit(
    principal == AgentCore::Agent::"finance-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in ["check_balance", "get_transactions", "transfer_funds"]
};

forbid(
    principal == AgentCore::Agent::"finance-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "transfer_funds" &&
    resource.parameters.amount > 10000
};

forbid(
    principal == AgentCore::Agent::"finance-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in ["search_documents", "store_interaction", "execute_code"]
};
"""

# Cedar policy: Knowledge agent memory access (ASI06)
KNOWLEDGE_AGENT_POLICY = """
permit(
    principal == AgentCore::Agent::"knowledge-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in ["search_documents", "store_interaction"]
};

permit(
    principal == AgentCore::Agent::"knowledge-agent-identity",
    action == AgentCore::Action::"ReadMemory",
    resource
) when {
    resource.namespace == context.user_id
};

forbid(
    principal == AgentCore::Agent::"knowledge-agent-identity",
    action == AgentCore::Action::"ReadMemory",
    resource
) when {
    resource.namespace != context.user_id
};
"""

# Cedar policy: Rate limiting / blast-radius cap (ASI08)
RATE_LIMIT_POLICY = """
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    context.session_tool_invocations > 50
};

forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "transfer_funds" &&
    context.session_transfer_count > 5
};
"""

# Cedar policy: Behavioral constraints for rogue agent detection (ASI10)
BEHAVIORAL_POLICY = """
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "transfer_funds" &&
    context.time_since_last_human_approval > 300
};

forbid(
    principal,
    action == AgentCore::Action::"WriteMemory",
    resource
) when {
    resource.content_trust_score < 0.3
};
"""

ALL_POLICIES = {
    "triage_agent_access": TRIAGE_AGENT_POLICY,
    "finance_agent_access": FINANCE_AGENT_POLICY,
    "knowledge_agent_access": KNOWLEDGE_AGENT_POLICY,
    "rate_limiting": RATE_LIMIT_POLICY,
    "behavioral_constraints": BEHAVIORAL_POLICY,
}
