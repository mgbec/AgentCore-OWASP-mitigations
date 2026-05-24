// Tool Access Control Policy
// Mitigates: ASI02 (Tool Misuse), ASI03 (Privilege Abuse)
//
// Enforces least-privilege tool access per agent identity.
// Deployed to AgentCore Policy Engine and enforced at Gateway.

// Triage agent: classification only, no execution tools
permit(
    principal == AgentCore::Agent::"triage-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "classify_intent"
};

// Finance agent: financial tools only
permit(
    principal == AgentCore::Agent::"finance-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in [
        "check_balance",
        "get_transactions",
        "transfer_funds",
        "calculate_interest"
    ]
};

// Knowledge agent: retrieval and storage only
permit(
    principal == AgentCore::Agent::"knowledge-agent-identity",
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in [
        "search_documents",
        "store_interaction"
    ]
};

// Default deny: any tool not explicitly permitted is blocked
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) unless {
    // Only the permits above grant access
    false
};
