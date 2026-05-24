// Agent Behavioral Constraints Policy
// Mitigates: ASI08 (Cascading Failures), ASI10 (Rogue Agents)
//
// Enforces operational boundaries that prevent agents from exceeding
// their intended scope, even if compromised or misaligned.

// Rate limiting: max 50 tool invocations per session
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    context.session_tool_invocations > 50
};

// Transfer frequency cap: max 5 transfers per session
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "transfer_funds" &&
    context.session_transfer_count > 5
};

// Require recent human approval for high-value operations
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName == "transfer_funds" &&
    resource.parameters.amount > 5000 &&
    context.time_since_last_human_approval > 300
};

// Prevent agents from modifying their own policies
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    resource.toolName in [
        "update_policy",
        "modify_permissions",
        "change_identity",
        "escalate_privileges"
    ]
};

// Circuit breaker: block all actions if error rate is high
forbid(
    principal,
    action == AgentCore::Action::"InvokeTool",
    resource
) when {
    context.session_error_count > 10
};
