// Data Scope Policy
// Mitigates: ASI06 (Memory Poisoning), Cross-User Bleed, Over-Broad Context
//
// Enforces data boundaries so agents can only access data belonging
// to the authenticated user's namespace.

// Memory reads: only within user's namespace
permit(
    principal,
    action == AgentCore::Action::"ReadMemory",
    resource
) when {
    resource.namespace == context.user_id
};

// Memory writes: only to user's namespace with trust validation
permit(
    principal,
    action == AgentCore::Action::"WriteMemory",
    resource
) when {
    resource.namespace == context.user_id &&
    resource.content_trust_score >= 0.3
};

// Block cross-namespace memory access
forbid(
    principal,
    action in [AgentCore::Action::"ReadMemory", AgentCore::Action::"WriteMemory"],
    resource
) when {
    resource.namespace != context.user_id
};

// Block low-trust writes (poisoning prevention)
forbid(
    principal,
    action == AgentCore::Action::"WriteMemory",
    resource
) when {
    resource.content_trust_score < 0.3
};

// Limit context retrieval breadth
forbid(
    principal,
    action == AgentCore::Action::"ReadMemory",
    resource
) when {
    context.retrieval_count > 10
};
