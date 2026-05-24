"""
AgentCore OWASP Risk Mitigation Demo - Entry Point

Secure Financial Assistant demonstrating mitigations for:
- OWASP Top 10 for Agentic Applications (2026)
- OWASP GenAI Data Security Risks and Mitigations (2026)

This agent system uses AgentCore Runtime, Identity, Memory, Gateway,
Code Interpreter, and Observability to implement defense-in-depth.
"""

import json
import logging
from typing import Any

try:
    from bedrock_agentcore_sdk import AgentCoreApp
except ImportError:
    AgentCoreApp = None

from agents.triage_agent import TriageAgent
from agents.finance_agent import FinanceAgent
from agents.knowledge_agent import KnowledgeAgent
from observability.tracing import setup_observability
from security.input_validator import InputValidator
from security.output_filter import OutputFilter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the AgentCore application
app = AgentCoreApp()

# Setup observability (ASI09, ASI10 mitigation - audit trails & anomaly detection)
tracer = setup_observability()

# Initialize security components
input_validator = InputValidator()   # ASI01 mitigation - goal hijack prevention
output_filter = OutputFilter()       # Data leakage mitigation - PII redaction


@app.handler
async def handle_request(request: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
    """
    Main request handler demonstrating defense-in-depth:

    1. Input validation (ASI01 - Goal Hijack prevention)
    2. Identity verification (ASI03 - Privilege Abuse prevention)
    3. Agent routing with isolation (ASI08 - Cascading Failure prevention)
    4. Output filtering (Data Leakage prevention)
    5. Audit logging (ASI09, ASI10 - Trust Exploitation & Rogue Agent detection)
    """
    with tracer.start_as_current_span("handle_request") as span:
        user_message = request.get("prompt", "")
        user_id = session.get("user_id", "anonymous")
        session_id = session.get("session_id", "unknown")

        span.set_attribute("user.id", user_id)
        span.set_attribute("session.id", session_id)

        # --- MITIGATION: ASI01 - Agent Goal Hijack ---
        # Validate input for prompt injection attempts before processing
        validation_result = input_validator.validate(user_message)
        if not validation_result.is_safe:
            logger.warning(
                "Prompt injection detected",
                extra={"user_id": user_id, "risk_score": validation_result.risk_score},
            )
            span.set_attribute("security.blocked", True)
            span.set_attribute("security.reason", "prompt_injection_detected")
            return {
                "response": "I cannot process this request as it contains potentially unsafe content.",
                "blocked": True,
                "risk_category": "ASI01",
            }

        # --- MITIGATION: ASI03 - Identity & Privilege Abuse ---
        # Each agent operates with its own scoped identity
        # The triage agent determines routing but cannot execute financial operations
        triage = TriageAgent(user_id=user_id, session_id=session_id)
        routing_decision = await triage.classify(user_message)

        span.set_attribute("routing.decision", routing_decision.agent_target)
        span.set_attribute("routing.confidence", routing_decision.confidence)

        # --- MITIGATION: ASI08 - Cascading Failures ---
        # Each agent runs in isolation with timeout and error boundaries
        try:
            if routing_decision.agent_target == "finance":
                agent = FinanceAgent(user_id=user_id, session_id=session_id)
            elif routing_decision.agent_target == "knowledge":
                agent = KnowledgeAgent(user_id=user_id, session_id=session_id)
            else:
                return {"response": "I can help with financial questions and document lookups."}

            result = await agent.execute(user_message, timeout_seconds=30)

        except TimeoutError:
            logger.error("Agent execution timed out", extra={"agent": routing_decision.agent_target})
            span.set_attribute("error.type", "timeout")
            return {"response": "The request took too long. Please try again.", "error": "timeout"}
        except Exception as e:
            logger.error(f"Agent execution failed: {e}", extra={"agent": routing_decision.agent_target})
            span.set_attribute("error.type", type(e).__name__)
            return {"response": "An error occurred processing your request.", "error": str(e)}

        # --- MITIGATION: Data Leakage Prevention ---
        # Filter PII and sensitive data from output before returning
        filtered_response = output_filter.filter(result.response, user_id=user_id)

        # --- MITIGATION: ASI09 - Human-Agent Trust Exploitation ---
        # Include confidence metadata so users can calibrate trust
        return {
            "response": filtered_response,
            "confidence": result.confidence,
            "sources": result.sources,
            "agent": routing_decision.agent_target,
            "audit_id": span.get_span_context().trace_id,
        }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)  # nosec B104 - required for container runtime
