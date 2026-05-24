"""
Gateway Lambda Interceptor - Input Validation (ASI01 mitigation)

This Lambda runs on every REQUEST to the AgentCore Gateway.
It scans user input for prompt injection patterns and blocks
malicious requests before they reach any agent.

Deployed as a Gateway interceptor at the REQUEST interception point.
"""

import json
import logging
import os
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BLOCK_THRESHOLD = float(os.environ.get("BLOCK_THRESHOLD", "0.7"))

# Prompt injection detection patterns
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)", re.I),
    re.compile(r"disregard\s+(your|all|the)\s+(instructions|rules|guidelines)", re.I),
    re.compile(r"forget\s+(everything|all|your)\s+(you|instructions|rules)", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"system\s*prompt\s*:", re.I),
    re.compile(r"pretend\s+(you\s+are|to\s+be)", re.I),
    re.compile(r"your\s+new\s+role\s+is", re.I),
    re.compile(r"(reveal|show|display|output)\s+(your|the|all)\s+(system|instructions|prompt)", re.I),
    re.compile(r"```\s*system", re.I),
    re.compile(r"\[SYSTEM\]", re.I),
    re.compile(r"instead\s+of\s+(that|your\s+task)", re.I),
    re.compile(r"your\s+(real|actual|true)\s+(task|goal|purpose)\s+is", re.I),
]

SUSPICIOUS_PATTERNS = [
    re.compile(r"base64", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"exec\s*\(", re.I),
    re.compile(r"import\s+os", re.I),
    re.compile(r"subprocess", re.I),
]


def lambda_handler(event, context):
    """
    Gateway REQUEST interceptor.

    Receives the request payload, scans for injection, and returns
    either the original request (pass-through) or a blocked response.
    """
    logger.info("Input validator invoked")

    try:
        # Extract the user message from the gateway request
        body = event.get("body", {})
        if isinstance(body, str):
            body = json.loads(body)

        user_input = _extract_user_input(body)

        if not user_input:
            # No user input to validate - pass through
            return {"statusCode": 200, "body": json.dumps(event)}

        # Calculate risk score
        risk_score = _calculate_risk_score(user_input)

        if risk_score >= BLOCK_THRESHOLD:
            logger.warning(
                "Prompt injection blocked",
                extra={"risk_score": risk_score},
            )
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "Request blocked by security policy",
                    "reason": "potential_prompt_injection",
                    "risk_score": risk_score,
                }),
            }

        # Pass through - request is safe
        return {"statusCode": 200, "body": json.dumps(event)}

    except Exception as e:
        logger.error(f"Input validator error: {e}")
        # Fail open in case of validator error (configurable)
        return {"statusCode": 200, "body": json.dumps(event)}


def _extract_user_input(body):
    """Extract user message from various request formats."""
    # MCP tool call format
    if "params" in body and "arguments" in body.get("params", {}):
        args = body["params"]["arguments"]
        return json.dumps(args) if isinstance(args, dict) else str(args)

    # Direct prompt format
    if "prompt" in body:
        return body["prompt"]

    # Message format
    if "message" in body:
        return body["message"]

    return None


def _calculate_risk_score(text):
    """Calculate injection risk score for input text."""
    score = 0.0

    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            score += 0.4

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            score += 0.15

    if len(text) > 4000:
        score += 0.2

    return min(score, 1.0)
