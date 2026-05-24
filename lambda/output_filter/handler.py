"""
Gateway Lambda Interceptor - Output Filtering (Data Leakage mitigation)

This Lambda runs on every RESPONSE from the AgentCore Gateway.
It scans agent output for PII and sensitive data, redacting
anything that shouldn't be exposed to the end user.

Deployed as a Gateway interceptor at the RESPONSE interception point.
"""

import json
import logging
import os
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Sensitive data patterns
PATTERNS = {
    "ssn": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "***-**-****"),
    "credit_card": (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "****-****-****-XXXX"),
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL REDACTED]"),
    "phone": (re.compile(r"\b(\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), "[PHONE REDACTED]"),
    "api_key": (re.compile(r"\b(sk|pk|api)[_-][A-Za-z0-9]{20,}\b"), "[API KEY REDACTED]"),
    "aws_key": (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS KEY REDACTED]"),
    "account_number": (re.compile(r"\b\d{10,12}\b"), "****XXXX"),
}


def lambda_handler(event, context):
    """
    Gateway RESPONSE interceptor.

    Scans the response body for sensitive data patterns and redacts matches.
    """
    logger.info("Output filter invoked")

    try:
        body = event.get("body", {})
        if isinstance(body, str):
            body = json.loads(body)

        # Recursively filter all string values in the response
        filtered_body = _filter_recursive(body)

        return {
            "statusCode": 200,
            "body": json.dumps(filtered_body),
        }

    except Exception as e:
        logger.error(f"Output filter error: {e}")
        # On error, return original (don't block responses)
        return {"statusCode": 200, "body": json.dumps(event.get("body", {}))}


def _filter_recursive(obj):
    """Recursively filter sensitive data from all string values."""
    if isinstance(obj, str):
        return _redact_sensitive(obj)
    elif isinstance(obj, dict):
        return {k: _filter_recursive(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_filter_recursive(item) for item in obj]
    return obj


def _redact_sensitive(text):
    """Apply all redaction patterns to a string."""
    redaction_count = 0

    for name, (pattern, replacement) in PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            redaction_count += 1
            if "XXXX" in replacement and len(match) >= 4:
                # Preserve last 4 chars for reference
                replacement_final = replacement.replace("XXXX", match[-4:])
            else:
                replacement_final = replacement
            text = text.replace(match, replacement_final)

    if redaction_count > 0:
        logger.info(f"Redacted {redaction_count} sensitive items from response")

    return text
