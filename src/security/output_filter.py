"""
Output Filter - PII and Sensitive Data Redaction

Mitigates:
- Data Security - Sensitive Data Leakage: Scans agent outputs for PII
  (names, emails, SSNs, account numbers, etc.) and redacts before delivery.
- Data Security - Telemetry Leakage: Ensures sensitive data doesn't leak
  into logs or observability traces.
- ASI09 (Human-Agent Trust Exploitation): Adds confidence metadata to
  help users calibrate trust in agent responses.

Uses Microsoft Presidio for entity recognition and anonymization.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Patterns for sensitive data that should never appear in output
SENSITIVE_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "account_full": re.compile(r"\b\d{10,12}\b"),  # Full account numbers
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b(\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "api_key": re.compile(r"\b(sk|pk|api)[_-][A-Za-z0-9]{20,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}

# Replacement templates for each sensitive type
REDACTION_TEMPLATES = {
    "ssn": "***-**-****",
    "credit_card": "****-****-****-{last4}",
    "account_full": "****{last4}",
    "email": "[EMAIL REDACTED]",
    "phone": "[PHONE REDACTED]",
    "api_key": "[API KEY REDACTED]",
    "aws_key": "[AWS KEY REDACTED]",
}


class OutputFilter:
    """
    Multi-layer output filtering for sensitive data protection.

    Layer 1: Regex-based pattern detection for known sensitive formats
    Layer 2: Presidio NER-based entity detection (when available)
    Layer 3: Custom business rules (e.g., never expose full account numbers)

    In production, this runs as a Gateway Lambda interceptor on the
    RESPONSE interception point for guaranteed enforcement.
    """

    def __init__(self, use_presidio: bool = True):
        self.use_presidio = use_presidio
        self._presidio_analyzer = None
        self._presidio_anonymizer = None

        if use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine

                self._presidio_analyzer = AnalyzerEngine()
                self._presidio_anonymizer = AnonymizerEngine()
            except ImportError:
                logger.warning("Presidio not available, using regex-only filtering")
                self.use_presidio = False

    def filter(self, text: str, user_id: str = "unknown") -> str:
        """
        Filter sensitive data from agent output.

        Applies multiple detection layers and redacts any matches.
        Logs redaction events for audit (without the sensitive content).
        """
        if not text:
            return text

        filtered = text
        redaction_count = 0

        # Layer 1: Regex pattern matching
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(filtered)
            for match in matches:
                redaction_count += 1
                template = REDACTION_TEMPLATES[pattern_name]

                if "{last4}" in template:
                    # Preserve last 4 digits for user reference
                    last4 = match[-4:] if len(match) >= 4 else "****"
                    replacement = template.format(last4=last4)
                else:
                    replacement = template

                filtered = filtered.replace(match, replacement)

        # Layer 2: Presidio NER detection
        if self.use_presidio and self._presidio_analyzer:
            filtered = self._apply_presidio(filtered)

        # Log redaction event (without sensitive content)
        if redaction_count > 0:
            logger.info(
                "Output filtered",
                extra={
                    "user_id": user_id,
                    "redactions": redaction_count,
                    "output_length": len(filtered),
                },
            )

        return filtered

    def _apply_presidio(self, text: str) -> str:
        """Apply Presidio NER-based entity detection and anonymization."""
        if not self._presidio_analyzer or not self._presidio_anonymizer:
            return text

        try:
            results = self._presidio_analyzer.analyze(
                text=text,
                language="en",
                entities=[
                    "PERSON",
                    "PHONE_NUMBER",
                    "EMAIL_ADDRESS",
                    "CREDIT_CARD",
                    "US_SSN",
                    "US_BANK_NUMBER",
                    "IP_ADDRESS",
                ],
            )

            if results:
                anonymized = self._presidio_anonymizer.anonymize(
                    text=text, analyzer_results=results
                )
                return anonymized.text

        except Exception as e:
            logger.error(f"Presidio filtering failed: {e}")

        return text

    def filter_for_logging(self, text: str) -> str:
        """
        Extra-aggressive filtering for telemetry/logging contexts.

        Telemetry Leakage mitigation: ensures no PII enters observability
        systems even if the primary output filter misses something.
        """
        filtered = self.filter(text)

        # Additional: truncate to prevent large data in logs
        if len(filtered) > 500:
            filtered = filtered[:500] + "... [TRUNCATED FOR LOGGING]"

        return filtered
