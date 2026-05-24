"""
Input Validator - Prompt Injection Detection

Mitigates:
- ASI01 (Agent Goal Hijack): Detects and blocks prompt injection attempts
  that try to override agent instructions or redirect goals.
- Data Security - Poisoning & Tampering: Prevents malicious content from
  entering the processing pipeline.

Detection approach uses pattern matching and heuristic scoring.
In production, this would be augmented with a trained classifier.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction override attempts
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
    r"disregard\s+(your|all|the)\s+(instructions|rules|guidelines)",
    r"forget\s+(everything|all|your)\s+(you|instructions|rules)",
    r"you\s+are\s+now\s+a",
    r"new\s+instructions?\s*:",
    r"system\s*prompt\s*:",
    # Role manipulation
    r"pretend\s+(you\s+are|to\s+be)",
    r"act\s+as\s+(if|though|a)",
    r"your\s+new\s+role\s+is",
    # Data exfiltration attempts
    r"(reveal|show|display|output)\s+(your|the|all)\s+(system|instructions|prompt|rules)",
    r"what\s+are\s+your\s+(instructions|rules|system\s+prompt)",
    # Delimiter injection
    r"```\s*system",
    r"\[SYSTEM\]",
    r"<\|im_start\|>system",
    # Goal redirection
    r"instead\s+of\s+(that|your\s+task)",
    r"your\s+(real|actual|true)\s+(task|goal|purpose)\s+is",
]

# Suspicious content that raises risk score but doesn't auto-block
SUSPICIOUS_PATTERNS = [
    r"base64",
    r"eval\s*\(",
    r"exec\s*\(",
    r"import\s+os",
    r"subprocess",
    r"__[a-z]+__",
    r"\\x[0-9a-f]{2}",
]


@dataclass
class ValidationResult:
    """Result of input validation check."""
    is_safe: bool
    risk_score: float  # 0.0 (safe) to 1.0 (definitely malicious)
    matched_patterns: list[str]
    reason: str


class InputValidator:
    """
    Multi-layer input validation for prompt injection detection.

    Layer 1: Pattern matching against known injection signatures
    Layer 2: Heuristic scoring based on suspicious content
    Layer 3: Length and structure anomaly detection

    In production, add:
    - ML-based classifier trained on injection examples
    - Gateway Lambda interceptor for pre-processing
    - Rate limiting on high-risk-score inputs
    """

    BLOCK_THRESHOLD = 0.7   # Auto-block above this score
    MAX_INPUT_LENGTH = 4000  # Prevent context stuffing attacks

    def __init__(self):
        self._injection_patterns = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
        self._suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]

    def validate(self, text: str) -> ValidationResult:
        """
        Validate input text for prompt injection attempts.

        Returns a ValidationResult with safety determination and risk score.
        """
        if not text or not text.strip():
            return ValidationResult(is_safe=True, risk_score=0.0, matched_patterns=[], reason="empty")

        risk_score = 0.0
        matched = []

        # Layer 1: Known injection patterns (high confidence)
        for pattern in self._injection_patterns:
            if pattern.search(text):
                risk_score += 0.4
                matched.append(pattern.pattern)

        # Layer 2: Suspicious content (medium confidence)
        for pattern in self._suspicious_patterns:
            if pattern.search(text):
                risk_score += 0.15
                matched.append(f"suspicious:{pattern.pattern}")

        # Layer 3: Structural anomalies
        if len(text) > self.MAX_INPUT_LENGTH:
            risk_score += 0.2
            matched.append("excessive_length")

        # Multiple newlines with different instruction styles suggest injection
        if text.count("\n") > 10 and any(p.search(text) for p in self._injection_patterns[:3]):
            risk_score += 0.2
            matched.append("structured_injection")

        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        is_safe = risk_score < self.BLOCK_THRESHOLD

        if not is_safe:
            logger.warning(
                "Input blocked by validator",
                extra={"risk_score": risk_score, "patterns": matched[:3]},
            )

        reason = "safe" if is_safe else f"injection_detected (score: {risk_score:.2f})"

        return ValidationResult(
            is_safe=is_safe,
            risk_score=risk_score,
            matched_patterns=matched,
            reason=reason,
        )
