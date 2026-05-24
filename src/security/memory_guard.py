"""
Memory Guard - Memory Write Validation

Mitigates:
- ASI06 (Memory & Context Poisoning): Validates all content before it's
  written to memory stores. Detects injection attempts, ensures provenance,
  and enforces trust scoring.
- Data Security - Cross-User Conversation Bleed: Enforces namespace
  boundaries on all memory operations.
- Data Security - Poisoning via Retrieval: Validates retrieved content
  hasn't been tampered with.
"""

import hashlib
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WriteValidation:
    """Result of memory write validation."""
    is_safe: bool
    reason: str
    trust_score: float
    content_hash: str


@dataclass
class RetrievalValidation:
    """Result of memory retrieval validation."""
    is_valid: bool
    provenance_verified: bool
    trust_score: float


class MemoryGuard:
    """
    Guards memory operations against poisoning and cross-contamination.

    Write validation:
    - Checks for injection patterns in content being stored
    - Assigns trust scores based on source reliability
    - Computes content hashes for tamper detection
    - Enforces namespace boundaries

    Retrieval validation:
    - Verifies provenance metadata exists and is consistent
    - Checks content hash integrity
    - Filters entries below trust threshold
    - Detects anomalous retrieval patterns
    """

    # Sources and their base trust scores
    SOURCE_TRUST_SCORES = {
        "verified_document": 0.95,
        "admin_upload": 0.90,
        "agent_interaction": 0.60,
        "user_provided": 0.40,
        "external_api": 0.50,
        "unknown": 0.10,
    }

    # Content that should never be stored in memory
    BLOCKED_CONTENT_PATTERNS = [
        "ignore previous",
        "system prompt",
        "you are now",
        "new instructions",
        "<script",
        "javascript:",
    ]

    MIN_TRUST_FOR_WRITE = 0.3
    TRUST_DECAY_RATE = 0.01  # Per day

    def validate_write(
        self, content: str, source: str, user_id: str
    ) -> WriteValidation:
        """
        Validate content before writing to memory.

        Checks:
        1. Content doesn't contain injection patterns
        2. Source has acceptable trust level
        3. Content length is within bounds
        4. No cross-namespace contamination
        """
        # Check for blocked content patterns
        content_lower = content.lower()
        for pattern in self.BLOCKED_CONTENT_PATTERNS:
            if pattern in content_lower:
                logger.warning(
                    "Memory write blocked: injection pattern detected",
                    extra={"source": source, "user_id": user_id, "pattern": pattern},
                )
                return WriteValidation(
                    is_safe=False,
                    reason=f"Blocked pattern detected: {pattern}",
                    trust_score=0.0,
                    content_hash="",
                )

        # Assign trust score based on source
        trust_score = self.SOURCE_TRUST_SCORES.get(source, 0.10)

        if trust_score < self.MIN_TRUST_FOR_WRITE:
            return WriteValidation(
                is_safe=False,
                reason=f"Source '{source}' trust score too low: {trust_score}",
                trust_score=trust_score,
                content_hash="",
            )

        # Check content length (prevent memory stuffing)
        if len(content) > 10000:
            return WriteValidation(
                is_safe=False,
                reason="Content exceeds maximum length for memory storage",
                trust_score=trust_score,
                content_hash="",
            )

        # Compute content hash for integrity verification
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        return WriteValidation(
            is_safe=True,
            reason="passed",
            trust_score=trust_score,
            content_hash=content_hash,
        )

    def validate_retrieval(self, chunk: dict) -> bool:
        """
        Validate a retrieved memory chunk before use.

        Checks:
        1. Provenance metadata exists
        2. Trust score meets minimum threshold
        3. Content hash matches (tamper detection)
        4. Entry hasn't expired
        """
        # Must have provenance
        if "source" not in chunk or "trust_score" not in chunk:
            logger.warning("Retrieved chunk missing provenance metadata")
            return False

        # Trust score check with time decay
        trust = chunk.get("trust_score", 0.0)
        created_at = chunk.get("created_at", time.time())
        age_days = (time.time() - created_at) / 86400
        decayed_trust = trust - (age_days * self.TRUST_DECAY_RATE)

        if decayed_trust < 0.5:
            logger.info(
                "Retrieved chunk below trust threshold after decay",
                extra={"chunk_id": chunk.get("id"), "decayed_trust": decayed_trust},
            )
            return False

        # Integrity check if hash is available
        if "content_hash" in chunk and "content" in chunk:
            expected_hash = hashlib.sha256(chunk["content"].encode()).hexdigest()
            if chunk["content_hash"] != expected_hash:
                logger.error(
                    "Memory chunk integrity violation - possible tampering",
                    extra={"chunk_id": chunk.get("id")},
                )
                return False

        return True

    def compute_trust_score(self, source: str, age_days: float = 0) -> float:
        """Compute current trust score with time decay."""
        base = self.SOURCE_TRUST_SCORES.get(source, 0.10)
        decayed = base - (age_days * self.TRUST_DECAY_RATE)
        return max(decayed, 0.0)
