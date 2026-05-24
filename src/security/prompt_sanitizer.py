"""
Prompt Sanitizer - Structural Separation for Prompt Injection Prevention

Mitigates:
- ASI01 (Agent Goal Hijack): Wraps user input in explicit data boundaries
  so models treat it as DATA, not as INSTRUCTIONS. Even if injection text
  gets through detection, it cannot escape its structural container.

This is the architectural complement to the InputValidator (which detects
and blocks). The sanitizer assumes all input could be malicious and
structurally contains it.
"""

import re
import unicodedata
import logging

logger = logging.getLogger(__name__)

# Characters/sequences that could break structural boundaries
BOUNDARY_ESCAPE_PATTERNS = [
    ("</user_request>", ""),       # Close tag escape
    ("</user_data>", ""),          # Alternative close tag
    ("<user_request>", ""),        # Nested open tag
    ("[SYSTEM]", "[system]"),      # System marker
    ("[INST]", "[inst]"),          # Instruction marker
    ("<|im_start|>", ""),          # ChatML start
    ("<|im_end|>", ""),            # ChatML end
    ("<|system|>", ""),            # System role marker
    ("<|user|>", ""),              # User role marker
    ("<|assistant|>", ""),         # Assistant role marker
]

# Max length to prevent context stuffing
MAX_INPUT_LENGTH = 4000


class PromptSanitizer:
    """
    Sanitizes and structurally wraps user input for safe consumption by agents.

    Two responsibilities:
    1. Sanitize: Remove/escape characters that could break structural boundaries
    2. Wrap: Place the sanitized input inside explicit data tags with metadata

    The resulting wrapped message is safe to pass to any agent because:
    - The agent's system prompt declares <user_request> content as untrusted data
    - Boundary-breaking sequences are neutralized
    - Invisible characters that could hide instructions are removed
    - Length is bounded to prevent context stuffing
    """

    def sanitize(self, text: str) -> str:
        """
        Sanitize user input by removing/escaping dangerous sequences.

        This does NOT wrap the text — call wrap() for the full structural
        separation. Use sanitize() alone when you need clean text without
        the XML boundary tags.
        """
        if not text:
            return text

        # Step 1: Remove invisible/control characters
        text = self._remove_invisible_chars(text)

        # Step 2: Escape boundary-breaking sequences
        text = self._escape_boundaries(text)

        # Step 3: Normalize whitespace (collapse structural injection attempts)
        text = self._normalize_whitespace(text)

        # Step 4: Truncate to prevent context stuffing
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]
            logger.info("Input truncated to max length", extra={"max": MAX_INPUT_LENGTH})

        return text

    def wrap(self, text: str, intent: str = "", confidence: float = 0.0) -> str:
        """
        Sanitize and wrap user input in structural data boundaries.

        The returned string is safe to embed in an agent prompt. The agent's
        system prompt should instruct it to treat <user_request> content as
        untrusted data to extract parameters from, not instructions to follow.

        Args:
            text: Raw user input
            intent: Pre-classified intent from triage (e.g., "check_balance")
            confidence: Triage confidence score (0.0-1.0)

        Returns:
            Structurally wrapped string with metadata
        """
        sanitized = self.sanitize(text)

        # Build the wrapped payload with metadata the agent can use
        # for context without treating the user text as instructions
        wrapped = f"""<request_metadata>
intent: {intent}
confidence: {confidence:.2f}
trust_level: untrusted
</request_metadata>

<user_request>
{sanitized}
</user_request>"""

        return wrapped

    def _remove_invisible_chars(self, text: str) -> str:
        """
        Remove zero-width spaces, RTL overrides, and other invisible characters
        that could hide injected instructions from human review.
        """
        cleaned = []
        for char in text:
            category = unicodedata.category(char)
            # Keep: letters, numbers, punctuation, symbols, standard whitespace
            # Remove: control chars (Cc), format chars (Cf), surrogates, private use
            if category[0] in ('L', 'N', 'P', 'S', 'Z'):
                cleaned.append(char)
            elif char in ('\n', '\t', ' '):
                cleaned.append(char)
            # else: drop the character (invisible/control)

        return ''.join(cleaned)

    def _escape_boundaries(self, text: str) -> str:
        """
        Remove or neutralize sequences that could break out of the
        <user_request> structural boundary.
        """
        for pattern, replacement in BOUNDARY_ESCAPE_PATTERNS:
            text = text.replace(pattern, replacement)

        # Also handle case-insensitive variants
        text = re.sub(r'</?user_request>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'</?user_data>', '', text, flags=re.IGNORECASE)
        text = re.sub(r'<\|[a-z_]+\|>', '', text, flags=re.IGNORECASE)

        return text

    def _normalize_whitespace(self, text: str) -> str:
        """
        Collapse excessive newlines that create visual separation.

        Attackers use many newlines to push the "real" instructions far
        from the system prompt, hoping the model forgets the context.
        """
        # Collapse 3+ consecutive newlines to 2
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()
