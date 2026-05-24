"""
Test Data Security: Sensitive Data Leakage Prevention

Validates that the OutputFilter correctly identifies and redacts
PII and sensitive data from agent responses.
"""

import pytest
from security.output_filter import OutputFilter


@pytest.fixture
def filter():
    return OutputFilter(use_presidio=False)  # Regex-only for unit tests


class TestDataLeakagePrevention:
    """Tests for Data Security - Sensitive Data Leakage mitigation."""

    def test_ssn_redacted(self, filter):
        """Social Security Numbers are redacted from output."""
        text = "Your SSN on file is 123-45-6789."
        result = filter.filter(text)
        assert "123-45-6789" not in result
        assert "***-**-****" in result

    def test_credit_card_redacted(self, filter):
        """Credit card numbers are redacted, preserving last 4."""
        text = "Card ending in 4532-1234-5678-9012 was charged."
        result = filter.filter(text)
        assert "4532-1234-5678-9012" not in result
        assert "9012" in result  # Last 4 preserved for reference

    def test_full_account_number_redacted(self, filter):
        """Full account numbers (10+ digits) are redacted."""
        text = "Account 1234567890 has a balance of $5,000."
        result = filter.filter(text)
        assert "1234567890" not in result
        assert "7890" in result  # Last 4 preserved

    def test_email_redacted(self, filter):
        """Email addresses are redacted from output."""
        text = "Contact the customer at john.doe@example.com for details."
        result = filter.filter(text)
        assert "john.doe@example.com" not in result
        assert "[EMAIL REDACTED]" in result

    def test_phone_number_redacted(self, filter):
        """Phone numbers are redacted from output."""
        text = "Call us at (555) 123-4567 for support."
        result = filter.filter(text)
        assert "(555) 123-4567" not in result
        assert "[PHONE REDACTED]" in result

    def test_api_key_redacted(self, filter):
        """API keys are redacted from output."""
        # Key format: (sk|pk|api) + underscore + 20+ alphanumeric chars
        fake_key = "pk_a1b2c3d4e5f6g7h8i9j0k1l2"
        text = f"Your API key is {fake_key}"
        result = filter.filter(text)
        assert fake_key not in result
        assert "[API KEY REDACTED]" in result

    def test_aws_key_redacted(self, filter):
        """AWS access keys are redacted from output."""
        text = "Found key AKIAIOSFODNN7EXAMPLE in the config."
        result = filter.filter(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[AWS KEY REDACTED]" in result

    def test_normal_text_unchanged(self, filter):
        """Normal text without sensitive data passes through unchanged."""
        text = "Your account balance is $5,432.10. Last transaction was $42.50."
        result = filter.filter(text)
        assert result == text

    def test_multiple_sensitive_items(self, filter):
        """Multiple sensitive items in one response are all redacted."""
        text = (
            "Customer John (john@email.com) with SSN 123-45-6789 "
            "called from (555) 987-6543 about account 9876543210."
        )
        result = filter.filter(text)
        assert "john@email.com" not in result
        assert "123-45-6789" not in result
        assert "(555) 987-6543" not in result
        assert "9876543210" not in result

    def test_logging_filter_truncates(self, filter):
        """Logging filter truncates long content to prevent telemetry leakage."""
        long_text = "A" * 1000
        result = filter.filter_for_logging(long_text)
        assert len(result) < 600
        assert "[TRUNCATED FOR LOGGING]" in result

    def test_empty_input_handled(self, filter):
        """Empty input doesn't cause errors."""
        assert filter.filter("") == ""
        assert filter.filter(None) is None
