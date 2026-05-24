"""
Test ASI02: Tool Misuse & Exploitation Prevention

Validates that tool access controls, parameter validation, and
rate limiting prevent agents from misusing their tools.
"""

import pytest
from tools.financial_tools import SecureQueryBuilder, FinancialCalculator


@pytest.fixture
def query_builder():
    return SecureQueryBuilder()


class TestToolMisusePrevention:
    """Tests for ASI02 - Tool Misuse & Exploitation mitigation."""

    def test_valid_query_type_accepted(self, query_builder):
        """Allowed query types produce valid parameterized queries."""
        template, params = query_builder.build_query(
            "balance",
            {"account_id": "usr_123_acct_001", "user_id": "user123"},
        )
        assert ":account_id" in template
        assert ":user_id" in template
        assert params["account_id"] == "usr_123_acct_001"

    def test_invalid_query_type_rejected(self, query_builder):
        """Query types not in the allowed set are rejected."""
        with pytest.raises(ValueError, match="not in allowed set"):
            query_builder.build_query(
                "drop_table",
                {"table": "users"},
            )

    def test_sql_injection_in_params_blocked(self, query_builder):
        """SQL injection attempts in parameters are blocked."""
        with pytest.raises(ValueError, match="Invalid characters"):
            query_builder.build_query(
                "balance",
                {"account_id": "1'; DROP TABLE accounts; --", "user_id": "user123"},
            )

    def test_semicolon_injection_blocked(self, query_builder):
        """Semicolons in parameters are blocked (statement termination)."""
        with pytest.raises(ValueError, match="Invalid characters"):
            query_builder.build_query(
                "transactions",
                {"account_id": "acct1; DELETE FROM transactions", "user_id": "u1", "limit": 10},
            )

    def test_comment_injection_blocked(self, query_builder):
        """SQL comment sequences in parameters are blocked."""
        with pytest.raises(ValueError, match="Invalid characters"):
            query_builder.build_query(
                "balance",
                {"account_id": "acct1 /* admin */", "user_id": "user1"},
            )

    def test_numeric_params_accepted(self, query_builder):
        """Numeric parameters are accepted without string validation."""
        template, params = query_builder.build_query(
            "transactions",
            {"account_id": "usr_123_acct_001", "user_id": "user123", "limit": 10},
        )
        assert params["limit"] == 10

    def test_unsupported_param_type_rejected(self, query_builder):
        """Non-string, non-numeric parameter types are rejected."""
        with pytest.raises(ValueError, match="Unsupported parameter type"):
            query_builder.build_query(
                "balance",
                {"account_id": ["list", "not", "allowed"], "user_id": "user1"},
            )

    def test_calculator_validates_principal(self):
        """Financial calculator rejects invalid principal amounts."""
        import asyncio
        calc = FinancialCalculator()
        if calc.interpreter is None:
            pytest.skip("AgentCore SDK not installed")

        result = asyncio.run(calc.calculate_interest(-1000, 0.05, 5))
        assert not result.success
        assert "Invalid principal" in result.error

    def test_calculator_validates_rate(self):
        """Financial calculator rejects rates outside 0-1 range."""
        import asyncio
        calc = FinancialCalculator()
        if calc.interpreter is None:
            pytest.skip("AgentCore SDK not installed")

        result = asyncio.run(calc.calculate_interest(1000, 5.0, 5))
        assert not result.success
        assert "Invalid rate" in result.error

    def test_calculator_validates_years(self):
        """Financial calculator rejects unreasonable year values."""
        import asyncio
        calc = FinancialCalculator()
        if calc.interpreter is None:
            pytest.skip("AgentCore SDK not installed")

        result = asyncio.run(calc.calculate_interest(1000, 0.05, -1))
        assert not result.success
        assert "Invalid years" in result.error
