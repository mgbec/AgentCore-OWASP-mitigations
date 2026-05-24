"""
Financial Tools - Scoped Operations with Safety Constraints

Mitigates:
- ASI02 (Tool Misuse): Each tool has strict parameter validation,
  rate limits, and scope restrictions.
- ASI05 (Unexpected Code Execution): Financial calculations use
  AgentCore Code Interpreter sandbox instead of eval/exec.
- Data Security - Unsafe LLM-to-SQL: All database queries are
  parameterized; LLM output never becomes raw SQL.
"""

import logging
from typing import Any
from dataclasses import dataclass

try:
    from bedrock_agentcore_sdk.tools import CodeInterpreter
except ImportError:
    CodeInterpreter = None  # SDK not available in test environment

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    success: bool
    data: dict[str, Any]
    error: str | None = None


class FinancialCalculator:
    """
    Sandboxed financial calculations via AgentCore Code Interpreter.

    Instead of using eval() or exec() on LLM-generated code (ASI05 risk),
    all calculations run in an isolated Code Interpreter sandbox with:
    - No network access
    - No filesystem access beyond /tmp
    - CPU and memory limits
    - Execution timeout
    """

    def __init__(self):
        if CodeInterpreter is not None:
            self.interpreter = CodeInterpreter(
                timeout_seconds=10,
                max_memory_mb=256,
            )
        else:
            self.interpreter = None

    async def calculate_interest(
        self, principal: float, rate: float, years: int
    ) -> ToolResult:
        """Calculate compound interest in sandbox."""
        # Validate inputs before sending to sandbox
        if principal < 0 or principal > 1_000_000_000:
            return ToolResult(success=False, data={}, error="Invalid principal amount")
        if rate < 0 or rate > 1.0:
            return ToolResult(success=False, data={}, error="Invalid rate (must be 0-1)")
        if years < 0 or years > 100:
            return ToolResult(success=False, data={}, error="Invalid years")

        # ASI05: Execute in sandbox, not on host
        code = f"""
principal = {principal}
rate = {rate}
years = {years}
result = principal * (1 + rate) ** years
interest = result - principal
print(f"{{result:.2f}},{{interest:.2f}}")
"""
        result = await self.interpreter.execute(code)

        if result.success:
            parts = result.output.strip().split(",")
            return ToolResult(
                success=True,
                data={
                    "final_amount": float(parts[0]),
                    "interest_earned": float(parts[1]),
                    "principal": principal,
                    "rate": rate,
                    "years": years,
                },
            )
        return ToolResult(success=False, data={}, error=result.error)


class SecureQueryBuilder:
    """
    Parameterized query builder - prevents LLM-to-SQL injection.

    The LLM never generates raw SQL. Instead, it selects from a set of
    pre-defined query templates and provides parameters that are safely
    bound using parameterized queries.
    """

    # Pre-defined query templates (LLM selects template, not SQL)
    ALLOWED_QUERIES = {
        "balance": "SELECT balance FROM accounts WHERE account_id = :account_id AND user_id = :user_id",
        "transactions": (
            "SELECT date, amount, description FROM transactions "
            "WHERE account_id = :account_id AND user_id = :user_id "
            "ORDER BY date DESC LIMIT :limit"
        ),
        "transfer_history": (
            "SELECT * FROM transfers "
            "WHERE (from_account = :account_id OR to_account = :account_id) "
            "AND user_id = :user_id ORDER BY created_at DESC LIMIT :limit"
        ),
    }

    def build_query(
        self, query_type: str, params: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """
        Build a parameterized query from a template.

        The LLM output (query_type) is validated against allowed templates.
        Parameters are type-checked and bound safely.
        """
        if query_type not in self.ALLOWED_QUERIES:
            raise ValueError(f"Query type '{query_type}' not in allowed set")

        template = self.ALLOWED_QUERIES[query_type]

        # Validate parameter types
        safe_params = {}
        for key, value in params.items():
            if isinstance(value, str):
                # Prevent SQL injection in string params
                if any(c in value for c in [";", "--", "/*", "*/", "'"]):
                    raise ValueError(f"Invalid characters in parameter '{key}'")
                safe_params[key] = value
            elif isinstance(value, (int, float)):
                safe_params[key] = value
            else:
                raise ValueError(f"Unsupported parameter type for '{key}'")

        return template, safe_params
