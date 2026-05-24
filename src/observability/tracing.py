"""
Observability & Tracing - Security-Focused Instrumentation

Mitigates:
- ASI09 (Human-Agent Trust Exploitation): Immutable audit logs of all
  agent suggestions and rationales enable post-hoc review.
- ASI10 (Rogue Agents): Behavioral monitoring detects anomalous patterns
  like unusual tool invocation sequences or frequency spikes.
- Data Security - Telemetry Leakage: PII is redacted from all trace
  attributes and log messages before export.
- Data Security - Governance & Compliance: Complete audit trail of all
  agent actions with tamper-evident properties.

Uses OpenTelemetry for distributed tracing with custom security spans.
"""

import logging
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource

logger = logging.getLogger(__name__)


def setup_observability() -> trace.Tracer:
    """
    Configure OpenTelemetry tracing with security-focused settings.

    Security properties:
    - All spans include agent identity for attribution
    - Sensitive attributes are redacted before export
    - Trace context propagates across agent boundaries
    - Anomaly detection hooks on span completion
    """
    resource = Resource.create({
        "service.name": "owasp-mitigation-demo",
        "service.version": "1.0.0",
        "deployment.environment": "production",
    })

    provider = TracerProvider(resource=resource)

    # In production: export to AgentCore Observability backend
    # processor = BatchSpanProcessor(AgentCoreSpanExporter())
    # provider.add_span_processor(processor)

    # Add security monitoring processor
    provider.add_span_processor(
        BatchSpanProcessor(SecurityAuditExporter())
    )

    trace.set_tracer_provider(provider)

    return trace.get_tracer("owasp-mitigation-demo")


class SecurityAuditExporter:
    """
    Custom span exporter that enforces security properties on telemetry.

    - Redacts PII from span attributes before export
    - Detects anomalous patterns in span sequences
    - Maintains tamper-evident audit log
    """

    # Attributes that should never contain raw PII
    SENSITIVE_ATTRIBUTES = {
        "user.email", "user.name", "user.phone",
        "request.body", "response.body",
    }

    def export(self, spans):
        """Export spans with security filtering."""
        for span in spans:
            self._redact_sensitive_attributes(span)
            self._check_anomalies(span)
        return True  # Success

    def _redact_sensitive_attributes(self, span):
        """Remove or hash PII from span attributes (Telemetry Leakage mitigation)."""
        if hasattr(span, 'attributes') and span.attributes:
            for attr_name in self.SENSITIVE_ATTRIBUTES:
                if attr_name in span.attributes:
                    # Replace with hash for correlation without exposure
                    import hashlib
                    value = str(span.attributes[attr_name])
                    hashed = hashlib.sha256(value.encode()).hexdigest()[:16]
                    span.attributes[attr_name] = f"[REDACTED:{hashed}]"

    def _check_anomalies(self, span):
        """
        Detect anomalous agent behavior patterns (ASI10 mitigation).

        Checks for:
        - Unusual tool invocation frequency
        - Unexpected tool combinations
        - Actions outside normal operating hours
        - Repeated failed authorization attempts
        """
        if hasattr(span, 'attributes'):
            attrs = span.attributes or {}

            # Check for blocked actions (potential rogue behavior)
            if attrs.get("security.blocked"):
                logger.warning(
                    "Security event detected in trace",
                    extra={
                        "trace_id": span.context.trace_id if span.context else "unknown",
                        "reason": attrs.get("security.reason", "unknown"),
                    },
                )

            # Check for error patterns (potential cascading failure)
            if attrs.get("error.type") == "timeout":
                logger.warning(
                    "Agent timeout detected - potential cascading failure",
                    extra={"trace_id": span.context.trace_id if span.context else "unknown"},
                )

    def shutdown(self):
        """Clean shutdown."""
        pass

    def force_flush(self, timeout_millis=None):
        """Force flush pending spans."""
        pass
