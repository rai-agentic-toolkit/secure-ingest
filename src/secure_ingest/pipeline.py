"""Ingestion pipeline - orchestrates all components.

This is the main entry point for processing content. It wires together:
1. Trust boundary admission
2. Stateless parsing
3. Schema validation
4. Semantic anomaly detection
5. Trust promotion or rejection

Each piece of content flows through the full pipeline and either
gets accepted into trusted storage or is rejected/quarantined.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .anomaly import SemanticAnomalyDetector
from .budget import BudgetExhaustedError, CycleDetectedError, RequestBudget
from .parser import ContentParser, ParserConfig
from .structure import StructureMonitor, StructureViolationError
from .trust import ContentDecision, ContentEnvelope, TrustBoundary
from .validator import SchemaValidator


@dataclass
class IngestResult:
    """Final result of pipeline processing."""

    submission_id: str
    decision: str  # "accepted", "quarantined", "rejected"
    content_type: str
    source_agent_id: str
    validated_content: dict[str, Any] | None = None
    errors: list[str] | None = None
    anomaly_score: float = 0.0
    anomaly_details: dict[str, Any] | None = None
    audit_trail: list[dict[str, Any]] | None = None
    budget_snapshot: dict[str, Any] | None = None
    structure_snapshot: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "submission_id": self.submission_id,
            "decision": self.decision,
            "content_type": self.content_type,
            "source_agent_id": self.source_agent_id,
        }
        if self.validated_content is not None:
            d["validated_content"] = self.validated_content
        if self.errors:
            d["errors"] = self.errors
        if self.anomaly_score > 0:
            d["anomaly_score"] = self.anomaly_score
        if self.anomaly_details:
            d["anomaly_details"] = self.anomaly_details
        if self.audit_trail:
            d["audit_trail"] = self.audit_trail
        if self.budget_snapshot is not None:
            d["budget_snapshot"] = self.budget_snapshot
        if self.structure_snapshot is not None:
            d["structure_snapshot"] = self.structure_snapshot
        return d


class IngestionPipeline:
    """Full ingestion pipeline from raw content to trusted data.

    Usage:
        pipeline = IngestionPipeline()
        result = pipeline.ingest(
            source_agent_id="agent-001",
            content_type="security_finding",
            raw_content='{"vulnerability_id": "CVE-2024-1234", ...}'
        )
    """

    def __init__(
        self,
        trust_boundary: TrustBoundary | None = None,
        parser: ContentParser | None = None,
        validator: SchemaValidator | None = None,
        anomaly_detector: SemanticAnomalyDetector | None = None,
        budget: RequestBudget | None = None,
        structure_monitor: StructureMonitor | None = None,
    ) -> None:
        self._trust = trust_boundary or TrustBoundary()
        self._parser = parser or ContentParser()
        self._validator = validator or SchemaValidator()
        self._anomaly = anomaly_detector or SemanticAnomalyDetector()
        self._budget = budget
        self._structure = structure_monitor

    def ingest(
        self,
        source_agent_id: str,
        content_type: str,
        raw_content: str,
        include_audit: bool = False,
    ) -> IngestResult:
        """Process a single piece of content through the full pipeline."""

        # Stage 0a: Budget enforcement (before any processing)
        if self._budget is not None:
            tool_name = f"ingest:{content_type}"
            try:
                self._budget.record(tool_name)
            except (BudgetExhaustedError, CycleDetectedError) as exc:
                # Create a minimal envelope for the rejection
                envelope = self._trust.admit(source_agent_id, content_type, raw_content)
                envelope.audit("budget", "rejected", reason=str(exc))
                self._trust.reject(envelope, f"budget_exceeded: {exc}")
                result = self._build_result(envelope, include_audit)
                result.budget_snapshot = self._budget.snapshot()
                return result

        # Stage 0b: Structure enforcement (before any processing)
        if self._structure is not None:
            tool_name = f"ingest:{content_type}"
            try:
                self._structure.check(tool_name)
            except StructureViolationError as exc:
                envelope = self._trust.admit(source_agent_id, content_type, raw_content)
                envelope.audit("structure", "rejected", reason=str(exc))
                self._trust.reject(envelope, f"structure_violation: {exc}")
                result = self._build_result(envelope, include_audit)
                result.structure_snapshot = self._structure.snapshot()
                if self._budget is not None:
                    result.budget_snapshot = self._budget.snapshot()
                return result

        # Stage 1: Admission (trust boundary gate)
        envelope = self._trust.admit(source_agent_id, content_type, raw_content)
        if envelope.decision is not None:
            return self._build_result(envelope, include_audit)

        # Stage 2: Parse (stateless, no capabilities)
        parse_result = self._parser.parse(raw_content, content_type)
        envelope.audit("parsing", "completed", success=parse_result.success)

        if not parse_result.success:
            self._trust.reject(envelope, f"parse_failed: {parse_result.error}")
            return self._build_result(envelope, include_audit)

        envelope.parsed_content = parse_result.parsed_content

        # Promote to CONTROLLED (parser output exists but not yet validated)
        if not self._trust.promote_to_controlled(envelope):
            self._trust.reject(envelope, "promotion_to_controlled_failed")
            return self._build_result(envelope, include_audit)

        # Stage 3: Schema validation
        validation = self._validator.validate(
            envelope.parsed_content, content_type  # type: ignore[arg-type]
        )
        envelope.audit(
            "validation",
            "completed",
            valid=validation.valid,
            error_count=len(validation.errors),
        )

        if not validation.valid:
            envelope.validation_errors = validation.errors
            self._trust.reject(
                envelope,
                f"validation_failed: {len(validation.errors)} errors",
            )
            return self._build_result(envelope, include_audit)

        # Stage 4: Semantic anomaly detection
        anomaly = self._anomaly.analyze(envelope.parsed_content)  # type: ignore[arg-type]
        envelope.anomaly_score = anomaly.composite_score
        envelope.anomaly_details = {
            "component_scores": anomaly.component_scores,
            "triggered_patterns": anomaly.triggered_patterns,
        }
        envelope.audit(
            "anomaly_detection",
            "completed",
            score=anomaly.composite_score,
            decision=anomaly.decision,
        )

        if anomaly.decision == "reject":
            self._trust.reject(
                envelope,
                f"anomaly_rejected: score={anomaly.composite_score:.2f}",
            )
            return self._build_result(envelope, include_audit)

        if anomaly.decision == "quarantine":
            self._trust.quarantine(
                envelope,
                f"anomaly_quarantined: score={anomaly.composite_score:.2f}",
            )
            return self._build_result(envelope, include_audit)

        # Stage 5: Promote to TRUSTED
        if not self._trust.promote_to_trusted(envelope):
            self._trust.reject(envelope, "promotion_to_trusted_failed")
            result = self._build_result(envelope, include_audit)
            if self._budget is not None:
                result.budget_snapshot = self._budget.snapshot()
            if self._structure is not None:
                result.structure_snapshot = self._structure.snapshot()
            return result

        result = self._build_result(envelope, include_audit)
        if self._budget is not None:
            result.budget_snapshot = self._budget.snapshot()
        if self._structure is not None:
            result.structure_snapshot = self._structure.snapshot()
        return result

    def _build_result(
        self, envelope: ContentEnvelope, include_audit: bool
    ) -> IngestResult:
        decision = envelope.decision
        decision_str = decision.value if decision else "unknown"

        audit = None
        if include_audit:
            audit = [
                {
                    "timestamp": e.timestamp,
                    "stage": e.stage,
                    "action": e.action,
                    "details": e.details,
                }
                for e in envelope.audit_trail
            ]

        return IngestResult(
            submission_id=envelope.submission_id,
            decision=decision_str,
            content_type=envelope.content_type,
            source_agent_id=envelope.source_agent_id,
            validated_content=envelope.parsed_content if decision == ContentDecision.ACCEPTED else None,
            errors=envelope.validation_errors or None,
            anomaly_score=envelope.anomaly_score,
            anomaly_details=envelope.anomaly_details or None,
            audit_trail=audit,
        )
