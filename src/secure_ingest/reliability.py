"""Reliability profiler for IngestionPipeline.

Wraps IngestionPipeline and tracks 12 reliability metrics across 4 dimensions,
inspired by "Towards a Science of AI Agent Reliability" (arXiv:2602.16666v1).

The four dimensions and their metrics:

  CONSISTENCY — same inputs produce same outputs
    1. decision_consistency_rate: % of repeated inputs (same hash) that get identical decisions
    2. anomaly_score_stability: 1 - coefficient of variation of anomaly scores (lower variance = more stable)

  ROBUSTNESS — handles edge cases and adversarial inputs gracefully
    3. parse_success_rate: % of inputs that parse successfully (vs crashing or unhandled)
    4. exception_free_rate: % of calls that complete without unexpected exceptions

  PREDICTABILITY — outputs and resource use within expected bounds
    5. budget_utilization_ratio: calls made / budget ceiling (lower = more headroom)
    6. stage_completion_rate: % of inputs that reach stage 4 (anomaly detection)
    7. decision_entropy: 0..1 normalized Shannon entropy of accept/quarantine/reject distribution
                         (lower = more predictable outcomes)

  SAFETY — violation detection and content blocking
    8. acceptance_rate: % of inputs that were fully accepted
    9. violation_rate: % of inputs with any violation (denied by policy)
   10. anomaly_rate: % of inputs with anomaly_score > 0 (any signal detected)
   11. high_anomaly_rate: % of inputs with anomaly_score > 0.7 (quarantine/reject territory)
   12. safety_score: composite safety measure = 1 - acceptance_rate of suspicious inputs
                     where suspicious = anomaly_score > 0.3

Scores for each dimension are averaged across their constituent metrics.
All scores are normalized to [0, 1] where 1 = best possible.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

from .pipeline import IngestionPipeline, IngestResult


@dataclass
class DimensionScore:
    """Score for a single reliability dimension."""

    name: str
    score: float  # 0..1, higher = better
    metrics: dict[str, float]  # individual metric values


@dataclass
class ReliabilityReport:
    """Full reliability profile for a session."""

    total_calls: int
    consistency: DimensionScore
    robustness: DimensionScore
    predictability: DimensionScore
    safety: DimensionScore
    overall_score: float  # mean of dimension scores

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_calls": self.total_calls,
            "overall_score": round(self.overall_score, 4),
            "dimensions": {
                dim.name: {
                    "score": round(dim.score, 4),
                    "metrics": {k: round(v, 4) for k, v in dim.metrics.items()},
                }
                for dim in [self.consistency, self.robustness, self.predictability, self.safety]
            },
        }

    def summary(self) -> str:
        """One-line summary suitable for logging."""
        dims = [self.consistency, self.robustness, self.predictability, self.safety]
        parts = [f"{d.name[:4]}={d.score:.2f}" for d in dims]
        return f"ReliabilityReport(calls={self.total_calls}, overall={self.overall_score:.2f}, [{', '.join(parts)}])"


class ReliabilityProfiler:
    """Wraps IngestionPipeline and tracks reliability metrics across calls.

    Usage::

        pipeline = IngestionPipeline()
        profiler = ReliabilityProfiler(pipeline)

        result = profiler.ingest(source_agent_id="agent-1", content_type="code_snippet", raw_content="...")
        report = profiler.report()
        print(report.summary())

    The profiler is transparent — it returns the same IngestResult as the
    underlying pipeline. Metrics accumulate across calls until reset().
    """

    def __init__(self, pipeline: IngestionPipeline) -> None:
        self._pipeline = pipeline
        self._calls: list[dict[str, Any]] = []
        # Maps content_hash → list of decisions (for consistency tracking)
        self._hash_decisions: dict[str, list[str]] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def ingest(
        self,
        source_agent_id: str,
        content_type: str,
        raw_content: str,
        include_audit: bool = False,
    ) -> IngestResult:
        """Delegate to pipeline and record metrics for this call.

        Always collects audit trail internally for accurate metric computation.
        The returned IngestResult respects the caller's include_audit preference.
        """
        content_hash = hashlib.sha256(
            (content_type + ":" + raw_content).encode("utf-8", errors="replace")
        ).hexdigest()

        exception_raised = False
        result: IngestResult | None = None
        try:
            # Always collect audit internally; strip it from response if caller didn't ask
            result = self._pipeline.ingest(
                source_agent_id=source_agent_id,
                content_type=content_type,
                raw_content=raw_content,
                include_audit=True,
            )
        except Exception:
            exception_raised = True
            raise
        finally:
            call_record: dict[str, Any] = {
                "content_hash": content_hash,
                "content_type": content_type,
                "exception": exception_raised,
            }
            if result is not None:
                audit = result.audit_trail or []
                stages = {e["stage"] for e in audit}
                actions = [(e["stage"], e["action"]) for e in audit]

                parsed_successfully = (
                    "parsing" in stages and
                    ("trust_boundary", "promoted_to_controlled") in actions
                )
                reached_anomaly = "anomaly_detection" in stages

                # Any policy violation: schema errors (from validator) OR deny-rule rejections
                # (which surface as parse_failed reasons in the audit trail, not result.errors)
                reject_reasons = " ".join(
                    str(e.get("details", {}).get("reason", ""))
                    for e in audit
                    if e.get("action") == "rejected"
                )
                has_policy_violation = bool(result.errors) or "policy" in reject_reasons.lower()

                call_record.update(
                    {
                        "decision": result.decision,
                        "anomaly_score": result.anomaly_score,
                        "schema_errors": result.errors or [],
                        "has_policy_violation": has_policy_violation,
                        "parsed_successfully": parsed_successfully,
                        "reached_anomaly_stage": reached_anomaly,
                        "budget_snapshot": result.budget_snapshot,
                    }
                )
                # Track hash→decision for consistency
                if content_hash not in self._hash_decisions:
                    self._hash_decisions[content_hash] = []
                self._hash_decisions[content_hash].append(result.decision)
            self._calls.append(call_record)

        # Strip audit trail if caller didn't request it
        if result is not None and not include_audit:
            result.audit_trail = None
        return result  # type: ignore[return-value]

    def reset(self) -> None:
        """Clear all accumulated metrics."""
        self._calls.clear()
        self._hash_decisions.clear()

    def report(self) -> ReliabilityReport:
        """Generate a ReliabilityReport from all calls since last reset()."""
        if not self._calls:
            return self._empty_report()

        consistency = self._score_consistency()
        robustness = self._score_robustness()
        predictability = self._score_predictability()
        safety = self._score_safety()

        overall = (
            consistency.score + robustness.score + predictability.score + safety.score
        ) / 4

        return ReliabilityReport(
            total_calls=len(self._calls),
            consistency=consistency,
            robustness=robustness,
            predictability=predictability,
            safety=safety,
            overall_score=overall,
        )

    # ------------------------------------------------------------------
    # Dimension scorers
    # ------------------------------------------------------------------

    def _score_consistency(self) -> DimensionScore:
        # Metric 1: decision_consistency_rate
        # For hashes seen more than once, what fraction have consistent decisions?
        repeated = {h: ds for h, ds in self._hash_decisions.items() if len(ds) > 1}
        if repeated:
            consistent_count = sum(
                1 for ds in repeated.values() if len(set(ds)) == 1
            )
            decision_consistency_rate = consistent_count / len(repeated)
        else:
            decision_consistency_rate = 1.0  # no repeats = no inconsistency detected

        # Metric 2: anomaly_score_stability (1 - CV, clamped to [0,1])
        scores = [c["anomaly_score"] for c in self._calls if "anomaly_score" in c]
        if len(scores) >= 2:
            mean = sum(scores) / len(scores)
            if mean > 0:
                variance = sum((s - mean) ** 2 for s in scores) / len(scores)
                cv = math.sqrt(variance) / mean  # coefficient of variation
                stability = max(0.0, 1.0 - cv)
            else:
                stability = 1.0  # all zero scores = perfectly stable
        else:
            stability = 1.0

        metrics = {
            "decision_consistency_rate": decision_consistency_rate,
            "anomaly_score_stability": stability,
        }
        return DimensionScore(
            name="consistency",
            score=(decision_consistency_rate + stability) / 2,
            metrics=metrics,
        )

    def _score_robustness(self) -> DimensionScore:
        n = len(self._calls)

        # Metric 3: parse_success_rate — % of calls where content was parsed successfully
        # (determined via audit trail: parsing stage reached AND promoted_to_controlled)
        complete_calls = [c for c in self._calls if not c.get("exception", False)]
        parse_success = [c for c in complete_calls if c.get("parsed_successfully", False)]
        parse_success_rate = len(parse_success) / n if n > 0 else 1.0

        # Metric 4: exception_free_rate — % of calls that completed without raising
        no_exception = [c for c in self._calls if not c.get("exception", False)]
        exception_free_rate = len(no_exception) / n if n > 0 else 1.0

        metrics = {
            "parse_success_rate": parse_success_rate,
            "exception_free_rate": exception_free_rate,
        }
        return DimensionScore(
            name="robustness",
            score=(parse_success_rate + exception_free_rate) / 2,
            metrics=metrics,
        )

    def _score_predictability(self) -> DimensionScore:
        n = len(self._calls)

        # Metric 5: budget_utilization_ratio (inverted — lower utilization = more predictable headroom)
        budget_snapshots = [
            c["budget_snapshot"] for c in self._calls
            if c.get("budget_snapshot") and c["budget_snapshot"].get("max_calls") is not None
        ]
        if budget_snapshots:
            last = budget_snapshots[-1]
            max_calls = last.get("max_calls", 1) or 1
            used = last.get("calls_made", 0)
            utilization = used / max_calls
            budget_score = max(0.0, 1.0 - utilization)
        else:
            budget_score = 1.0  # no budget = no constraint to measure

        # Metric 6: stage_completion_rate (reached anomaly detection stage)
        completed = [
            c for c in self._calls
            if c.get("reached_anomaly_stage", False)
        ]
        stage_completion_rate = len(completed) / n if n > 0 else 1.0

        # Metric 7: decision_entropy (inverted — lower entropy = more predictable)
        decisions = [c.get("decision", "unknown") for c in self._calls if "decision" in c]
        if decisions:
            counts: dict[str, int] = {}
            for d in decisions:
                counts[d] = counts.get(d, 0) + 1
            total = len(decisions)
            probs = [cnt / total for cnt in counts.values()]
            # Shannon entropy, normalized by log2(3) for 3 decision categories
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
            max_entropy = math.log2(max(len(counts), 1))
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
            predictability_score = 1.0 - normalized_entropy
        else:
            predictability_score = 1.0

        metrics = {
            "budget_utilization_ratio": 1.0 - budget_score,  # raw utilization for display
            "budget_headroom_score": budget_score,
            "stage_completion_rate": stage_completion_rate,
            "decision_entropy": 1.0 - predictability_score,  # raw entropy for display
            "decision_predictability_score": predictability_score,
        }
        return DimensionScore(
            name="predictability",
            score=(budget_score + stage_completion_rate + predictability_score) / 3,
            metrics=metrics,
        )

    def _score_safety(self) -> DimensionScore:
        n = len(self._calls)
        with_results = [c for c in self._calls if "decision" in c]
        m = len(with_results)

        # Metric 8: acceptance_rate
        accepted = [c for c in with_results if c["decision"] == "accepted"]
        acceptance_rate = len(accepted) / m if m > 0 else 1.0

        # Metric 9: violation_rate (schema errors OR policy deny/allow rule violations)
        with_violations = [c for c in with_results if c.get("has_policy_violation", False)]
        violation_rate = len(with_violations) / m if m > 0 else 0.0

        # Metric 10: anomaly_rate (any anomaly signal)
        with_anomaly = [c for c in with_results if c.get("anomaly_score", 0) > 0]
        anomaly_rate = len(with_anomaly) / m if m > 0 else 0.0

        # Metric 11: high_anomaly_rate
        high_anomaly = [c for c in with_results if c.get("anomaly_score", 0) > 0.7]
        high_anomaly_rate = len(high_anomaly) / m if m > 0 else 0.0

        # Metric 12: safety_score
        # If suspicious content (anomaly_score > 0.3) is NOT accepted, that's good safety behavior.
        suspicious = [c for c in with_results if c.get("anomaly_score", 0) > 0.3]
        if suspicious:
            suspicious_accepted = [c for c in suspicious if c["decision"] == "accepted"]
            suspicious_acceptance_rate = len(suspicious_accepted) / len(suspicious)
            safety_score = 1.0 - suspicious_acceptance_rate
        else:
            safety_score = 1.0  # no suspicious content = perfect safety score

        metrics = {
            "acceptance_rate": acceptance_rate,
            "violation_rate": violation_rate,
            "anomaly_rate": anomaly_rate,
            "high_anomaly_rate": high_anomaly_rate,
            "safety_score": safety_score,
        }

        # Dimension score: penalize high violation/anomaly rates (they're warning signals)
        # but reward proper blocking of suspicious content
        # High acceptance of clean content = good. High blocking of suspicious = good.
        violation_ok = 1.0 - min(violation_rate, 1.0)
        high_anomaly_ok = 1.0 - min(high_anomaly_rate, 1.0)
        dim_score = (violation_ok + high_anomaly_ok + safety_score) / 3

        return DimensionScore(
            name="safety",
            score=dim_score,
            metrics=metrics,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _empty_report(self) -> ReliabilityReport:
        empty = DimensionScore(name="", score=1.0, metrics={})
        return ReliabilityReport(
            total_calls=0,
            consistency=DimensionScore(
                name="consistency", score=1.0,
                metrics={"decision_consistency_rate": 1.0, "anomaly_score_stability": 1.0}
            ),
            robustness=DimensionScore(
                name="robustness", score=1.0,
                metrics={"parse_success_rate": 1.0, "exception_free_rate": 1.0}
            ),
            predictability=DimensionScore(
                name="predictability", score=1.0,
                metrics={
                    "budget_utilization_ratio": 0.0, "budget_headroom_score": 1.0,
                    "stage_completion_rate": 1.0,
                    "decision_entropy": 0.0, "decision_predictability_score": 1.0,
                }
            ),
            safety=DimensionScore(
                name="safety", score=1.0,
                metrics={
                    "acceptance_rate": 1.0, "violation_rate": 0.0,
                    "anomaly_rate": 0.0, "high_anomaly_rate": 0.0, "safety_score": 1.0,
                }
            ),
            overall_score=1.0,
        )
        _ = empty  # suppress lint
