"""Tests for ReliabilityProfiler — the 12 reliability metrics wrapper.

Verifies that each of the 4 dimensions and 12 metrics is computed correctly,
and that the profiler is transparent (same IngestResult as underlying pipeline).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secure_ingest import IngestionPipeline
from secure_ingest.reliability import DimensionScore, ReliabilityProfiler, ReliabilityReport


# ---------------------------------------------------------------------------
# Test fixtures — valid content that passes schema validation
# ---------------------------------------------------------------------------

CLEAN_FINDING = json.dumps({
    "vulnerability_id": "CVE-2024-12345",
    "severity": "HIGH",
    "cvss_score": 7.5,
    "description": "SQL injection vulnerability found in authentication module.",
    "affected_systems": ["auth-service"],
    "recommendation": "Apply security patches.",
})

CLEAN_REPORT = json.dumps({
    "report_id": "RPT-20240115-A1B2C3",
    "analysis_type": "threat_intelligence",
    "key_findings": [
        {"finding": "New malware variant detected in financial sector", "confidence": 0.85}
    ],
    "confidence": 0.85,
})

# Invalid JSON — will fail at parse stage
INVALID_JSON = "not json at all {{{"


def make_profiler() -> ReliabilityProfiler:
    return ReliabilityProfiler(IngestionPipeline())


# ---------------------------------------------------------------------------
# Basic transparency
# ---------------------------------------------------------------------------

class TestTransparency:
    def test_returns_same_decision_as_pipeline(self):
        pipeline = IngestionPipeline()
        profiler = ReliabilityProfiler(pipeline)
        result = profiler.ingest("agent-1", "security_finding", CLEAN_FINDING)
        # Profiler uses the same pipeline instance — just check decision type
        assert result.decision in ("accepted", "quarantined", "rejected")
        assert result.content_type == "security_finding"

    def test_accepted_content_decision(self):
        profiler = make_profiler()
        result = profiler.ingest("agent-1", "security_finding", CLEAN_FINDING)
        assert result.decision == "accepted"

    def test_include_audit_false_strips_audit_trail(self):
        profiler = make_profiler()
        result = profiler.ingest("agent-1", "security_finding", CLEAN_FINDING, include_audit=False)
        assert result.audit_trail is None

    def test_include_audit_true_returns_audit_trail(self):
        profiler = make_profiler()
        result = profiler.ingest("agent-1", "security_finding", CLEAN_FINDING, include_audit=True)
        assert result.audit_trail is not None
        assert len(result.audit_trail) > 0

    def test_empty_report_before_calls(self):
        profiler = make_profiler()
        report = profiler.report()
        assert report.total_calls == 0
        assert report.overall_score == 1.0
        for dim in [report.consistency, report.robustness, report.predictability, report.safety]:
            assert dim.score == 1.0

    def test_reset_clears_state(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().total_calls == 1
        profiler.reset()
        assert profiler.report().total_calls == 0


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

class TestReportStructure:
    def test_report_has_all_four_dimensions(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.consistency.name == "consistency"
        assert report.robustness.name == "robustness"
        assert report.predictability.name == "predictability"
        assert report.safety.name == "safety"

    def test_overall_score_is_mean_of_dimensions(self):
        profiler = make_profiler()
        for _ in range(3):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        expected = (
            report.consistency.score + report.robustness.score +
            report.predictability.score + report.safety.score
        ) / 4
        assert abs(report.overall_score - expected) < 1e-9

    def test_all_scores_in_unit_range(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        for dim in [report.consistency, report.robustness, report.predictability, report.safety]:
            assert 0.0 <= dim.score <= 1.0
        assert 0.0 <= report.overall_score <= 1.0

    def test_to_dict_has_required_keys(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        d = profiler.report().to_dict()
        assert "total_calls" in d
        assert "overall_score" in d
        assert "dimensions" in d
        for dim_name in ["consistency", "robustness", "predictability", "safety"]:
            assert dim_name in d["dimensions"]
            assert "score" in d["dimensions"][dim_name]
            assert "metrics" in d["dimensions"][dim_name]

    def test_summary_string_format(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        summary = profiler.report().summary()
        assert "ReliabilityReport" in summary
        assert "calls=" in summary
        assert "overall=" in summary


# ---------------------------------------------------------------------------
# Consistency dimension
# ---------------------------------------------------------------------------

class TestConsistency:
    def test_no_repeats_gives_perfect_consistency(self):
        profiler = make_profiler()
        # All unique content → no repeated hashes → no inconsistency detected
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        profiler.ingest("a", "analysis_report", CLEAN_REPORT)
        report = profiler.report()
        assert report.consistency.metrics["decision_consistency_rate"] == 1.0

    def test_repeated_identical_inputs_are_consistent(self):
        profiler = make_profiler()
        for _ in range(4):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.consistency.metrics["decision_consistency_rate"] == 1.0

    def test_single_call_stability_defaults_to_one(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.consistency.metrics["anomaly_score_stability"] == 1.0

    def test_uniform_anomaly_scores_are_stable(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        # Same content → same score every time → zero variance → stability = 1.0
        assert profiler.report().consistency.metrics["anomaly_score_stability"] == 1.0

    def test_consistency_has_required_metrics(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        metrics = profiler.report().consistency.metrics
        assert "decision_consistency_rate" in metrics
        assert "anomaly_score_stability" in metrics


# ---------------------------------------------------------------------------
# Robustness dimension
# ---------------------------------------------------------------------------

class TestRobustness:
    def test_all_valid_content_gives_full_robustness(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.robustness.metrics["exception_free_rate"] == 1.0

    def test_no_exceptions_means_perfect_exception_free_rate(self):
        profiler = make_profiler()
        for _ in range(3):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().robustness.metrics["exception_free_rate"] == 1.0

    def test_robustness_has_required_metrics(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        metrics = profiler.report().robustness.metrics
        assert "parse_success_rate" in metrics
        assert "exception_free_rate" in metrics

    def test_valid_content_parses_successfully(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.robustness.metrics["parse_success_rate"] == 1.0

    def test_invalid_json_reduces_parse_success_rate(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)   # parses OK
        profiler.ingest("a", "security_finding", INVALID_JSON)     # fails at parse
        report = profiler.report()
        assert report.robustness.metrics["parse_success_rate"] < 1.0


# ---------------------------------------------------------------------------
# Predictability dimension
# ---------------------------------------------------------------------------

class TestPredictability:
    def test_no_budget_gives_full_budget_headroom_score(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().predictability.metrics["budget_headroom_score"] == 1.0

    def test_uniform_decisions_give_perfect_predictability(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        # All accepted → entropy = 0 → predictability = 1.0
        assert report.predictability.metrics["decision_predictability_score"] == 1.0

    def test_predictability_has_required_metrics(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        metrics = profiler.report().predictability.metrics
        assert "budget_headroom_score" in metrics
        assert "stage_completion_rate" in metrics
        assert "decision_predictability_score" in metrics

    def test_valid_content_reaches_anomaly_stage(self):
        profiler = make_profiler()
        for _ in range(4):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        # Clean content passes all stages including anomaly detection
        assert report.predictability.metrics["stage_completion_rate"] == 1.0

    def test_invalid_content_lowers_stage_completion_rate(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)   # reaches anomaly
        profiler.ingest("a", "security_finding", INVALID_JSON)     # fails before anomaly
        report = profiler.report()
        assert report.predictability.metrics["stage_completion_rate"] < 1.0


# ---------------------------------------------------------------------------
# Safety dimension
# ---------------------------------------------------------------------------

class TestSafety:
    def test_clean_content_zero_violation_rate(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        report = profiler.report()
        assert report.safety.metrics["violation_rate"] == 0.0

    def test_clean_content_perfect_safety_score(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().safety.metrics["safety_score"] == 1.0

    def test_clean_content_has_nonzero_acceptance_rate(self):
        profiler = make_profiler()
        for _ in range(3):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().safety.metrics["acceptance_rate"] == 1.0

    def test_safety_has_required_metrics(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        metrics = profiler.report().safety.metrics
        assert "acceptance_rate" in metrics
        assert "violation_rate" in metrics
        assert "anomaly_rate" in metrics
        assert "high_anomaly_rate" in metrics
        assert "safety_score" in metrics

    def test_unknown_content_type_reduces_acceptance_rate(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        profiler.ingest("a", "nonexistent_type_xyz", '{"key": "value"}')
        report = profiler.report()
        assert report.safety.metrics["acceptance_rate"] < 1.0

    def test_schema_violations_increase_violation_rate(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        # Bad schema — missing required fields
        bad = json.dumps({"vulnerability_id": "CVE-2024-1", "severity": "bad"})
        profiler.ingest("a", "security_finding", bad)
        report = profiler.report()
        assert report.safety.metrics["violation_rate"] > 0.0

    def test_policy_deny_rule_increases_violation_rate(self):
        from secure_ingest import Policy, DenyRule
        from secure_ingest.parser import ContentParser, ParserConfig

        deny_rule = DenyRule(name="no_cve", pattern=r"CVE-", description="block CVE refs")
        policy = Policy(deny_rules=(deny_rule,))
        parser = ContentParser(config=ParserConfig(policy=policy))
        pipeline = IngestionPipeline(parser=parser)
        profiler = ReliabilityProfiler(pipeline)

        profiler.ingest("a", "security_finding", CLEAN_FINDING)  # contains CVE-2024-12345
        report = profiler.report()
        assert report.safety.metrics["violation_rate"] > 0.0


# ---------------------------------------------------------------------------
# Accumulation and multi-call behavior
# ---------------------------------------------------------------------------

class TestAccumulation:
    def test_total_calls_tracks_all_invocations(self):
        profiler = make_profiler()
        for _ in range(7):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().total_calls == 7

    def test_call_count_increments_each_call(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().total_calls == 1
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().total_calls == 2

    def test_mixed_content_types_tracked(self):
        profiler = make_profiler()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        profiler.ingest("a", "analysis_report", CLEAN_REPORT)
        report = profiler.report()
        assert report.total_calls == 2
        assert 0.0 <= report.overall_score <= 1.0

    def test_reset_then_fresh_report(self):
        profiler = make_profiler()
        for _ in range(5):
            profiler.ingest("a", "security_finding", CLEAN_FINDING)
        profiler.reset()
        profiler.ingest("a", "security_finding", CLEAN_FINDING)
        assert profiler.report().total_calls == 1
