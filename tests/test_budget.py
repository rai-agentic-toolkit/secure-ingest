"""Tests for request budget enforcement."""

import pytest

from secure_ingest.budget import (
    BudgetConfig,
    BudgetExhaustedError,
    CycleDetectedError,
    RequestBudget,
)


# --- BudgetConfig validation ---


class TestBudgetConfig:
    def test_defaults(self):
        cfg = BudgetConfig()
        assert cfg.max_calls is None
        assert cfg.max_calls_per_tool is None
        assert cfg.max_cycle_repeats == 2
        assert cfg.min_cycle_length == 2
        assert cfg.max_cycle_length == 8

    def test_max_calls_must_be_positive(self):
        with pytest.raises(ValueError, match="max_calls must be >= 1"):
            BudgetConfig(max_calls=0)

    def test_max_calls_per_tool_must_be_positive(self):
        with pytest.raises(ValueError, match="max_calls_per_tool must be >= 1"):
            BudgetConfig(max_calls_per_tool=0)

    def test_max_cycle_repeats_must_be_positive(self):
        with pytest.raises(ValueError, match="max_cycle_repeats must be >= 1"):
            BudgetConfig(max_cycle_repeats=0)

    def test_min_cycle_length_must_be_at_least_2(self):
        with pytest.raises(ValueError, match="min_cycle_length must be >= 2"):
            BudgetConfig(min_cycle_length=1)

    def test_max_cycle_length_must_be_gte_min(self):
        with pytest.raises(ValueError, match="max_cycle_length must be >= min_cycle_length"):
            BudgetConfig(min_cycle_length=4, max_cycle_length=3)

    def test_custom_config(self):
        cfg = BudgetConfig(max_calls=50, max_calls_per_tool=10, max_cycle_repeats=3)
        assert cfg.max_calls == 50
        assert cfg.max_calls_per_tool == 10
        assert cfg.max_cycle_repeats == 3


# --- RequestBudget basics ---


class TestRequestBudgetBasics:
    def test_empty_budget(self):
        b = RequestBudget()
        assert b.total_calls == 0
        assert b.call_sequence == ()
        assert b.tool_counts == {}

    def test_record_tracks_calls(self):
        b = RequestBudget()
        b.record("tool_a")
        b.record("tool_b")
        b.record("tool_a")
        assert b.total_calls == 3
        assert b.call_sequence == ("tool_a", "tool_b", "tool_a")
        assert b.tool_counts == {"tool_a": 2, "tool_b": 1}

    def test_snapshot(self):
        b = RequestBudget(BudgetConfig(max_calls=10))
        b.record("x")
        snap = b.snapshot()
        assert snap["total_calls"] == 1
        assert snap["tool_counts"] == {"x": 1}
        assert snap["remaining"]["total_calls"] == 9

    def test_remaining_no_limit(self):
        b = RequestBudget()
        assert b.remaining()["total_calls"] is None


# --- Total call limit ---


class TestTotalCallLimit:
    def test_enforces_max_calls(self):
        b = RequestBudget(BudgetConfig(max_calls=3))
        b.record("a")
        b.record("b")
        b.record("c")
        with pytest.raises(BudgetExhaustedError) as exc_info:
            b.record("d")
        assert exc_info.value.budget_type == "total_calls"
        assert exc_info.value.limit == 3
        assert exc_info.value.current == 4

    def test_max_calls_exactly_at_limit(self):
        b = RequestBudget(BudgetConfig(max_calls=2))
        b.record("a")
        b.record("b")  # exactly at limit, should succeed
        assert b.total_calls == 2

    def test_no_limit_means_unlimited(self):
        b = RequestBudget()
        for i in range(100):
            b.record(f"tool_{i}")
        assert b.total_calls == 100


# --- Per-tool call limit ---


class TestPerToolLimit:
    def test_enforces_per_tool_limit(self):
        b = RequestBudget(BudgetConfig(max_calls_per_tool=2))
        b.record("tool_a")
        b.record("tool_b")
        b.record("tool_a")  # 2nd call to tool_a, at limit
        with pytest.raises(BudgetExhaustedError) as exc_info:
            b.record("tool_a")  # 3rd call to tool_a, over limit
        assert "calls_per_tool:tool_a" in exc_info.value.budget_type
        assert exc_info.value.limit == 2

    def test_per_tool_limit_independent_across_tools(self):
        b = RequestBudget(BudgetConfig(max_calls_per_tool=2))
        b.record("a")
        b.record("b")
        b.record("a")
        b.record("b")
        # Both at limit, but different tools — all OK
        assert b.total_calls == 4

    def test_per_tool_limit_1(self):
        b = RequestBudget(BudgetConfig(max_calls_per_tool=1))
        b.record("tool_x")
        with pytest.raises(BudgetExhaustedError):
            b.record("tool_x")


# --- Cycle detection ---


class TestCycleDetection:
    def test_simple_ab_cycle(self):
        b = RequestBudget(BudgetConfig(max_cycle_repeats=2))
        b.record("a")
        b.record("b")
        b.record("a")
        b.record("b")
        # 2 repeats so far — at threshold, not over
        with pytest.raises(CycleDetectedError) as exc_info:
            b.record("a")
            b.record("b")  # 3rd repeat
        err = exc_info.value
        assert err.cycle == ("a", "b")
        assert err.occurrences > 2

    def test_no_cycle_with_varied_calls(self):
        b = RequestBudget(BudgetConfig(max_cycle_repeats=2))
        for tool in ["a", "b", "c", "d", "e", "f", "g", "h"]:
            b.record(tool)
        assert b.total_calls == 8

    def test_abc_cycle(self):
        b = RequestBudget(BudgetConfig(max_cycle_repeats=1, min_cycle_length=3))
        b.record("a")
        b.record("b")
        b.record("c")
        with pytest.raises(CycleDetectedError):
            b.record("a")
            b.record("b")
            b.record("c")

    def test_cycle_length_below_min_not_detected(self):
        """Cycles shorter than min_cycle_length are ignored."""
        b = RequestBudget(BudgetConfig(max_cycle_repeats=1, min_cycle_length=3))
        # a, b, a, b — length-2 cycle, but min is 3
        b.record("a")
        b.record("b")
        b.record("a")
        b.record("b")
        assert b.total_calls == 4  # no error

    def test_cycle_length_above_max_not_detected(self):
        """Cycles longer than max_cycle_length are ignored."""
        b = RequestBudget(
            BudgetConfig(max_cycle_repeats=1, min_cycle_length=2, max_cycle_length=2)
        )
        # a, b, c, a, b, c — length-3 cycle, but max is 2
        b.record("a")
        b.record("b")
        b.record("c")
        b.record("a")
        b.record("b")
        b.record("c")
        assert b.total_calls == 6  # no error

    def test_high_threshold_tolerates_repeats(self):
        """High max_cycle_repeats allows more repetition before triggering."""
        b = RequestBudget(BudgetConfig(max_cycle_repeats=5))
        for _ in range(5):
            b.record("x")
            b.record("y")
        # 5 repeats at threshold — shouldn't error
        assert b.total_calls == 10


# --- Combined limits ---


class TestCombinedLimits:
    def test_total_limit_hits_before_cycle(self):
        """Total call limit can fire before cycle detection."""
        b = RequestBudget(BudgetConfig(max_calls=4, max_cycle_repeats=2))
        b.record("a")
        b.record("b")
        b.record("a")
        b.record("b")
        with pytest.raises(BudgetExhaustedError):
            b.record("a")  # call 5 > max_calls=4

    def test_per_tool_hits_before_total(self):
        b = RequestBudget(BudgetConfig(max_calls=100, max_calls_per_tool=1))
        b.record("a")
        with pytest.raises(BudgetExhaustedError) as exc_info:
            b.record("a")
        assert "calls_per_tool" in exc_info.value.budget_type


# --- Error types ---


class TestErrors:
    def test_budget_exhausted_error_message(self):
        err = BudgetExhaustedError("total_calls", 10, 11)
        assert "total_calls" in str(err)
        assert "10" in str(err)

    def test_cycle_detected_error_message(self):
        err = CycleDetectedError(("a", "b"), 3)
        assert "a -> b" in str(err)
        assert "3" in str(err)

    def test_budget_exhausted_custom_message(self):
        err = BudgetExhaustedError("x", 1, 2, "custom msg")
        assert str(err) == "custom msg"

    def test_cycle_detected_custom_message(self):
        err = CycleDetectedError(("a",), 1, "custom cycle msg")
        assert str(err) == "custom cycle msg"
