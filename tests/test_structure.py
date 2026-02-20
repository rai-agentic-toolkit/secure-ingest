"""Tests for tool-call structure enforcement."""

import pytest
from secure_ingest.structure import (
    ToolGraph,
    StructureMonitor,
    StructureViolationError,
)


# --- ToolGraph ---


class TestToolGraph:
    def test_empty_graph_allows_everything(self):
        g = ToolGraph()
        assert g.is_entry_allowed("anything")
        assert g.is_transition_allowed("a", "b")

    def test_entry_points_allow_mode(self):
        g = ToolGraph(entry_points=frozenset({"parse", "validate"}))
        assert g.is_entry_allowed("parse")
        assert g.is_entry_allowed("validate")
        assert not g.is_entry_allowed("store")

    def test_entry_points_deny_mode(self):
        g = ToolGraph(
            entry_points=frozenset({"admin"}),
            mode="deny",
        )
        assert not g.is_entry_allowed("admin")
        assert g.is_entry_allowed("parse")
        assert g.is_entry_allowed("anything_else")

    def test_transitions_allow_mode(self):
        g = ToolGraph(
            transitions={
                "parse": frozenset({"validate", "store"}),
                "validate": frozenset({"store"}),
            }
        )
        assert g.is_transition_allowed("parse", "validate")
        assert g.is_transition_allowed("parse", "store")
        assert g.is_transition_allowed("validate", "store")
        assert not g.is_transition_allowed("validate", "parse")
        assert not g.is_transition_allowed("store", "parse")

    def test_transitions_deny_mode(self):
        g = ToolGraph(
            transitions={
                "store": frozenset({"admin"}),
            },
            mode="deny",
        )
        assert not g.is_transition_allowed("store", "admin")
        assert g.is_transition_allowed("store", "parse")
        assert g.is_transition_allowed("parse", "store")

    def test_no_transitions_for_source_in_allow_mode(self):
        g = ToolGraph(
            transitions={"parse": frozenset({"validate"})}
        )
        # "store" has no outgoing edges defined
        assert not g.is_transition_allowed("store", "parse")

    def test_no_transitions_for_source_in_deny_mode(self):
        g = ToolGraph(
            transitions={"parse": frozenset({"admin"})},
            mode="deny",
        )
        # "store" has no deny rules = everything allowed
        assert g.is_transition_allowed("store", "admin")

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="mode must be"):
            ToolGraph(mode="invalid")

    def test_frozen(self):
        g = ToolGraph(entry_points=frozenset({"a"}))
        with pytest.raises(AttributeError):
            g.mode = "deny"


class TestToolGraphCompose:
    def test_compose_empty(self):
        g = ToolGraph.compose()
        assert g.is_entry_allowed("anything")

    def test_compose_single(self):
        g = ToolGraph(entry_points=frozenset({"a"}))
        result = ToolGraph.compose(g)
        assert result is g

    def test_compose_entry_points_intersection(self):
        g1 = ToolGraph(entry_points=frozenset({"a", "b", "c"}))
        g2 = ToolGraph(entry_points=frozenset({"b", "c", "d"}))
        result = ToolGraph.compose(g1, g2)
        assert result.entry_points == frozenset({"b", "c"})

    def test_compose_transitions_intersection(self):
        g1 = ToolGraph(
            entry_points=frozenset({"a"}),
            transitions={"a": frozenset({"b", "c", "d"})},
        )
        g2 = ToolGraph(
            entry_points=frozenset({"a"}),
            transitions={"a": frozenset({"c", "d", "e"})},
        )
        result = ToolGraph.compose(g1, g2)
        assert result.transitions["a"] == frozenset({"c", "d"})

    def test_compose_source_missing_in_one_graph(self):
        g1 = ToolGraph(
            entry_points=frozenset({"a"}),
            transitions={
                "a": frozenset({"b"}),
                "b": frozenset({"c"}),
            },
        )
        g2 = ToolGraph(
            entry_points=frozenset({"a"}),
            transitions={
                "a": frozenset({"b"}),
                # no "b" transitions = no outgoing edges
            },
        )
        result = ToolGraph.compose(g1, g2)
        assert "a" in result.transitions
        assert "b" not in result.transitions  # intersection with empty = empty

    def test_compose_deny_mode_raises(self):
        g1 = ToolGraph(mode="allow")
        g2 = ToolGraph(mode="deny")
        with pytest.raises(ValueError, match="Cannot compose deny-mode"):
            ToolGraph.compose(g1, g2)

    def test_compose_three_graphs(self):
        g1 = ToolGraph(
            entry_points=frozenset({"a", "b"}),
            transitions={"a": frozenset({"b", "c"})},
        )
        g2 = ToolGraph(
            entry_points=frozenset({"a", "c"}),
            transitions={"a": frozenset({"b", "d"})},
        )
        g3 = ToolGraph(
            entry_points=frozenset({"a", "d"}),
            transitions={"a": frozenset({"b", "e"})},
        )
        result = ToolGraph.compose(g1, g2, g3)
        assert result.entry_points == frozenset({"a"})
        assert result.transitions["a"] == frozenset({"b"})


# --- StructureMonitor ---


class TestStructureMonitor:
    def test_basic_flow(self):
        graph = ToolGraph(
            entry_points=frozenset({"parse"}),
            transitions={
                "parse": frozenset({"validate"}),
                "validate": frozenset({"store"}),
            },
        )
        monitor = StructureMonitor(graph)
        monitor.check("parse")
        monitor.check("validate")
        monitor.check("store")
        assert monitor.call_sequence == ("parse", "validate", "store")
        assert monitor.last_tool == "store"
        assert len(monitor.violations) == 0

    def test_entry_violation(self):
        graph = ToolGraph(entry_points=frozenset({"parse"}))
        monitor = StructureMonitor(graph)
        with pytest.raises(StructureViolationError) as exc_info:
            monitor.check("admin")
        assert exc_info.value.from_tool is None
        assert exc_info.value.to_tool == "admin"
        assert exc_info.value.reason == "not_an_entry_point"
        assert len(monitor.violations) == 1

    def test_transition_violation(self):
        graph = ToolGraph(
            entry_points=frozenset({"parse"}),
            transitions={"parse": frozenset({"validate"})},
        )
        monitor = StructureMonitor(graph)
        monitor.check("parse")
        with pytest.raises(StructureViolationError) as exc_info:
            monitor.check("store")
        assert exc_info.value.from_tool == "parse"
        assert exc_info.value.to_tool == "store"
        assert exc_info.value.reason == "transition_not_allowed"

    def test_violation_does_not_advance_state(self):
        graph = ToolGraph(
            entry_points=frozenset({"a"}),
            transitions={"a": frozenset({"b"})},
        )
        monitor = StructureMonitor(graph)
        monitor.check("a")
        with pytest.raises(StructureViolationError):
            monitor.check("c")  # violation
        # State should still be at "a"
        assert monitor.last_tool == "a"
        assert monitor.call_sequence == ("a",)

    def test_reset(self):
        graph = ToolGraph(entry_points=frozenset({"a"}))
        monitor = StructureMonitor(graph)
        monitor.check("a")
        monitor.reset()
        assert monitor.last_tool is None
        assert monitor.call_sequence == ()
        assert monitor.violations == ()

    def test_snapshot(self):
        graph = ToolGraph()
        monitor = StructureMonitor(graph)
        monitor.check("a")
        monitor.check("b")
        snap = monitor.snapshot()
        assert snap["call_sequence"] == ["a", "b"]
        assert snap["last_tool"] == "b"
        assert snap["total_calls"] == 2
        assert snap["violations"] == []

    def test_empty_graph_allows_all(self):
        monitor = StructureMonitor(ToolGraph())
        monitor.check("anything")
        monitor.check("whatever")
        assert len(monitor.violations) == 0

    def test_deny_mode_graph(self):
        graph = ToolGraph(
            entry_points=frozenset({"admin"}),
            transitions={"parse": frozenset({"admin"})},
            mode="deny",
        )
        monitor = StructureMonitor(graph)
        monitor.check("parse")  # OK (admin is denied entry, not parse)
        with pytest.raises(StructureViolationError):
            monitor.check("admin")  # parse -> admin is denied

    def test_multiple_violations_tracked(self):
        graph = ToolGraph(entry_points=frozenset({"a"}))
        monitor = StructureMonitor(graph)
        with pytest.raises(StructureViolationError):
            monitor.check("b")
        with pytest.raises(StructureViolationError):
            monitor.check("c")
        assert len(monitor.violations) == 2


# --- StructureViolationError ---


class TestStructureViolationError:
    def test_default_message(self):
        err = StructureViolationError(None, "admin", "not_an_entry_point")
        assert "(start)" in str(err)
        assert "admin" in str(err)

    def test_custom_message(self):
        err = StructureViolationError("a", "b", "reason", message="custom msg")
        assert str(err) == "custom msg"

    def test_attributes(self):
        err = StructureViolationError("a", "b", "transition_not_allowed")
        assert err.from_tool == "a"
        assert err.to_tool == "b"
        assert err.reason == "transition_not_allowed"
