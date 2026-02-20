"""Tool-call structure enforcement for agent pipelines.

Defines and enforces allowed tool-call transitions as a directed graph.
This is the "structure layer" — it prevents attacks that manipulate which
tools get called in which order, complementing the content layer (policies)
and budget layer (call counts/cycles).

Design principles:
- Fail-closed: unlisted transitions are denied by default
- Observable: all violations include structured context
- Composable: graphs can be merged with most-restrictive-wins

Informed by:
- "PCAS" (2602.16708v1): dependency graph-based policy enforcement
- "Overthinking Loops" (2602.14798v1): structural patterns as attack surface
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class StructureViolationError(Exception):
    """Raised when a tool-call transition violates the structure graph."""

    def __init__(
        self,
        from_tool: str | None,
        to_tool: str,
        reason: str,
        message: str = "",
    ) -> None:
        self.from_tool = from_tool
        self.to_tool = to_tool
        self.reason = reason
        super().__init__(
            message
            or f"Structure violation: {from_tool or '(start)'} -> {to_tool}: {reason}"
        )


@dataclass(frozen=True)
class ToolGraph:
    """Defines allowed tool-call transitions as a directed graph.

    In "allow" mode (default), only listed transitions are permitted.
    In "deny" mode, all transitions are permitted EXCEPT listed ones.

    Usage:
        graph = ToolGraph(
            entry_points=frozenset({"parse", "validate"}),
            transitions={"parse": frozenset({"validate", "store"}),
                         "validate": frozenset({"store"})},
        )
        monitor = StructureMonitor(graph)
        monitor.check("parse")      # OK (entry point)
        monitor.check("validate")   # OK (parse -> validate allowed)
        monitor.check("store")      # OK (validate -> store allowed)
        monitor.check("parse")      # VIOLATION (store -> parse not allowed)
    """

    entry_points: frozenset[str] = field(default_factory=frozenset)
    transitions: dict[str, frozenset[str]] = field(default_factory=dict)
    mode: str = "allow"

    def __post_init__(self) -> None:
        if self.mode not in ("allow", "deny"):
            raise ValueError(f"mode must be 'allow' or 'deny', got {self.mode!r}")

    def is_entry_allowed(self, tool: str) -> bool:
        """Check if a tool is allowed as an entry point."""
        if not self.entry_points:
            # No entry points defined = all entry points allowed
            return True
        if self.mode == "allow":
            return tool in self.entry_points
        else:
            return tool not in self.entry_points

    def is_transition_allowed(self, from_tool: str, to_tool: str) -> bool:
        """Check if a transition from one tool to another is allowed."""
        if not self.transitions:
            # No transitions defined = all transitions allowed
            return True
        if self.mode == "allow":
            allowed = self.transitions.get(from_tool)
            if allowed is None:
                # Tool has no defined transitions = no outgoing edges allowed
                return False
            return to_tool in allowed
        else:
            denied = self.transitions.get(from_tool)
            if denied is None:
                return True
            return to_tool not in denied

    @staticmethod
    def compose(*graphs: ToolGraph) -> ToolGraph:
        """Merge multiple graphs with most-restrictive-wins semantics.

        Only works for "allow" mode graphs. Result allows only transitions
        that ALL input graphs allow.

        Raises ValueError if any graph uses "deny" mode (composition of
        deny-mode graphs is semantically ambiguous).
        """
        if not graphs:
            return ToolGraph()
        if len(graphs) == 1:
            return graphs[0]

        for g in graphs:
            if g.mode != "allow":
                raise ValueError(
                    "Cannot compose deny-mode graphs. "
                    "Convert to allow-mode first."
                )

        # Entry points: intersection (only tools ALL graphs allow)
        entry_sets = [g.entry_points for g in graphs if g.entry_points]
        if entry_sets:
            merged_entries = entry_sets[0]
            for s in entry_sets[1:]:
                merged_entries = merged_entries & s
        else:
            merged_entries = frozenset()

        # Transitions: intersection per source tool
        all_sources: set[str] = set()
        for g in graphs:
            all_sources.update(g.transitions.keys())

        merged_transitions: dict[str, frozenset[str]] = {}
        for source in all_sources:
            # Get allowed targets from each graph that defines this source
            target_sets = []
            for g in graphs:
                if source in g.transitions:
                    target_sets.append(g.transitions[source])
                elif g.transitions:
                    # Graph has transitions but not for this source = no targets
                    target_sets.append(frozenset())

            if target_sets:
                merged = target_sets[0]
                for ts in target_sets[1:]:
                    merged = merged & ts
                if merged:
                    merged_transitions[source] = merged

        return ToolGraph(
            entry_points=merged_entries,
            transitions=merged_transitions,
            mode="allow",
        )


@dataclass
class StructureMonitor:
    """Monitors tool-call structure against a ToolGraph in real-time.

    Usage:
        monitor = StructureMonitor(graph)
        monitor.check("tool_a")  # validates entry + records
        monitor.check("tool_b")  # validates transition + records
    """

    graph: ToolGraph
    _last_tool: str | None = field(default=None, repr=False)
    _call_sequence: list[str] = field(default_factory=list, repr=False)
    _violations: list[dict[str, Any]] = field(default_factory=list, repr=False)

    @property
    def call_sequence(self) -> tuple[str, ...]:
        return tuple(self._call_sequence)

    @property
    def violations(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._violations)

    @property
    def last_tool(self) -> str | None:
        return self._last_tool

    def check(self, tool_name: str) -> None:
        """Validate and record a tool call.

        Raises StructureViolationError if the transition is not allowed.
        """
        if self._last_tool is None:
            # First call — check entry point
            if not self.graph.is_entry_allowed(tool_name):
                violation = {
                    "from": None,
                    "to": tool_name,
                    "reason": "not_an_entry_point",
                }
                self._violations.append(violation)
                raise StructureViolationError(
                    None, tool_name, "not_an_entry_point"
                )
        else:
            # Subsequent call — check transition
            if not self.graph.is_transition_allowed(self._last_tool, tool_name):
                violation = {
                    "from": self._last_tool,
                    "to": tool_name,
                    "reason": "transition_not_allowed",
                }
                self._violations.append(violation)
                raise StructureViolationError(
                    self._last_tool,
                    tool_name,
                    "transition_not_allowed",
                )

        self._call_sequence.append(tool_name)
        self._last_tool = tool_name

    def reset(self) -> None:
        """Reset the monitor state (e.g., for a new request)."""
        self._last_tool = None
        self._call_sequence.clear()
        self._violations.clear()

    def snapshot(self) -> dict[str, Any]:
        """Return current state for audit/logging."""
        return {
            "call_sequence": list(self._call_sequence),
            "last_tool": self._last_tool,
            "violations": list(self._violations),
            "total_calls": len(self._call_sequence),
        }
