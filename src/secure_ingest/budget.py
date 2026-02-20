"""Request budget enforcement for agent tool-call pipelines.

Prevents amplification attacks (overthinking loops, forced-refinement cycles)
by enforcing per-request budgets on call counts and detecting structural
patterns in tool-call sequences.

Design principles:
- Stateless per-check (budget object tracks state, but each check is pure)
- Fail-closed: budget exhaustion = rejection, not silent passthrough
- Observable: all violations include structured context for audit

Informed by:
- "Overthinking Loops in MCP Agents" (2602.14798v1): cyclic tool-call
  patterns amplify token usage up to 142x
- "PCAS" (2602.16708v1): structural enforcement > runtime detection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class BudgetExhaustedError(Exception):
    """Raised when a request budget ceiling is exceeded."""

    def __init__(
        self,
        budget_type: str,
        limit: int,
        current: int,
        message: str = "",
    ) -> None:
        self.budget_type = budget_type
        self.limit = limit
        self.current = current
        super().__init__(
            message or f"Budget exhausted: {budget_type} ({current}/{limit})"
        )


class CycleDetectedError(Exception):
    """Raised when a cyclic tool-call pattern is detected."""

    def __init__(
        self,
        cycle: tuple[str, ...],
        occurrences: int,
        message: str = "",
    ) -> None:
        self.cycle = cycle
        self.occurrences = occurrences
        super().__init__(
            message
            or f"Cycle detected: {' -> '.join(cycle)} (repeated {occurrences}x)"
        )


@dataclass
class BudgetConfig:
    """Configuration for request budget enforcement.

    All limits are optional. None = no limit enforced for that dimension.
    """

    max_calls: int | None = None
    max_calls_per_tool: int | None = None
    max_cycle_repeats: int = 2
    min_cycle_length: int = 2
    max_cycle_length: int = 8

    def __post_init__(self) -> None:
        if self.max_calls is not None and self.max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        if self.max_calls_per_tool is not None and self.max_calls_per_tool < 1:
            raise ValueError("max_calls_per_tool must be >= 1")
        if self.max_cycle_repeats < 1:
            raise ValueError("max_cycle_repeats must be >= 1")
        if self.min_cycle_length < 2:
            raise ValueError("min_cycle_length must be >= 2")
        if self.max_cycle_length < self.min_cycle_length:
            raise ValueError("max_cycle_length must be >= min_cycle_length")


@dataclass
class RequestBudget:
    """Tracks and enforces budget for a single agent request.

    Usage:
        budget = RequestBudget(BudgetConfig(max_calls=10))
        budget.record("tool_a")  # OK
        budget.record("tool_b")  # OK
        ...
        budget.record("tool_a")  # raises BudgetExhaustedError if limit hit

    Call `record()` before each tool invocation. It raises on violation.
    Call `snapshot()` for current state without mutation.
    """

    config: BudgetConfig = field(default_factory=BudgetConfig)
    _call_sequence: list[str] = field(default_factory=list, repr=False)
    _tool_counts: dict[str, int] = field(default_factory=dict, repr=False)

    @property
    def total_calls(self) -> int:
        return len(self._call_sequence)

    @property
    def call_sequence(self) -> tuple[str, ...]:
        return tuple(self._call_sequence)

    @property
    def tool_counts(self) -> dict[str, int]:
        return dict(self._tool_counts)

    def record(self, tool_name: str) -> None:
        """Record a tool call and enforce budget limits.

        Raises BudgetExhaustedError if any call-count ceiling is exceeded.
        Raises CycleDetectedError if a repeating cycle pattern is found.
        """
        # Check total calls BEFORE recording (fail-closed: don't let it through)
        new_total = self.total_calls + 1
        if self.config.max_calls is not None and new_total > self.config.max_calls:
            raise BudgetExhaustedError("total_calls", self.config.max_calls, new_total)

        # Check per-tool calls
        new_tool_count = self._tool_counts.get(tool_name, 0) + 1
        if (
            self.config.max_calls_per_tool is not None
            and new_tool_count > self.config.max_calls_per_tool
        ):
            raise BudgetExhaustedError(
                f"calls_per_tool:{tool_name}",
                self.config.max_calls_per_tool,
                new_tool_count,
            )

        # Record the call
        self._call_sequence.append(tool_name)
        self._tool_counts[tool_name] = new_tool_count

        # Check for cycles after recording
        cycle = self._detect_cycle()
        if cycle is not None:
            pattern, count = cycle
            raise CycleDetectedError(pattern, count)

    def _detect_cycle(self) -> tuple[tuple[str, ...], int] | None:
        """Detect repeating patterns in the call sequence.

        Scans for patterns of length min_cycle_length..max_cycle_length
        that repeat more than max_cycle_repeats times at the tail of
        the sequence.
        """
        seq = self._call_sequence
        threshold = self.config.max_cycle_repeats

        for length in range(self.config.min_cycle_length, self.config.max_cycle_length + 1):
            if len(seq) < length * (threshold + 1):
                continue

            # Extract the candidate pattern from the tail
            pattern = tuple(seq[-length:])

            # Count consecutive repetitions going backward
            repeats = 1
            pos = len(seq) - length
            while pos >= length:
                window = tuple(seq[pos - length : pos])
                if window == pattern:
                    repeats += 1
                    pos -= length
                else:
                    break

            if repeats > threshold:
                return pattern, repeats

        return None

    def remaining(self) -> dict[str, int | None]:
        """Return remaining budget for each dimension."""
        result: dict[str, int | None] = {}

        if self.config.max_calls is not None:
            result["total_calls"] = self.config.max_calls - self.total_calls
        else:
            result["total_calls"] = None

        return result

    def snapshot(self) -> dict[str, Any]:
        """Return a snapshot of current budget state for audit/logging."""
        return {
            "total_calls": self.total_calls,
            "tool_counts": self.tool_counts,
            "call_sequence": list(self._call_sequence),
            "remaining": self.remaining(),
        }
