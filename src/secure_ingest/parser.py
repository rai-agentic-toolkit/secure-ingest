"""Stateless sandboxed content parser.

Converts raw text content into structured data using strict extraction rules.
This parser has NO capabilities: no tools, no memory, no network access.
Each invocation is completely isolated.

Design principle: even if a prompt injection succeeds at manipulating the
parser's LLM, the output is still constrained to the predefined schema.
Since no real LLM is required for the MVP, this module implements a
deterministic JSON extraction parser that enforces the same architectural
guarantees.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ParseResult:
    """Immutable result from a parse operation."""

    success: bool
    parsed_content: dict[str, Any] | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParserConfig:
    """Parser configuration - capabilities are always empty."""

    max_content_bytes: int = 1_048_576  # 1 MB
    max_parse_time_seconds: float = 30.0
    # Security constraints (not configurable - always enforced)
    tools: tuple = ()          # No tools
    memory: bool = False       # Stateless
    network_access: bool = False  # No network


class ContentParser:
    """Stateless content parser with no capabilities.

    Each call to parse() is independent - no state carries over between calls.
    The parser can only produce JSON matching a predefined structure.
    """

    def __init__(self, config: ParserConfig | None = None) -> None:
        self._config = config or ParserConfig()

    def parse(self, raw_content: str, content_type: str) -> ParseResult:
        """Parse raw content into structured data.

        This is a deterministic extraction: find JSON in the input, parse it,
        and return it. No LLM is used in the MVP - this enforces the same
        architectural guarantee that the parser can only produce structured
        output and cannot take actions.
        """
        start = time.monotonic()

        # Enforce size limit
        if len(raw_content.encode("utf-8", errors="replace")) > self._config.max_content_bytes:
            return ParseResult(
                success=False,
                error="content_too_large",
                metadata={"max_bytes": self._config.max_content_bytes},
            )

        if not raw_content.strip():
            return ParseResult(success=False, error="empty_content")

        # Try to extract JSON from the content
        parsed = self._extract_json(raw_content)
        elapsed = time.monotonic() - start

        if elapsed > self._config.max_parse_time_seconds:
            return ParseResult(success=False, error="timeout")

        if parsed is None:
            return ParseResult(
                success=False,
                error="no_json_found",
                metadata={"parse_time": elapsed},
            )

        if not isinstance(parsed, dict):
            return ParseResult(
                success=False,
                error="expected_object",
                metadata={"parse_time": elapsed, "got_type": type(parsed).__name__},
            )

        return ParseResult(
            success=True,
            parsed_content=parsed,
            metadata={
                "parse_time": elapsed,
                "content_type": content_type,
                "parser_version": "0.1.0",
            },
        )

    def _extract_json(self, text: str) -> Any:
        """Extract JSON from text content.

        Tries the full text first, then looks for JSON embedded in the text.
        """
        # Try parsing the entire text as JSON
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Look for JSON object embedded in text (find first { ... last })
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

        # Look for JSON array embedded in text
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass

        return None
