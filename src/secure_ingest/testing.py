"""Test utilities for secure-ingest.

Makes it easy to construct ``ParseResult`` objects in tests without running
the full parse pipeline. This matters because downstream functions often
accept ``ParseResult`` and you don't want every unit test to depend on the
parser internals.

Usage::

    from secure_ingest.testing import make_validated_result, make_sanitized_result

    def test_my_handler():
        result = make_validated_result({"user_id": 1, "query": "hello"})
        assert my_handler(result) == "expected output"

    def test_my_handler_rejects_sanitized():
        result = make_sanitized_result("raw text")
        with pytest.raises(ParseError):
            my_strict_handler(result)  # decorated with @require_validated
"""

from __future__ import annotations

import types
import uuid
from typing import Any

from .parser import ContentType, ParseResult, TaintLevel, content_hash_of


def _deep_freeze(content: dict[str, Any] | Any) -> Any:
    """Recursively freeze dicts/lists for VALIDATED results."""
    if isinstance(content, dict):
        return types.MappingProxyType({k: _deep_freeze(v) for k, v in content.items()})
    if isinstance(content, list):
        return tuple(_deep_freeze(item) for item in content)
    return content


def make_validated_result(
    content: dict[str, Any] | Any,
    *,
    content_type: ContentType = ContentType.JSON,
    provenance: str = "testing",
    chain_id: str | None = None,
    warnings: list[str] | None = None,
) -> ParseResult:
    """Build a ``ParseResult`` with ``TaintLevel.VALIDATED`` without parsing.

    Content is deep-frozen (``MappingProxyType`` for dicts, ``tuple`` for lists)
    to match the guarantee real VALIDATED results carry.

    Args:
        content: The content to place in the result — typically a dict.
        content_type: Defaults to ``ContentType.JSON``.
        provenance: Origin label. Defaults to ``"testing"``.
        chain_id: Correlation ID. Auto-generated if not provided.
        warnings: Any warnings to attach. Defaults to empty list.

    Returns:
        ``ParseResult`` with ``taint=TaintLevel.VALIDATED``.
    """
    frozen = _deep_freeze(content) if isinstance(content, dict | list) else content
    return ParseResult(
        content=frozen,
        content_type=content_type,
        sanitized=True,
        warnings=warnings or [],
        stripped=[],
        taint=TaintLevel.VALIDATED,
        provenance=provenance,
        chain_id=chain_id or uuid.uuid4().hex[:12],
        content_hash=content_hash_of(content),
    )


def make_sanitized_result(
    content: Any,
    *,
    content_type: ContentType = ContentType.TEXT,
    provenance: str = "testing",
    chain_id: str | None = None,
    warnings: list[str] | None = None,
    stripped: list[str] | None = None,
) -> ParseResult:
    """Build a ``ParseResult`` with ``TaintLevel.SANITIZED`` without parsing.

    Use this when testing code that must *reject* SANITIZED results
    (e.g., functions decorated with ``@require_validated``).

    Args:
        content: The content to place in the result.
        content_type: Defaults to ``ContentType.TEXT``.
        provenance: Origin label. Defaults to ``"testing"``.
        chain_id: Correlation ID. Auto-generated if not provided.
        warnings: Warnings list. Defaults to empty.
        stripped: Stripped pattern names. Defaults to empty.

    Returns:
        ``ParseResult`` with ``taint=TaintLevel.SANITIZED``.
    """
    return ParseResult(
        content=content,
        content_type=content_type,
        sanitized=True,
        warnings=warnings or [],
        stripped=stripped or [],
        taint=TaintLevel.SANITIZED,
        provenance=provenance,
        chain_id=chain_id or uuid.uuid4().hex[:12],
        content_hash=content_hash_of(content),
    )
