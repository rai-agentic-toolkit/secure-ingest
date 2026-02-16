"""Core parser — stateless, sandboxed content ingestion for AI agents.

Design principles:
- Stateless: no side effects, no persistence, pure function
- Sandboxed: no code execution, no network, no file I/O
- Deny-by-default: only explicitly allowed content passes
- Prompt injection resistant: strips/escapes injection patterns
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ContentType(Enum):
    """Supported content types for ingestion."""
    JSON = "json"
    TEXT = "text"
    MARKDOWN = "markdown"


class ParseError(Exception):
    """Raised when content fails validation."""

    def __init__(self, message: str, content_type: str | None = None,
                 violations: list[str] | None = None):
        super().__init__(message)
        self.content_type = content_type
        self.violations = violations or []


@dataclass(frozen=True)
class ParseResult:
    """Immutable result from parsing content."""
    content: Any
    content_type: ContentType
    sanitized: bool
    warnings: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)


# --- Prompt injection detection ---

# Patterns that indicate prompt injection attempts in agent-to-agent content.
# Deliberately broad — false positives are safer than false negatives.
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|above|prior|all)\b.{0,30}\b(?:instructions?|rules?|context|prompts?)\b"), "instruction_override"),
    (re.compile(r"(?i)\b(?:you are|act as|pretend|roleplay|simulate)\b.{0,30}\b(?:a|an|the|now)\b"), "role_hijack"),
    (re.compile(r"(?i)\b(?:system|assistant|user)\s*(?:prompt|message|:)"), "message_boundary"),
    (re.compile(r"(?i)<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>"), "chat_template"),
    (re.compile(r"(?i)\[(?:INST|SYS|/INST|/SYS)\]"), "instruction_tag"),
    (re.compile(r"(?i)#{1,3}\s*(?:system\s*(?:prompt|message|instruction)|new\s*(?:instruction|task|role))"), "header_injection"),
]

_MAX_TEXT_SIZE = 1_000_000    # 1MB
_MAX_JSON_SIZE = 10_000_000   # 10MB
_MAX_JSON_DEPTH = 50


def _check_injection(text: str) -> list[str]:
    """Check text for prompt injection patterns. Returns matched pattern names."""
    return [name for pattern, name in _INJECTION_PATTERNS if pattern.search(text)]


def _check_json_depth(obj: Any, max_depth: int = _MAX_JSON_DEPTH, _current: int = 0) -> None:
    """Raise ParseError if JSON nesting exceeds max depth."""
    if _current > max_depth:
        raise ParseError(
            f"JSON nesting depth exceeds maximum of {max_depth}",
            content_type="json",
            violations=["excessive_nesting"],
        )
    if isinstance(obj, dict):
        for v in obj.values():
            _check_json_depth(v, max_depth, _current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, max_depth, _current + 1)


def _strip_injection_from_text(text: str) -> tuple[str, list[str]]:
    """Strip injection patterns from text. Returns (cleaned_text, stripped_pattern_names)."""
    stripped = []
    cleaned = text
    for pattern, name in _INJECTION_PATTERNS:
        if pattern.search(cleaned):
            cleaned = pattern.sub("[REDACTED]", cleaned)
            stripped.append(name)
    return cleaned, stripped


def _scan_json_strings(obj: Any, warnings: list[str]) -> None:
    """Recursively scan JSON string values for injection patterns."""
    if isinstance(obj, str):
        for m in _check_injection(obj):
            warnings.append(f"injection_in_value:{m}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            for m in _check_injection(k):
                warnings.append(f"injection_in_key:{m}")
            _scan_json_strings(v, warnings)
    elif isinstance(obj, list):
        for item in obj:
            _scan_json_strings(item, warnings)


# --- Content type parsers ---

def _parse_json(raw: str | bytes, *, strict: bool = True) -> ParseResult:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_JSON_SIZE:
        raise ParseError("JSON exceeds max size", content_type="json", violations=["size_exceeded"])
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}", content_type="json", violations=["invalid_json"]) from e
    _check_json_depth(parsed)
    warnings: list[str] = []
    _scan_json_strings(parsed, warnings)
    return ParseResult(content=parsed, content_type=ContentType.JSON, sanitized=True, warnings=warnings)


def _parse_text(raw: str | bytes, *, strip_injections: bool = True) -> ParseResult:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_TEXT_SIZE:
        raise ParseError("Text exceeds max size", content_type="text", violations=["size_exceeded"])
    warnings: list[str] = []
    stripped: list[str] = []
    if strip_injections:
        matches = _check_injection(raw)
        if matches:
            raw, stripped = _strip_injection_from_text(raw)
            warnings.extend(f"stripped:{s}" for s in stripped)
    return ParseResult(content=raw, content_type=ContentType.TEXT, sanitized=True, warnings=warnings, stripped=stripped)


def _parse_markdown(raw: str | bytes, *, strip_injections: bool = True) -> ParseResult:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_TEXT_SIZE:
        raise ParseError("Markdown exceeds max size", content_type="markdown", violations=["size_exceeded"])
    warnings: list[str] = []
    stripped: list[str] = []
    # Strip HTML tags — deny by default
    html_pattern = re.compile(r"<[^>]+>")
    html_matches = html_pattern.findall(raw)
    if html_matches:
        raw = html_pattern.sub("", raw)
        stripped.append(f"html_tags({len(html_matches)})")
        warnings.append(f"stripped {len(html_matches)} HTML tags")
    if strip_injections:
        matches = _check_injection(raw)
        if matches:
            raw, inj_stripped = _strip_injection_from_text(raw)
            stripped.extend(inj_stripped)
            warnings.extend(f"stripped:{s}" for s in inj_stripped)
    return ParseResult(content=raw, content_type=ContentType.MARKDOWN, sanitized=True, warnings=warnings, stripped=stripped)


# --- Public API ---

def parse(
    content: str | bytes,
    content_type: ContentType | str = ContentType.TEXT,
    *,
    strict: bool = True,
    strip_injections: bool = True,
) -> ParseResult:
    """Parse and sanitize content for safe agent ingestion.

    Args:
        content: Raw content to parse (string or bytes).
        content_type: The type of content (json, text, markdown).
        strict: If True, raise on any validation failure.
        strip_injections: If True, strip detected prompt injection patterns.

    Returns:
        ParseResult with sanitized content and any warnings.

    Raises:
        ParseError: If content fails validation.

    Example:
        >>> from secure_ingest import parse, ContentType
        >>> result = parse('{"key": "value"}', ContentType.JSON)
        >>> result.content
        {'key': 'value'}
    """
    if isinstance(content_type, str):
        try:
            content_type = ContentType(content_type.lower())
        except ValueError:
            raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])

    if content_type == ContentType.JSON:
        return _parse_json(content, strict=strict)
    elif content_type == ContentType.TEXT:
        return _parse_text(content, strip_injections=strip_injections)
    elif content_type == ContentType.MARKDOWN:
        return _parse_markdown(content, strip_injections=strip_injections)
    else:
        raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])
