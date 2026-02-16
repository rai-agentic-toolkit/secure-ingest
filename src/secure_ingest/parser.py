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
    YAML = "yaml"
    XML = "xml"


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


def _parse_yaml(raw: str | bytes, *, strict: bool = True) -> ParseResult:
    """Parse YAML content with depth limits and injection scanning.

    Uses PyYAML safe_load (no arbitrary Python object construction).
    Falls back to treating as text if PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError:
        raise ParseError(
            "PyYAML is required for YAML parsing: pip install secure-ingest[yaml]",
            content_type="yaml",
            violations=["missing_dependency"],
        )

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_JSON_SIZE:  # Same size limit as JSON
        raise ParseError("YAML exceeds max size", content_type="yaml", violations=["size_exceeded"])

    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ParseError(f"Invalid YAML: {e}", content_type="yaml", violations=["invalid_yaml"]) from e

    # YAML can parse scalars — ensure we got a container or wrap it
    if parsed is None:
        parsed = {}

    # Depth check (YAML can be deeply nested too)
    _check_json_depth(parsed)

    warnings: list[str] = []
    _scan_json_strings(parsed, warnings)
    return ParseResult(content=parsed, content_type=ContentType.YAML, sanitized=True, warnings=warnings)


_MAX_XML_SIZE = 10_000_000  # 10MB


def _parse_xml(raw: str | bytes, *, strict: bool = True) -> ParseResult:
    """Parse XML content with XXE protection and injection scanning.

    Security measures:
    - Disables external entity resolution (XXE protection)
    - Disables DTD processing
    - Enforces size limits
    - Scans text content for injection patterns
    """
    import xml.etree.ElementTree as ET
    from xml.parsers.expat import ExpatError

    if isinstance(raw, bytes):
        raw_str = raw.decode("utf-8", errors="replace")
    else:
        raw_str = raw

    if len(raw_str) > _MAX_XML_SIZE:
        raise ParseError("XML exceeds max size", content_type="xml", violations=["size_exceeded"])

    # Reject DOCTYPE declarations entirely — this prevents XXE, billion laughs, etc.
    if re.search(r"<!DOCTYPE", raw_str, re.IGNORECASE):
        raise ParseError(
            "DOCTYPE declarations are not allowed (XXE protection)",
            content_type="xml",
            violations=["doctype_forbidden"],
        )

    try:
        root = ET.fromstring(raw_str)
    except ET.ParseError as e:
        raise ParseError(f"Invalid XML: {e}", content_type="xml", violations=["invalid_xml"]) from e
    except ExpatError as e:
        raise ParseError(f"Invalid XML: {e}", content_type="xml", violations=["invalid_xml"]) from e

    warnings: list[str] = []

    def _element_to_dict(elem: ET.Element) -> dict:
        """Convert XML element tree to dict, scanning for injections."""
        result: dict = {}
        # Attributes
        if elem.attrib:
            for k, v in elem.attrib.items():
                for m in _check_injection(v):
                    warnings.append(f"injection_in_attr:{m}")
                for m in _check_injection(k):
                    warnings.append(f"injection_in_attr_name:{m}")
            result["@attributes"] = dict(elem.attrib)

        # Text content
        if elem.text and elem.text.strip():
            for m in _check_injection(elem.text):
                warnings.append(f"injection_in_text:{m}")
            result["#text"] = elem.text.strip()

        # Child elements
        for child in elem:
            child_dict = _element_to_dict(child)
            tag = child.tag
            # Strip namespace prefixes for cleaner output
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            if tag in result:
                # Multiple children with same tag → list
                existing = result[tag]
                if not isinstance(existing, list):
                    result[tag] = [existing]
                result[tag].append(child_dict)
            else:
                result[tag] = child_dict

            # Tail text (text after child element)
            if child.tail and child.tail.strip():
                for m in _check_injection(child.tail):
                    warnings.append(f"injection_in_text:{m}")

        return result

    parsed = _element_to_dict(root)
    # Check depth of the resulting dict
    _check_json_depth(parsed)

    # Include root tag in result
    root_tag = root.tag
    if "}" in root_tag:
        root_tag = root_tag.split("}", 1)[1]
    content = {root_tag: parsed}

    return ParseResult(content=content, content_type=ContentType.XML, sanitized=True, warnings=warnings)


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
    elif content_type == ContentType.YAML:
        return _parse_yaml(content, strict=strict)
    elif content_type == ContentType.XML:
        return _parse_xml(content, strict=strict)
    else:
        raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])


@dataclass
class ParserConfig:
    """Configuration for the ContentParser."""
    strict: bool = True
    strip_injections: bool = True


@dataclass
class ContentParserResult:
    """Result type expected by the ingestion pipeline."""
    success: bool
    parsed_content: dict[str, Any] | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


class ContentParser:
    """Object-oriented parser interface for the ingestion pipeline.

    Wraps the module-level parse() function in the interface that
    IngestionPipeline expects.
    """

    def __init__(self, config: ParserConfig | None = None) -> None:
        self._config = config or ParserConfig()

    def parse(self, raw_content: str, content_type: str) -> ContentParserResult:
        """Parse raw content and return a pipeline-compatible result."""
        if not raw_content:
            return ContentParserResult(
                success=False,
                error="empty content",
            )

        # Map pipeline content types to parser content types.
        # The pipeline uses domain names like "security_finding";
        # all of those are JSON payloads.
        parser_type = self._resolve_content_type(content_type)

        try:
            result = parse(
                raw_content,
                parser_type,
                strict=self._config.strict,
                strip_injections=self._config.strip_injections,
            )
            # For JSON content, .content is already a dict.
            # For text/markdown, wrap it so downstream expects dict.
            parsed = result.content
            if not isinstance(parsed, dict):
                parsed = {"content": parsed, "_content_type": content_type}

            return ContentParserResult(
                success=True,
                parsed_content=parsed,
                warnings=list(result.warnings),
            )
        except ParseError as e:
            return ContentParserResult(
                success=False,
                error=str(e),
            )

    @staticmethod
    def _resolve_content_type(content_type: str) -> str:
        """Map pipeline content type names to parser content types."""
        # Known JSON-based types from the schema registry
        json_types = {"security_finding", "analysis_report"}
        if content_type in json_types:
            return "json"
        # Known YAML-based types
        yaml_types = {"config", "pipeline_config", "ci_config"}
        if content_type in yaml_types:
            return "yaml"
        # Known XML-based types
        xml_types = {"feed", "rss", "atom", "soap_message"}
        if content_type in xml_types:
            return "xml"
        # If it matches a known ContentType value, pass through
        try:
            ContentType(content_type.lower())
            return content_type.lower()
        except ValueError:
            # Default: treat unknown types as JSON (the pipeline validates schema later)
            return "json"
