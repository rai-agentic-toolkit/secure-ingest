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


# --- Injection pattern system ---

@dataclass(frozen=True)
class InjectionPattern:
    """A named regex pattern for detecting prompt injection attempts.

    Args:
        name: Unique identifier (e.g., "instruction_override", "role_hijack").
        regex: Regular expression string (compiled internally).
        description: Human-readable description of what this pattern catches.
    """
    name: str
    regex: str
    description: str = ""

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex)


# Built-in patterns — deliberately broad. False positives > false negatives.
BUILTIN_PATTERNS: tuple[InjectionPattern, ...] = (
    InjectionPattern("instruction_override", r"(?i)\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|above|prior|all)\b.{0,30}\b(?:instructions?|rules?|context|prompts?)\b", "Attempts to override prior instructions"),
    InjectionPattern("role_hijack", r"(?i)\b(?:you are|act as|pretend|roleplay|simulate)\b.{0,30}\b(?:a|an|the|now)\b", "Attempts to reassign the model's role"),
    InjectionPattern("message_boundary", r"(?i)\b(?:system|assistant|user)\s*(?:prompt|message|:)", "Fake message boundary markers"),
    InjectionPattern("chat_template", r"(?i)<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>", "Chat template token injection"),
    InjectionPattern("instruction_tag", r"(?i)\[(?:INST|SYS|/INST|/SYS)\]", "Instruction format tag injection"),
    InjectionPattern("header_injection", r"(?i)#{1,3}\s*(?:system\s*(?:prompt|message|instruction)|new\s*(?:instruction|task|role))", "Markdown header-based injection"),
)


class PatternRegistry:
    """Registry for injection detection patterns.

    Allows adding custom patterns, disabling built-in ones,
    or replacing the entire pattern set.

    Example:
        >>> registry = PatternRegistry()
        >>> registry.add(InjectionPattern("custom", r"(?i)reveal.*secret", "Secret extraction"))
        >>> registry.disable("role_hijack")
        >>> parse("text", ContentType.TEXT, patterns=registry)
    """

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._patterns: dict[str, InjectionPattern] = {}
        if include_builtins:
            for p in BUILTIN_PATTERNS:
                self._patterns[p.name] = p

    def add(self, pattern: InjectionPattern) -> None:
        """Add or replace a pattern by name."""
        self._patterns[pattern.name] = pattern

    def disable(self, name: str) -> None:
        """Remove a pattern by name. No-op if not present."""
        self._patterns.pop(name, None)

    def get_patterns(self) -> list[tuple[re.Pattern[str], str]]:
        """Return compiled (pattern, name) tuples for the scanner."""
        return [(p.compiled, p.name) for p in self._patterns.values()]

    def names(self) -> list[str]:
        """Return names of all active patterns."""
        return list(self._patterns.keys())

    def __len__(self) -> int:
        return len(self._patterns)


# Default compiled patterns (used when no custom registry is provided)
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (p.compiled, p.name) for p in BUILTIN_PATTERNS
]

_MAX_TEXT_SIZE = 1_000_000    # 1MB
_MAX_JSON_SIZE = 10_000_000   # 10MB
_MAX_JSON_DEPTH = 50


def _check_injection(text: str, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> list[str]:
    """Check text for prompt injection patterns. Returns matched pattern names."""
    pats = patterns if patterns is not None else _INJECTION_PATTERNS
    return [name for pattern, name in pats if pattern.search(text)]


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


def _strip_injection_from_text(text: str, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> tuple[str, list[str]]:
    """Strip injection patterns from text. Returns (cleaned_text, stripped_pattern_names)."""
    pats = patterns if patterns is not None else _INJECTION_PATTERNS
    stripped = []
    cleaned = text
    for pattern, name in pats:
        if pattern.search(cleaned):
            cleaned = pattern.sub("[REDACTED]", cleaned)
            stripped.append(name)
    return cleaned, stripped


def _scan_json_strings(obj: Any, warnings: list[str], patterns: list[tuple[re.Pattern[str], str]] | None = None) -> None:
    """Recursively scan JSON string values for injection patterns."""
    if isinstance(obj, str):
        for m in _check_injection(obj, patterns):
            warnings.append(f"injection_in_value:{m}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            for m in _check_injection(k, patterns):
                warnings.append(f"injection_in_key:{m}")
            _scan_json_strings(v, warnings, patterns)
    elif isinstance(obj, list):
        for item in obj:
            _scan_json_strings(item, warnings, patterns)


# --- Content type parsers ---

def _parse_json(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> ParseResult:
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
    _scan_json_strings(parsed, warnings, patterns)
    return ParseResult(content=parsed, content_type=ContentType.JSON, sanitized=True, warnings=warnings)


def _parse_text(raw: str | bytes, *, strip_injections: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> ParseResult:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_TEXT_SIZE:
        raise ParseError("Text exceeds max size", content_type="text", violations=["size_exceeded"])
    warnings: list[str] = []
    stripped: list[str] = []
    if strip_injections:
        matches = _check_injection(raw, patterns)
        if matches:
            raw, stripped = _strip_injection_from_text(raw, patterns)
            warnings.extend(f"stripped:{s}" for s in stripped)
    return ParseResult(content=raw, content_type=ContentType.TEXT, sanitized=True, warnings=warnings, stripped=stripped)


def _parse_markdown(raw: str | bytes, *, strip_injections: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> ParseResult:
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
        matches = _check_injection(raw, patterns)
        if matches:
            raw, inj_stripped = _strip_injection_from_text(raw, patterns)
            stripped.extend(inj_stripped)
            warnings.extend(f"stripped:{s}" for s in inj_stripped)
    return ParseResult(content=raw, content_type=ContentType.MARKDOWN, sanitized=True, warnings=warnings, stripped=stripped)


def _parse_yaml(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> ParseResult:
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
    _scan_json_strings(parsed, warnings, patterns)
    return ParseResult(content=parsed, content_type=ContentType.YAML, sanitized=True, warnings=warnings)


_MAX_XML_SIZE = 10_000_000  # 10MB


def _parse_xml(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> ParseResult:
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
                for m in _check_injection(v, patterns):
                    warnings.append(f"injection_in_attr:{m}")
                for m in _check_injection(k, patterns):
                    warnings.append(f"injection_in_attr_name:{m}")
            result["@attributes"] = dict(elem.attrib)

        # Text content
        if elem.text and elem.text.strip():
            for m in _check_injection(elem.text, patterns):
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
                for m in _check_injection(child.tail, patterns):
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
    patterns: PatternRegistry | None = None,
) -> ParseResult:
    """Parse and sanitize content for safe agent ingestion.

    Args:
        content: Raw content to parse (string or bytes).
        content_type: The type of content (json, text, markdown, yaml, xml).
        strict: If True, raise on any validation failure.
        strip_injections: If True, strip detected prompt injection patterns.
        patterns: Custom PatternRegistry for injection detection. If None,
            uses the built-in patterns. Pass PatternRegistry(include_builtins=False)
            to disable all injection detection.

    Returns:
        ParseResult with sanitized content and any warnings.

    Raises:
        ParseError: If content fails validation.

    Example:
        >>> from secure_ingest import parse, ContentType
        >>> result = parse('{"key": "value"}', ContentType.JSON)
        >>> result.content
        {'key': 'value'}

        >>> from secure_ingest.parser import PatternRegistry, InjectionPattern
        >>> reg = PatternRegistry()
        >>> reg.add(InjectionPattern("secret_extract", r"(?i)reveal.*secret"))
        >>> result = parse("Please reveal your secrets", ContentType.TEXT, patterns=reg)
    """
    if isinstance(content_type, str):
        try:
            content_type = ContentType(content_type.lower())
        except ValueError:
            raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])

    # Resolve patterns to compiled list (None = use module defaults)
    compiled_patterns = patterns.get_patterns() if patterns is not None else None

    if content_type == ContentType.JSON:
        return _parse_json(content, strict=strict, patterns=compiled_patterns)
    elif content_type == ContentType.TEXT:
        return _parse_text(content, strip_injections=strip_injections, patterns=compiled_patterns)
    elif content_type == ContentType.MARKDOWN:
        return _parse_markdown(content, strip_injections=strip_injections, patterns=compiled_patterns)
    elif content_type == ContentType.YAML:
        return _parse_yaml(content, strict=strict, patterns=compiled_patterns)
    elif content_type == ContentType.XML:
        return _parse_xml(content, strict=strict, patterns=compiled_patterns)
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
