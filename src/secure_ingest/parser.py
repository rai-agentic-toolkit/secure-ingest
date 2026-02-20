"""Core parser — stateless, sandboxed content ingestion for AI agents.

Design principles:
- Stateless: no side effects, no persistence, pure function
- Sandboxed: no code execution, no network, no file I/O
- Deny-by-default: only explicitly allowed content passes
- Prompt injection resistant: strips/escapes injection patterns
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
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


class TaintLevel(Enum):
    """Taint level for tracking content trust through multi-agent flows.

    Levels (ordered by trust, lowest to highest):
    - UNTRUSTED: Raw content, not yet processed by secure-ingest.
    - SANITIZED: Processed by secure-ingest, injection patterns stripped/detected.
    - VALIDATED: Sanitized AND passed schema validation.
    """
    UNTRUSTED = "untrusted"
    SANITIZED = "sanitized"
    VALIDATED = "validated"

    def __lt__(self, other: "TaintLevel") -> bool:
        order = {TaintLevel.UNTRUSTED: 0, TaintLevel.SANITIZED: 1, TaintLevel.VALIDATED: 2}
        return order[self] < order[other]

    def __le__(self, other: "TaintLevel") -> bool:
        return self == other or self < other

    def __gt__(self, other: "TaintLevel") -> bool:
        return not self <= other

    def __ge__(self, other: "TaintLevel") -> bool:
        return not self < other


class ParseError(Exception):
    """Raised when content fails validation."""

    def __init__(self, message: str, content_type: str | None = None,
                 violations: list[str] | None = None):
        super().__init__(message)
        self.content_type = content_type
        self.violations = violations or []


def _compute_content_hash(content: Any) -> str:
    """Compute a SHA-256 digest of content for integrity verification.

    Deterministic: same content always produces the same hash,
    regardless of dict key ordering (uses sort_keys for JSON).
    """
    if isinstance(content, (str, bytes)):
        raw = content.encode("utf-8") if isinstance(content, str) else content
    else:
        raw = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ParseResult:
    """Immutable result from parsing content."""
    content: Any
    content_type: ContentType
    sanitized: bool
    warnings: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)
    taint: TaintLevel = TaintLevel.SANITIZED
    provenance: str = ""
    chain_id: str = ""
    content_hash: str = ""

    def verify(self) -> bool:
        """Verify content integrity against the stored hash.

        Returns True if the content hash matches, False if it doesn't.
        Returns True if no hash was set (backwards compatibility).
        """
        if not self.content_hash:
            return True
        return self.content_hash == _compute_content_hash(self.content)


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

@dataclass(frozen=True)
class Policy:
    """Structural policy enforcement for content ingestion.

    Policies compile security rules into the parse call itself — the PCAS
    principle of "structural enforcement over runtime detection." Instead of
    relying on consumers to check results, the policy prevents disallowed
    content from being parsed at all.

    Args:
        allowed_types: Set of ContentType values that are permitted.
            If None, all types are allowed. If set, any other type raises ParseError.
        max_depth: Maximum nesting depth for structured content (JSON, YAML, XML).
            Overrides the module default (50). Set to 0 for flat-only.
        max_size: Maximum content size in bytes. Overrides per-type defaults.
        require_schema: If True, parse() raises ParseError when no schema is provided
            for structured content types (JSON, YAML, XML).
        patterns: Custom PatternRegistry. Overrides the patterns parameter on parse().
        strip_injections: Whether to strip detected injection patterns from text content.

    Example:
        >>> policy = Policy(allowed_types={ContentType.JSON, ContentType.YAML},
        ...                 max_depth=10, require_schema=True)
        >>> parse('{"key": "value"}', "json", policy=policy, schema=my_schema)
    """
    allowed_types: frozenset[ContentType] | None = None
    max_depth: int | None = None
    max_size: int | None = None
    require_schema: bool = False
    patterns: PatternRegistry | None = None
    strip_injections: bool = True


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

def _parse_json(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None, max_depth: int | None = None) -> ParseResult:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > _MAX_JSON_SIZE:
        raise ParseError("JSON exceeds max size", content_type="json", violations=["size_exceeded"])
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}", content_type="json", violations=["invalid_json"]) from e
    _check_json_depth(parsed, max_depth=max_depth if max_depth is not None else _MAX_JSON_DEPTH)
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


def _parse_yaml(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None, max_depth: int | None = None) -> ParseResult:
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
    _check_json_depth(parsed, max_depth=max_depth if max_depth is not None else _MAX_JSON_DEPTH)

    warnings: list[str] = []
    _scan_json_strings(parsed, warnings, patterns)
    return ParseResult(content=parsed, content_type=ContentType.YAML, sanitized=True, warnings=warnings)


_MAX_XML_SIZE = 10_000_000  # 10MB


def _parse_xml(raw: str | bytes, *, strict: bool = True, patterns: list[tuple[re.Pattern[str], str]] | None = None, max_depth: int | None = None) -> ParseResult:
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
    _check_json_depth(parsed, max_depth=max_depth if max_depth is not None else _MAX_JSON_DEPTH)

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
    schema: Any | None = None,
    provenance: str = "",
    chain_id: str = "",
    policy: Policy | None = None,
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
        schema: A Schema instance to validate structured content against.
            Only applies to JSON, YAML, and XML content types.
            SchemaError is raised if validation fails.
        provenance: Source identifier for taint tracking (e.g., "agent-A",
            "api-gateway"). Propagated in the result for downstream consumers.
        chain_id: Correlation ID for tracking content through multi-hop flows.
            If empty, a new UUID is generated automatically.
        policy: A Policy instance for structural enforcement. When provided,
            the policy's settings override the corresponding parameters
            (patterns, strip_injections). Content type and schema requirements
            are enforced before parsing begins.

    Returns:
        ParseResult with sanitized content, taint metadata, and any warnings.

    Raises:
        ParseError: If content fails validation or violates the policy.
        SchemaError: If content fails schema validation.

    Example:
        >>> from secure_ingest import parse, ContentType
        >>> result = parse('{"key": "value"}', ContentType.JSON)
        >>> result.content
        {'key': 'value'}
        >>> result.taint
        <TaintLevel.SANITIZED: 'sanitized'>

        >>> from secure_ingest import Schema, Field, Policy
        >>> policy = Policy(allowed_types=frozenset({ContentType.JSON}), require_schema=True)
        >>> schema = Schema({"name": Field(str, required=True)})
        >>> result = parse('{"name": "Alice"}', ContentType.JSON, schema=schema, policy=policy)
        >>> result.taint
        <TaintLevel.VALIDATED: 'validated'>
    """
    if isinstance(content_type, str):
        try:
            content_type = ContentType(content_type.lower())
        except ValueError:
            raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])

    # --- Policy enforcement (structural, before any parsing) ---
    if policy is not None:
        # Type restriction
        if policy.allowed_types is not None and content_type not in policy.allowed_types:
            allowed = ", ".join(t.value for t in sorted(policy.allowed_types, key=lambda t: t.value))
            raise ParseError(
                f"Content type '{content_type.value}' not allowed by policy (allowed: {allowed})",
                content_type=content_type.value,
                violations=["policy_type_denied"],
            )

        # Schema requirement for structured types
        _structured_types = {ContentType.JSON, ContentType.YAML, ContentType.XML}
        if policy.require_schema and content_type in _structured_types and schema is None:
            raise ParseError(
                f"Policy requires schema validation for {content_type.value} content",
                content_type=content_type.value,
                violations=["policy_schema_required"],
            )

        # Size enforcement (check before parsing)
        raw_str = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        if policy.max_size is not None and len(raw_str.encode("utf-8")) > policy.max_size:
            raise ParseError(
                f"Content exceeds policy size limit ({policy.max_size} bytes)",
                content_type=content_type.value,
                violations=["policy_size_exceeded"],
            )

        # Policy overrides for patterns and strip_injections
        if policy.patterns is not None:
            patterns = policy.patterns
        strip_injections = policy.strip_injections

    # Resolve patterns to compiled list (None = use module defaults)
    compiled_patterns = patterns.get_patterns() if patterns is not None else None

    # Generate chain_id if not provided
    if not chain_id:
        chain_id = uuid.uuid4().hex[:12]

    # Override max depth if policy specifies it
    original_max_depth = _MAX_JSON_DEPTH
    if policy is not None and policy.max_depth is not None:
        # Temporarily patch the module-level depth for this call
        _override_depth = policy.max_depth
    else:
        _override_depth = None

    if content_type == ContentType.JSON:
        result = _parse_json(content, strict=strict, patterns=compiled_patterns, max_depth=_override_depth)
    elif content_type == ContentType.TEXT:
        result = _parse_text(content, strip_injections=strip_injections, patterns=compiled_patterns)
    elif content_type == ContentType.MARKDOWN:
        result = _parse_markdown(content, strip_injections=strip_injections, patterns=compiled_patterns)
    elif content_type == ContentType.YAML:
        result = _parse_yaml(content, strict=strict, patterns=compiled_patterns, max_depth=_override_depth)
    elif content_type == ContentType.XML:
        result = _parse_xml(content, strict=strict, patterns=compiled_patterns, max_depth=_override_depth)
    else:
        raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])

    # Determine taint level
    taint = TaintLevel.SANITIZED

    # Schema validation (only for structured types that produce dicts)
    if schema is not None and isinstance(result.content, dict):
        schema.validate(result.content)
        taint = TaintLevel.VALIDATED

    # Return result with taint metadata and integrity hash
    return ParseResult(
        content=result.content,
        content_type=result.content_type,
        sanitized=result.sanitized,
        warnings=result.warnings,
        stripped=result.stripped,
        taint=taint,
        provenance=provenance,
        chain_id=chain_id,
        content_hash=_compute_content_hash(result.content),
    )


def compose(*results: ParseResult, chain_id: str = "") -> ParseResult:
    """Safely combine multiple ParseResults with taint propagation.

    The composed result has:
    - taint: minimum taint level across all inputs (least trusted wins)
    - provenance: comma-separated list of all input provenances
    - chain_id: shared chain_id (new UUID if not provided)
    - content: list of all input contents
    - warnings: merged from all inputs
    - stripped: merged from all inputs

    Args:
        *results: Two or more ParseResult instances to combine.
        chain_id: Shared chain ID for the composed result.
            If empty, generates a new one.

    Returns:
        A new ParseResult combining all inputs.

    Raises:
        ValueError: If fewer than 2 results are provided.

    Example:
        >>> r1 = parse('{"a": 1}', "json", provenance="agent-a")
        >>> r2 = parse("hello", "text", provenance="agent-b")
        >>> combined = compose(r1, r2)
        >>> combined.taint  # min of both
        <TaintLevel.SANITIZED: 'sanitized'>
    """
    if len(results) < 2:
        raise ValueError("compose() requires at least 2 ParseResults")

    if not chain_id:
        chain_id = uuid.uuid4().hex[:12]

    # Taint = minimum (least trusted wins)
    taint = min(results, key=lambda r: r.taint).taint

    # Merge provenance (deduplicated, ordered)
    seen: set[str] = set()
    provenances: list[str] = []
    for r in results:
        if r.provenance and r.provenance not in seen:
            provenances.append(r.provenance)
            seen.add(r.provenance)
    provenance = ",".join(provenances)

    # Merge warnings and stripped
    all_warnings: list[str] = []
    all_stripped: list[str] = []
    for r in results:
        all_warnings.extend(r.warnings)
        all_stripped.extend(r.stripped)

    # Content is a list of all contents
    contents = [r.content for r in results]

    return ParseResult(
        content=contents,
        content_type=results[0].content_type,
        sanitized=all(r.sanitized for r in results),
        warnings=all_warnings,
        stripped=all_stripped,
        taint=taint,
        provenance=provenance,
        chain_id=chain_id,
        content_hash=_compute_content_hash(contents),
    )


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
