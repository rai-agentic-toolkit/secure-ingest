"""Core parser — strict payload validation and structural hygiene layer for Python.

Design principles:
- Stateless: no side effects, no persistence, pure function
- Isolated: no code execution, no network, no file I/O
- Deny-by-default: only explicitly allowed content passes
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import re
import types
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Type
from pydantic import BaseModel, ValidationError
from .rules import ValueRule

from .semantic import SemanticValidator, BaseSemanticScanner


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
    """Base class for all parse/validation failures.

    All subclasses expose `.content_type` and `.violations` so existing
    ``except ParseError`` handlers continue to work unchanged.
    """

    def __init__(self, message: str, content_type: str | None = None,
                 violations: list[str] | None = None):
        super().__init__(message)
        self.content_type = content_type
        self.violations = violations or []


class SizeExceededError(ParseError):
    """Content exceeds the configured byte-size limit."""

    def __init__(self, limit: int, actual: int, content_type: str | None = None):
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"Content exceeds size limit ({actual} > {limit} bytes)",
            content_type=content_type,
            violations=["policy_size_exceeded"],
        )


class DepthExceededError(ParseError):
    """Structured content nesting exceeds the configured depth limit."""

    def __init__(self, max_depth: int, content_type: str | None = None):
        self.max_depth = max_depth
        super().__init__(
            f"JSON nesting depth exceeds maximum of {max_depth}",
            content_type=content_type or "json",
            violations=["excessive_nesting"],
        )


class SchemaValidationError(ParseError):
    """Content failed Pydantic schema validation."""

    def __init__(self, pydantic_errors: list[dict], content_type: str | None = None):
        self.pydantic_errors = pydantic_errors
        violations = [f"schema_violation:{err['loc'][0]}_{err['msg']}" for err in pydantic_errors]
        super().__init__(
            f"Content failed schema validation ({len(pydantic_errors)} error(s))",
            content_type=content_type,
            violations=violations,
        )


class SemanticRejectedError(ParseError):
    """Content was rejected by one or more SemanticValidator instances."""

    def __init__(self, rejected_by: list[str], content_type: str | None = None):
        self.rejected_by = rejected_by
        super().__init__(
            f"Content rejected by semantic validator(s): {', '.join(rejected_by)}",
            content_type=content_type,
            violations=[f"semantic_validator_rejected:{name}" for name in rejected_by],
        )


class PolicyTypeError(ParseError):
    """Content type is not permitted by the active StrictPolicy."""

    def __init__(self, attempted: str, allowed: list[str]):
        self.attempted = attempted
        self.allowed = allowed
        allowed_str = ", ".join(sorted(allowed))
        super().__init__(
            f"Content type '{attempted}' not allowed by policy (allowed: {allowed_str})",
            content_type=attempted,
            violations=["policy_type_denied"],
        )


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


def _deep_freeze(obj: Any) -> Any:
    """Recursively wrap all dicts in MappingProxyType, tuples for lists.

    Guarantees that no nested structure can be mutated after content is
    promoted to VALIDATED taint. One-level MappingProxyType is not enough
    because nested dicts are still regular, mutable djects.
    """
    if isinstance(obj, dict):
        return types.MappingProxyType({k: _deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return tuple(_deep_freeze(item) for item in obj)
    return obj



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

    def as_validated(self) -> "ParseResult":
        """Return self if taint level is VALIDATED, otherwise raise ParseError.

        Use this to assert trust at a boundary without manually checking
        ``result.taint == TaintLevel.VALIDATED``::

            safe = parse(raw, ContentType.JSON, schema=MySchema).as_validated()
            # safe.content is guaranteed to be a frozen MappingProxyType

        Raises:
            ParseError: if taint < VALIDATED (no schema was applied, or
                        content was only structurally sanitized).
        """
        if self.taint < TaintLevel.VALIDATED:
            raise ParseError(
                f"ParseResult has taint level {self.taint.name}, expected VALIDATED. "
                "Pass a Pydantic schema to parse() to promote to VALIDATED.",
                content_type=self.content_type.value if self.content_type else None,
                violations=["insufficient_taint"],
            )
        return self


# --- @require_validated decorator ---

def require_validated(func):
    """Decorator that asserts the first ParseResult argument is VALIDATED.

    Enforces taint-level contracts at function boundaries without
    boilerplate ``if result.taint < TaintLevel.VALIDATED: raise ...``::

        @require_validated
        def call_llm(result: ParseResult) -> str:
            return openai.chat(str(result.content))  # guaranteed VALIDATED

        @require_validated
        async def async_handler(result: ParseResult) -> dict:
            ...

    Raises ParseError (insufficient_taint) if the first positional argument
    whose type annotation is ParseResult has taint < VALIDATED.
    """
    @functools.wraps(func)
    def _sync_wrapper(*args, **kwargs):
        _enforce_validated(func, args, kwargs)
        return func(*args, **kwargs)

    @functools.wraps(func)
    async def _async_wrapper(*args, **kwargs):
        _enforce_validated(func, args, kwargs)
        return await func(*args, **kwargs)

    return _async_wrapper if inspect.iscoroutinefunction(func) else _sync_wrapper


def _enforce_validated(func, args, kwargs):
    """Check that any ParseResult arg/kwarg has VALIDATED taint."""
    params = list(inspect.signature(func).parameters.keys())

    # Check positional args
    for i, (name, val) in enumerate(zip(params, args)):
        if isinstance(val, ParseResult):
            if val.taint < TaintLevel.VALIDATED:
                raise ParseError(
                    f"Argument '{name}' passed to {func.__name__}() has taint level "
                    f"{val.taint.name}; @require_validated requires VALIDATED. "
                    "Pass a Pydantic schema to parse() to promote.",
                    violations=["insufficient_taint"],
                )
    # Check keyword args
    for name, val in kwargs.items():
        if isinstance(val, ParseResult):
            if val.taint < TaintLevel.VALIDATED:
                raise ParseError(
                    f"Argument '{name}' passed to {func.__name__}() has taint level "
                    f"{val.taint.name}; @require_validated requires VALIDATED.",
                    violations=["insufficient_taint"],
                )



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

    def get_all(self) -> list[InjectionPattern]:
        """Return all active InjectionPattern instances."""
        return list(self._patterns.values())

    def __len__(self) -> int:
        return len(self._patterns)


# Default compiled patterns (used when no custom registry is provided)
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (p.compiled, p.name) for p in BUILTIN_PATTERNS
]

@dataclass(frozen=True)
class StrictPolicy:
    """Strict structural policy enforcement for content ingestion.

    Forces security-first defaults: size/depth bounding, value rules,
    and optional pluggable semantic validators.
    """
    allowed_types: frozenset[ContentType]
    max_size_bytes: int
    max_depth: int
    schema: type[BaseModel] | None = None
    mutation_mode: str = "IGNORE" # "IGNORE", "STRIP_AND_WARN", or "REJECT"
    value_rules: tuple[ValueRule, ...] = ()
    patterns: PatternRegistry | None = None
    semantic_validators: tuple[SemanticValidator, ...] = ()

    def __post_init__(self):
        if self.max_size_bytes > 1024 * 1024:
            import logging
            logging.getLogger(__name__).warning(
                "StrictPolicy allows payloads > 1MB. Ensure downstream LLM context can handle this."
            )

    @staticmethod
    def compose(*policies: "StrictPolicy") -> "StrictPolicy":
        if len(policies) < 2:
            raise ValueError("StrictPolicy.compose() requires at least 2 policies")

        type_sets = [p.allowed_types for p in policies]
        allowed_types = type_sets[0]
        for ts in type_sets[1:]:
            allowed_types = allowed_types & ts
        if not allowed_types:
            raise ValueError("StrictPolicy.compose() resulted in empty allowed_types")

        max_depth = min(p.max_depth for p in policies)
        max_size_bytes = min(p.max_size_bytes for p in policies)

        schemas = [p.schema for p in policies if p.schema is not None]
        schema = schemas[0] if schemas else None

        modes = {p.mutation_mode for p in policies}
        mutation_mode = "REJECT" if "REJECT" in modes else "STRIP_AND_WARN"

        seen_rules = {}
        for p in policies:
            for rule in p.value_rules:
                seen_rules[rule.name] = rule
        value_rules = tuple(seen_rules.values())

        registries = [p.patterns for p in policies if p.patterns is not None]
        if not registries:
            merged_patterns = None
        else:
            merged_patterns = PatternRegistry(include_builtins=False)
            for reg in registries:
                for pat in reg.get_all():
                    merged_patterns.add(pat)

        # Merge semantic validators (union — all validators from all policies)
        seen_validators: list[SemanticValidator] = []
        seen_validator_ids: set[int] = set()
        for p in policies:
            for v in p.semantic_validators:
                if id(v) not in seen_validator_ids:
                    seen_validators.append(v)
                    seen_validator_ids.add(id(v))

        return StrictPolicy(
            allowed_types=frozenset(allowed_types),
            max_size_bytes=max_size_bytes,
            max_depth=max_depth,
            schema=schema,
            mutation_mode=mutation_mode,
            value_rules=value_rules,
            patterns=merged_patterns,
            semantic_validators=tuple(seen_validators),
        )


_MAX_SIZE_BYTES = 10_000_000  # 10MB
_MAX_JSON_DEPTH = 50


def _check_injection(text: str, patterns: list[tuple[re.Pattern[str], str]] | None = None) -> list[str]:
    """Check text for prompt injection patterns. Returns matched pattern names."""
    pats = patterns if patterns is not None else _INJECTION_PATTERNS
    return [name for pattern, name in pats if pattern.search(text)]


def _check_json_depth(obj: Any, max_depth: int = _MAX_JSON_DEPTH, _current: int = 0) -> None:
    """Raise DepthExceededError if JSON nesting exceeds max depth."""
    if _current > max_depth:
        raise DepthExceededError(max_depth=max_depth, content_type="json")
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
    """Parse XML content safely using defusedxml."""
    import defusedxml.ElementTree as ET
    from xml.parsers.expat import ExpatError

    if isinstance(raw, bytes):
        raw_str = raw.decode("utf-8", errors="replace")
    else:
        raw_str = raw

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
    patterns: PatternRegistry | None = None,
    schema: type[BaseModel] | None = None,
    semantic_scanner: BaseSemanticScanner | None = None,
    provenance: str = "",
    chain_id: str = "",
    policy: StrictPolicy | None = None,
    mutation_mode: str = "IGNORE",
) -> ParseResult:
    """Parse and sanitize content for safe agent ingestion.
    """
    if isinstance(content_type, str):
        try:
            content_type = ContentType(content_type.lower())
        except ValueError:
            raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])

    # --- StrictPolicy enforcement (structural, before any parsing) ---
    if policy is not None:
        if content_type not in policy.allowed_types:
            raise PolicyTypeError(
                attempted=content_type.value,
                allowed=[t.value for t in policy.allowed_types],
            )

        _structured_types = {ContentType.JSON, ContentType.YAML, ContentType.XML}
        if content_type in _structured_types and policy.schema is not None and schema is None:
            schema = policy.schema

        max_size = policy.max_size_bytes
    else:
        max_size = _MAX_SIZE_BYTES

    size_bytes = len(content) if isinstance(content, bytes) else len(content.encode("utf-8"))
    if size_bytes > max_size:
        raise SizeExceededError(limit=max_size, actual=size_bytes, content_type=content_type.value)

    if policy is not None:
        if policy.patterns is not None:
            patterns = policy.patterns
        
        mutation_mode = policy.mutation_mode
        
    check_injections = (mutation_mode != "IGNORE")

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
        result = _parse_text(content, strip_injections=check_injections, patterns=compiled_patterns)
    elif content_type == ContentType.MARKDOWN:
        result = _parse_markdown(content, strip_injections=check_injections, patterns=compiled_patterns)
    elif content_type == ContentType.YAML:
        result = _parse_yaml(content, strict=strict, patterns=compiled_patterns, max_depth=_override_depth)
    elif content_type == ContentType.XML:
        result = _parse_xml(content, strict=strict, patterns=compiled_patterns, max_depth=_override_depth)
    else:
        raise ParseError(f"Unsupported content type: {content_type}", violations=["unsupported_type"])


    if mutation_mode == "REJECT" and result.stripped:
        raise ParseError(
            f"Content denied by StrictPolicy: injection pattern matched",
            content_type=content_type.value,
            violations=[f"policy_pattern:{pat}" for pat in result.stripped]
        )

    # Determine taint level
    taint = TaintLevel.SANITIZED

    # Schema validation (only for structured types that produce dicts)
    if schema is not None and isinstance(result.content, dict):
        try:
            parsed_model = schema.model_validate(result.content, strict=schema.model_config.get("strict", False))
            # Deep-freeze: recursively wrap all nested dicts in MappingProxyType
            # so no nested structure can be mutated after VALIDATED promotion.
            frozen_content = _deep_freeze(parsed_model.model_dump())
            result = ParseResult(
                content=frozen_content,
                content_type=result.content_type,
                sanitized=result.sanitized,
                warnings=result.warnings,
                stripped=result.stripped,
                taint=taint,
                provenance=provenance,
                chain_id=chain_id,
                content_hash=_compute_content_hash(result.content),
            )
            taint = TaintLevel.VALIDATED
        except ValidationError as e:
            raise SchemaValidationError(
                pydantic_errors=e.errors(),
                content_type=content_type.value,
            ) from e

    # Collect semantic validators: explicit arg + policy-level validators
    _all_semantic_validators: list[SemanticValidator] = []
    if semantic_scanner is not None:
        _all_semantic_validators.append(semantic_scanner)  # backward compat
    if policy is not None:
        _all_semantic_validators.extend(policy.semantic_validators)

    if _all_semantic_validators:
        # Build a text representation to validate against
        if isinstance(result.content, str):
            _text_repr = result.content
        else:
            _text_repr = json.dumps(
                dict(result.content) if isinstance(result.content, types.MappingProxyType) else result.content,
                default=str,
            )
        new_warnings = list(result.warnings)
        new_stripped = list(result.stripped)
        rejected_by: list[str] = []
        for validator in _all_semantic_validators:
            # Support both old scan() interface and new validate() Protocol
            if hasattr(validator, "validate"):
                passed = validator.validate(_text_repr)
                if not passed:
                    rejected_by.append(type(validator).__name__)
            elif hasattr(validator, "scan"):
                # Legacy BaseSemanticScanner with scan() returning violation list
                violations = validator.scan(_text_repr)
                if violations:
                    new_warnings.extend([f"semantic_violation:{v}" for v in violations])
                    new_stripped.extend(violations)
        if rejected_by:
            raise SemanticRejectedError(rejected_by=rejected_by, content_type=content_type.value)
        result = ParseResult(
            content=result.content,
            content_type=result.content_type,
            sanitized=result.sanitized,
            warnings=new_warnings,
            stripped=new_stripped,
            taint=result.taint,
            provenance=result.provenance,
            chain_id=result.chain_id,
            content_hash=result.content_hash,
        )
        
    # ValueRule enforcement (after parsing structure)
    if policy is not None and policy.value_rules:
        violations = []
        allow_rules = [r for r in policy.value_rules if r.action == "ALLOW"]
        deny_rules = [r for r in policy.value_rules if r.action == "DENY"]
        allow_matched = {r.name: False for r in allow_rules}

        def _scan_vals(obj, path="root"):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _scan_vals(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    _scan_vals(v, f"{path}[{i}]")
            elif isinstance(obj, str):
                for rule in deny_rules:
                    if rule.compiled.search(obj):
                        violations.append(f"policy_deny:{rule.name} at {path}")
                for rule in allow_rules:
                    if rule.compiled.search(obj):
                        allow_matched[rule.name] = True

        _scan_vals(result.content)

        for rule in allow_rules:
            if not allow_matched[rule.name]:
                violations.append(f"policy_allow:{rule.name} missed in content")

        if violations:
            raise ParseError(
                f"Content denied by StrictPolicy value rules: {', '.join(violations)}",
                content_type=content_type.value,
                violations=violations,
            )

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





@dataclass
class ParserConfig:
    """Configuration for the ContentParser."""
    strict: bool = True
    mutation_mode: str = "REJECT"
    policy: StrictPolicy | None = None


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
                policy=self._config.policy,
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
