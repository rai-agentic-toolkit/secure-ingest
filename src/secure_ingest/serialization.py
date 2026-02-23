"""Policy serialization — load/save policies from YAML, JSON, or dicts.

This bridges the gap between "developer library" and "operator tool."
Instead of constructing Policy objects in code, operators can define
policies in config files:

    # policy.yaml
    allowed_types: [json, text]
    max_depth: 10
    max_size: 50000
    require_schema: true
    strip_injections: true
    deny_rules:
      - name: no_api_keys
        pattern: "(?i)api[_-]?key\\s*[:=]\\s*\\S+"
        description: Block content containing API keys
    patterns:
      include_builtins: true
      custom:
        - name: secret_extraction
          regex: "(?i)reveal.*secret"
          description: Secret extraction attempts
      disabled: [role_hijack]
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .parser import (
    ContentType,
    InjectionPattern,
    PatternRegistry,
    StrictPolicy,
)
from .rules import ValueRule

# Current schema version written into all serialized policies.
# Bump this when the format changes in a breaking way.
_SCHEMA_VERSION = 2


class PolicyVersionError(ValueError):
    """Raised when a serialized policy has an unknown or unsupported schema version."""

    def __init__(self, found: int, supported: int):
        self.found = found
        self.supported = supported
        super().__init__(
            f"Unsupported policy schema_version {found!r} "
            f"(this library supports up to version {supported}). "
            "Upgrade secure-ingest or regenerate the policy file."
        )


def policy_to_dict(policy: StrictPolicy) -> dict[str, Any]:
    """Serialize a StrictPolicy to a plain dict (suitable for JSON/YAML).

    The output always includes ``schema_version`` so that future library
    versions can detect and migrate stale policy files.
    """
    d: dict[str, Any] = {"schema_version": _SCHEMA_VERSION}

    if policy.allowed_types is not None:
        d["allowed_types"] = sorted(t.value for t in policy.allowed_types)

    d["max_depth"] = policy.max_depth
    d["max_size_bytes"] = policy.max_size_bytes
    d["mutation_mode"] = policy.mutation_mode

    if policy.value_rules:
        d["value_rules"] = [
            _value_rule_to_dict(rule) for rule in policy.value_rules
        ]

    if policy.patterns is not None:
        d["patterns"] = _registry_to_dict(policy.patterns)

    return d


def policy_from_dict(d: dict[str, Any]) -> StrictPolicy:
    """Deserialize a StrictPolicy from a plain dict.

    Validates ``schema_version`` if present. Version 1 policies (no version
    field) are accepted with a ``mutation_mode`` migration: the old default
    was ``REJECT``; if a v1 file omits ``mutation_mode`` we preserve that
    intent. Version 2+ files use ``IGNORE`` as the default.
    """
    schema_version = int(d.get("schema_version", 1))
    if schema_version > _SCHEMA_VERSION:
        raise PolicyVersionError(found=schema_version, supported=_SCHEMA_VERSION)

    # allowed_types
    if "allowed_types" not in d:
        raise ValueError("allowed_types is required for StrictPolicy")
    raw_types = d["allowed_types"]
    if not isinstance(raw_types, list):
        raise ValueError(f"allowed_types must be a list, got {type(raw_types).__name__}")
    types = set()
    for t in raw_types:
        try:
            types.add(ContentType(t.lower()))
        except ValueError:
            valid = ", ".join(ct.value for ct in ContentType)
            raise ValueError(f"Unknown content type '{t}' (valid: {valid})")
    allowed_types = frozenset(types)

    max_depth = int(d["max_depth"]) if "max_depth" in d else 50
    max_size_bytes = int(d["max_size_bytes"]) if "max_size_bytes" in d else 50000

    if "mutation_mode" in d:
        mutation_mode = str(d["mutation_mode"])
    elif "strip_injections" in d:
        # Backward compatibility with v1 strip_injections boolean.
        mutation_mode = "REJECT" if d["strip_injections"] else "IGNORE"
    elif schema_version < 2:
        # v1 policy with no mutation_mode: preserve old REJECT default
        # to avoid silently changing behaviour on upgrade.
        mutation_mode = "REJECT"
    else:
        # v2+ policy with no mutation_mode: use current library default
        mutation_mode = "IGNORE"

    value_rules_list = []
    if "value_rules" in d:
        rules_raw = d["value_rules"]
        if not isinstance(rules_raw, list):
            raise ValueError(f"value_rules must be a list, got {type(rules_raw).__name__}")
        value_rules_list.extend([_value_rule_from_dict(r) for r in rules_raw])
        
    # Backward compatibility
    if "deny_rules" in d:
        rules_raw = d["deny_rules"]
        if isinstance(rules_raw, list):
            for r in rules_raw:
                r["action"] = "DENY"
                value_rules_list.append(_value_rule_from_dict(r))
                
    if "allow_rules" in d:
        rules_raw = d["allow_rules"]
        if isinstance(rules_raw, list):
            for r in rules_raw:
                r["action"] = "ALLOW"
                value_rules_list.append(_value_rule_from_dict(r))

    value_rules = tuple(value_rules_list)

    patterns = None
    if "patterns" in d:
        patterns = _registry_from_dict(d["patterns"])

    return StrictPolicy(
        allowed_types=allowed_types,
        max_size_bytes=max_size_bytes,
        max_depth=max_depth,
        mutation_mode=mutation_mode,
        value_rules=value_rules,
        patterns=patterns,
    )


def policy_to_json(policy: StrictPolicy, path: str | Path | None = None, indent: int = 2) -> str:
    """Serialize a Policy to JSON string. Optionally write to a file."""
    d = policy_to_dict(policy)
    s = json.dumps(d, indent=indent)
    if path is not None:
        Path(path).write_text(s + "\n", encoding="utf-8")
    return s


def policy_from_json(source: str | Path) -> StrictPolicy:
    """Load a Policy from a JSON string or file path.

    If source looks like a file path (contains / or \\, or ends in .json),
    it's treated as a file. Otherwise, it's parsed as a JSON string.
    """
    path = Path(source)
    if path.suffix == ".json" or "/" in str(source) or "\\" in str(source):
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Fall through — maybe it's actually a JSON string
            text = str(source)
    else:
        text = str(source)

    d = json.loads(text)
    return policy_from_dict(d)


def policy_to_yaml(policy: StrictPolicy, path: str | Path | None = None) -> str:
    """Serialize a Policy to YAML string. Optionally write to a file.

    Requires PyYAML (pip install secure-ingest[yaml]).
    """
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for YAML serialization: pip install secure-ingest[yaml]")

    d = policy_to_dict(policy)
    s = yaml.dump(d, default_flow_style=False, sort_keys=False)
    if path is not None:
        Path(path).write_text(s, encoding="utf-8")
    return s


def policy_from_yaml(source: str | Path) -> StrictPolicy:
    """Load a Policy from a YAML string or file path.

    If source looks like a file path (contains / or \\, or ends in .yaml/.yml),
    it's treated as a file. Otherwise, it's parsed as a YAML string.

    Requires PyYAML (pip install secure-ingest[yaml]).
    """
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML is required for YAML serialization: pip install secure-ingest[yaml]")

    path = Path(source)
    if path.suffix in (".yaml", ".yml") or "/" in str(source) or "\\" in str(source):
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = str(source)
    else:
        text = str(source)

    d = yaml.safe_load(text)
    if not isinstance(d, dict):
        raise ValueError(f"YAML must deserialize to a dict, got {type(d).__name__}")
    return policy_from_dict(d)


# --- Internal helpers ---

def _value_rule_to_dict(rule: ValueRule) -> dict[str, str]:
    d: dict[str, str] = {"name": rule.name, "pattern": rule.pattern, "action": rule.action}
    if rule.description:
        d["description"] = rule.description
    return d

def _value_rule_from_dict(d: dict[str, Any]) -> ValueRule:
    if "name" not in d or "pattern" not in d:
        raise ValueError(f"value_rule requires 'name' and 'pattern', got keys: {list(d.keys())}")
    return ValueRule(
        name=str(d["name"]),
        pattern=str(d["pattern"]),
        action=str(d.get("action", "DENY")),
        description=str(d.get("description", "")),
    )

def _registry_to_dict(registry: PatternRegistry) -> dict[str, Any]:
    """Serialize a PatternRegistry to dict.

    Infers include_builtins by checking if any builtin pattern names are present.
    Custom patterns (non-builtin) are listed under "custom".
    """
    from .parser import BUILTIN_PATTERNS
    builtin_names = {p.name for p in BUILTIN_PATTERNS}
    current_names = set(registry.names())

    # If any builtin is present, we assume builtins were included
    has_builtins = bool(current_names & builtin_names)

    # Custom = patterns not in the builtin set
    custom_patterns = [p for p in registry.get_all() if p.name not in builtin_names]

    d: dict[str, Any] = {"include_builtins": has_builtins}
    if custom_patterns:
        d["custom"] = [_pattern_to_dict(p) for p in custom_patterns]

    # Disabled builtins = builtins that are NOT in current names
    if has_builtins:
        disabled = sorted(builtin_names - current_names)
        if disabled:
            d["disabled"] = disabled

    return d


def _registry_from_dict(d: dict[str, Any]) -> PatternRegistry:
    """Deserialize a PatternRegistry from dict.

    Accepted format:
        {
            "include_builtins": true,  # default: true
            "custom": [...],           # additional patterns
            "disabled": [...]          # builtin names to disable
        }
    """
    include_builtins = bool(d.get("include_builtins", True))
    registry = PatternRegistry(include_builtins=include_builtins)

    # Disable specific builtins
    for name in d.get("disabled", []):
        registry.disable(str(name))

    # Add custom patterns
    for p in d.get("custom", []):
        registry.add(_pattern_from_dict(p))

    return registry


def _pattern_to_dict(pattern: InjectionPattern) -> dict[str, str]:
    d: dict[str, str] = {"name": pattern.name, "regex": pattern.regex}
    if pattern.description:
        d["description"] = pattern.description
    return d


def _pattern_from_dict(d: dict[str, Any]) -> InjectionPattern:
    if "name" not in d or "regex" not in d:
        raise ValueError(f"pattern requires 'name' and 'regex', got keys: {list(d.keys())}")
    return InjectionPattern(
        name=str(d["name"]),
        regex=str(d["regex"]),
        description=str(d.get("description", "")),
    )
