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
    DenyRule,
    InjectionPattern,
    PatternRegistry,
    Policy,
)


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Serialize a Policy to a plain dict (suitable for JSON/YAML).

    The output is human-readable and round-trips through policy_from_dict().
    """
    d: dict[str, Any] = {}

    if policy.allowed_types is not None:
        d["allowed_types"] = sorted(t.value for t in policy.allowed_types)

    if policy.max_depth is not None:
        d["max_depth"] = policy.max_depth

    if policy.max_size is not None:
        d["max_size"] = policy.max_size

    if policy.require_schema:
        d["require_schema"] = True

    # Only include strip_injections if it's non-default (default is True)
    if not policy.strip_injections:
        d["strip_injections"] = False

    if policy.deny_rules:
        d["deny_rules"] = [
            _deny_rule_to_dict(rule) for rule in policy.deny_rules
        ]

    if policy.patterns is not None:
        d["patterns"] = _registry_to_dict(policy.patterns)

    return d


def policy_from_dict(d: dict[str, Any]) -> Policy:
    """Deserialize a Policy from a plain dict.

    Accepts the format produced by policy_to_dict(), plus the
    human-friendly YAML/JSON config format documented in the module docstring.

    Raises:
        ValueError: If the dict contains invalid values (unknown content types,
            missing required fields in deny rules/patterns, etc.).
    """
    # allowed_types
    allowed_types = None
    if "allowed_types" in d:
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
        allowed_types = frozenset(types) if types else None

    # max_depth
    max_depth = d.get("max_depth")
    if max_depth is not None:
        max_depth = int(max_depth)

    # max_size
    max_size = d.get("max_size")
    if max_size is not None:
        max_size = int(max_size)

    # require_schema
    require_schema = bool(d.get("require_schema", False))

    # strip_injections (default True)
    strip_injections = bool(d.get("strip_injections", True))

    # deny_rules
    deny_rules: tuple[DenyRule, ...] = ()
    if "deny_rules" in d:
        rules_raw = d["deny_rules"]
        if not isinstance(rules_raw, list):
            raise ValueError(f"deny_rules must be a list, got {type(rules_raw).__name__}")
        deny_rules = tuple(_deny_rule_from_dict(r) for r in rules_raw)

    # patterns
    patterns = None
    if "patterns" in d:
        patterns = _registry_from_dict(d["patterns"])

    return Policy(
        allowed_types=allowed_types,
        max_depth=max_depth,
        max_size=max_size,
        require_schema=require_schema,
        patterns=patterns,
        strip_injections=strip_injections,
        deny_rules=deny_rules,
    )


def policy_to_json(policy: Policy, path: str | Path | None = None, indent: int = 2) -> str:
    """Serialize a Policy to JSON string. Optionally write to a file."""
    d = policy_to_dict(policy)
    s = json.dumps(d, indent=indent)
    if path is not None:
        Path(path).write_text(s + "\n", encoding="utf-8")
    return s


def policy_from_json(source: str | Path) -> Policy:
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


def policy_to_yaml(policy: Policy, path: str | Path | None = None) -> str:
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


def policy_from_yaml(source: str | Path) -> Policy:
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

def _deny_rule_to_dict(rule: DenyRule) -> dict[str, str]:
    d: dict[str, str] = {"name": rule.name, "pattern": rule.pattern}
    if rule.description:
        d["description"] = rule.description
    return d


def _deny_rule_from_dict(d: dict[str, Any]) -> DenyRule:
    if "name" not in d or "pattern" not in d:
        raise ValueError(f"deny_rule requires 'name' and 'pattern', got keys: {list(d.keys())}")
    return DenyRule(
        name=str(d["name"]),
        pattern=str(d["pattern"]),
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
