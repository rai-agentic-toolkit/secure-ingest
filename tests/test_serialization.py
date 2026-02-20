"""Tests for policy serialization — dict, JSON, YAML round-tripping."""

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

from secure_ingest import (
    ContentType,
    DenyRule,
    InjectionPattern,
    PatternRegistry,
    Policy,
)
from secure_ingest.serialization import (
    policy_from_dict,
    policy_from_json,
    policy_from_yaml,
    policy_to_dict,
    policy_to_json,
    policy_to_yaml,
)


# --- policy_to_dict / policy_from_dict ---

class TestPolicyToDict:
    def test_empty_policy(self):
        """Default policy serializes to empty dict (all defaults)."""
        d = policy_to_dict(Policy())
        assert d == {}

    def test_allowed_types(self):
        policy = Policy(allowed_types=frozenset({ContentType.JSON, ContentType.TEXT}))
        d = policy_to_dict(policy)
        assert sorted(d["allowed_types"]) == ["json", "text"]

    def test_max_depth(self):
        d = policy_to_dict(Policy(max_depth=10))
        assert d["max_depth"] == 10

    def test_max_size(self):
        d = policy_to_dict(Policy(max_size=50000))
        assert d["max_size"] == 50000

    def test_require_schema(self):
        d = policy_to_dict(Policy(require_schema=True))
        assert d["require_schema"] is True

    def test_strip_injections_default_omitted(self):
        """strip_injections=True (default) is omitted from output."""
        d = policy_to_dict(Policy(strip_injections=True))
        assert "strip_injections" not in d

    def test_strip_injections_false(self):
        d = policy_to_dict(Policy(strip_injections=False))
        assert d["strip_injections"] is False

    def test_deny_rules(self):
        rules = (
            DenyRule("no_pii", r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
            DenyRule("no_keys", r"(?i)api[_-]?key"),
        )
        d = policy_to_dict(Policy(deny_rules=rules))
        assert len(d["deny_rules"]) == 2
        assert d["deny_rules"][0]["name"] == "no_pii"
        assert d["deny_rules"][1]["name"] == "no_keys"
        assert d["deny_rules"][0]["description"] == "SSN pattern"

    def test_patterns(self):
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("custom1", r"test", "test pattern"))
        d = policy_to_dict(Policy(patterns=reg))
        assert "patterns" in d
        assert len(d["patterns"]["custom"]) == 1
        assert d["patterns"]["custom"][0]["name"] == "custom1"


class TestPolicyFromDict:
    def test_empty_dict(self):
        """Empty dict produces default policy."""
        policy = policy_from_dict({})
        assert policy.allowed_types is None
        assert policy.max_depth is None
        assert policy.max_size is None
        assert policy.require_schema is False
        assert policy.strip_injections is True
        assert policy.deny_rules == ()
        assert policy.patterns is None

    def test_allowed_types(self):
        policy = policy_from_dict({"allowed_types": ["json", "yaml"]})
        assert policy.allowed_types == frozenset({ContentType.JSON, ContentType.YAML})

    def test_allowed_types_case_insensitive(self):
        policy = policy_from_dict({"allowed_types": ["JSON", "Text"]})
        assert policy.allowed_types == frozenset({ContentType.JSON, ContentType.TEXT})

    def test_invalid_content_type(self):
        with pytest.raises(ValueError, match="Unknown content type 'html'"):
            policy_from_dict({"allowed_types": ["json", "html"]})

    def test_allowed_types_not_list(self):
        with pytest.raises(ValueError, match="must be a list"):
            policy_from_dict({"allowed_types": "json"})

    def test_max_depth(self):
        policy = policy_from_dict({"max_depth": 5})
        assert policy.max_depth == 5

    def test_max_size(self):
        policy = policy_from_dict({"max_size": 10000})
        assert policy.max_size == 10000

    def test_require_schema(self):
        policy = policy_from_dict({"require_schema": True})
        assert policy.require_schema is True

    def test_strip_injections_false(self):
        policy = policy_from_dict({"strip_injections": False})
        assert policy.strip_injections is False

    def test_deny_rules(self):
        policy = policy_from_dict({
            "deny_rules": [
                {"name": "r1", "pattern": "abc", "description": "test"},
                {"name": "r2", "pattern": "def"},
            ]
        })
        assert len(policy.deny_rules) == 2
        assert policy.deny_rules[0].name == "r1"
        assert policy.deny_rules[0].description == "test"
        assert policy.deny_rules[1].name == "r2"
        assert policy.deny_rules[1].description == ""

    def test_deny_rules_missing_fields(self):
        with pytest.raises(ValueError, match="requires 'name' and 'pattern'"):
            policy_from_dict({"deny_rules": [{"name": "only_name"}]})

    def test_deny_rules_not_list(self):
        with pytest.raises(ValueError, match="must be a list"):
            policy_from_dict({"deny_rules": "not a list"})

    def test_patterns_with_builtins(self):
        policy = policy_from_dict({
            "patterns": {
                "include_builtins": True,
                "custom": [
                    {"name": "extra", "regex": "abc", "description": "test"},
                ],
            }
        })
        assert policy.patterns is not None
        names = policy.patterns.names()
        assert "extra" in names
        # Builtins should be present
        assert "instruction_override" in names

    def test_patterns_without_builtins(self):
        policy = policy_from_dict({
            "patterns": {
                "include_builtins": False,
                "custom": [
                    {"name": "only_this", "regex": "xyz"},
                ],
            }
        })
        assert policy.patterns is not None
        assert policy.patterns.names() == ["only_this"]

    def test_patterns_with_disabled(self):
        policy = policy_from_dict({
            "patterns": {
                "include_builtins": True,
                "disabled": ["role_hijack", "chat_template"],
            }
        })
        assert policy.patterns is not None
        names = policy.patterns.names()
        assert "role_hijack" not in names
        assert "chat_template" not in names
        assert "instruction_override" in names

    def test_pattern_missing_fields(self):
        with pytest.raises(ValueError, match="requires 'name' and 'regex'"):
            policy_from_dict({
                "patterns": {"custom": [{"name": "incomplete"}]}
            })


class TestRoundTrip:
    def test_full_policy_round_trip(self):
        """A fully-configured policy survives dict round-trip."""
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("custom_pat", r"test\d+", "numeric test"))
        original = Policy(
            allowed_types=frozenset({ContentType.JSON, ContentType.MARKDOWN}),
            max_depth=15,
            max_size=100000,
            require_schema=True,
            strip_injections=False,
            deny_rules=(
                DenyRule("no_secrets", r"(?i)secret", "block secrets"),
            ),
            patterns=reg,
        )
        d = policy_to_dict(original)
        restored = policy_from_dict(d)

        assert restored.allowed_types == original.allowed_types
        assert restored.max_depth == original.max_depth
        assert restored.max_size == original.max_size
        assert restored.require_schema == original.require_schema
        assert restored.strip_injections == original.strip_injections
        assert len(restored.deny_rules) == len(original.deny_rules)
        assert restored.deny_rules[0].name == "no_secrets"
        assert restored.patterns is not None
        assert restored.patterns.names() == ["custom_pat"]

    def test_default_policy_round_trip(self):
        """Default policy survives round-trip."""
        original = Policy()
        d = policy_to_dict(original)
        restored = policy_from_dict(d)
        assert restored.allowed_types is None
        assert restored.max_depth is None
        assert restored.strip_injections is True


# --- JSON I/O ---

class TestJsonIO:
    def test_to_json_string(self):
        policy = Policy(max_depth=5)
        s = policy_to_json(policy)
        d = json.loads(s)
        assert d["max_depth"] == 5

    def test_to_json_file(self, tmp_path):
        policy = Policy(allowed_types=frozenset({ContentType.TEXT}))
        path = tmp_path / "policy.json"
        policy_to_json(policy, path)
        assert path.exists()
        d = json.loads(path.read_text())
        assert d["allowed_types"] == ["text"]

    def test_from_json_string(self):
        s = '{"max_depth": 10, "require_schema": true}'
        policy = policy_from_json(s)
        assert policy.max_depth == 10
        assert policy.require_schema is True

    def test_from_json_file(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text('{"max_size": 5000}')
        policy = policy_from_json(str(path))
        assert policy.max_size == 5000

    def test_json_round_trip_via_file(self, tmp_path):
        original = Policy(
            allowed_types=frozenset({ContentType.JSON}),
            max_depth=8,
            deny_rules=(DenyRule("test", r"abc"),),
        )
        path = tmp_path / "rt.json"
        policy_to_json(original, path)
        restored = policy_from_json(str(path))
        assert restored.allowed_types == original.allowed_types
        assert restored.max_depth == 8
        assert len(restored.deny_rules) == 1


# --- YAML I/O ---

class TestYamlIO:
    def test_to_yaml_string(self):
        policy = Policy(max_depth=5)
        s = policy_to_yaml(policy)
        d = yaml.safe_load(s)
        assert d["max_depth"] == 5

    def test_to_yaml_file(self, tmp_path):
        policy = Policy(allowed_types=frozenset({ContentType.JSON, ContentType.TEXT}))
        path = tmp_path / "policy.yaml"
        policy_to_yaml(policy, path)
        assert path.exists()
        d = yaml.safe_load(path.read_text())
        assert sorted(d["allowed_types"]) == ["json", "text"]

    def test_from_yaml_string(self):
        s = "max_depth: 10\nrequire_schema: true\n"
        policy = policy_from_yaml(s)
        assert policy.max_depth == 10
        assert policy.require_schema is True

    def test_from_yaml_file(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("max_size: 5000\n")
        policy = policy_from_yaml(str(path))
        assert policy.max_size == 5000

    def test_yaml_round_trip_via_file(self, tmp_path):
        original = Policy(
            allowed_types=frozenset({ContentType.YAML, ContentType.XML}),
            max_size=25000,
            strip_injections=False,
            deny_rules=(DenyRule("block_it", r"bad_pattern", "test"),),
        )
        path = tmp_path / "rt.yaml"
        policy_to_yaml(original, path)
        restored = policy_from_yaml(str(path))
        assert restored.allowed_types == original.allowed_types
        assert restored.max_size == 25000
        assert restored.strip_injections is False
        assert len(restored.deny_rules) == 1

    def test_from_yaml_non_dict(self):
        with pytest.raises(ValueError, match="must deserialize to a dict"):
            policy_from_yaml("- just\n- a\n- list\n")

    def test_yaml_with_patterns(self, tmp_path):
        """Full YAML config with patterns, deny rules, the works."""
        config = """
allowed_types: [json, text]
max_depth: 10
max_size: 50000
require_schema: true
strip_injections: true
deny_rules:
  - name: no_api_keys
    pattern: "(?i)api[_-]?key\\\\s*[:=]\\\\s*\\\\S+"
    description: Block content containing API keys
patterns:
  include_builtins: true
  custom:
    - name: secret_extraction
      regex: "(?i)reveal.*secret"
      description: Secret extraction attempts
  disabled: [role_hijack]
"""
        path = tmp_path / "full.yaml"
        path.write_text(config)
        policy = policy_from_yaml(str(path))
        assert policy.allowed_types == frozenset({ContentType.JSON, ContentType.TEXT})
        assert policy.max_depth == 10
        assert policy.max_size == 50000
        assert policy.require_schema is True
        assert len(policy.deny_rules) == 1
        assert policy.deny_rules[0].name == "no_api_keys"
        assert policy.patterns is not None
        names = policy.patterns.names()
        assert "secret_extraction" in names
        assert "role_hijack" not in names
        assert "instruction_override" in names  # builtin still present


# --- Edge cases ---

class TestEdgeCases:
    def test_empty_allowed_types_list(self):
        """Empty list → None (allow all), not frozenset()."""
        policy = policy_from_dict({"allowed_types": []})
        assert policy.allowed_types is None

    def test_deny_rule_description_optional(self):
        d = policy_to_dict(Policy(deny_rules=(DenyRule("r", r"x"),)))
        # No description key when empty
        assert "description" not in d["deny_rules"][0]

    def test_pattern_description_optional(self):
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("p", r"x"))
        d = policy_to_dict(Policy(patterns=reg))
        assert "description" not in d["patterns"]["custom"][0]
