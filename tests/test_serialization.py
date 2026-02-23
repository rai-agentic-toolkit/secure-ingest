"""Tests for policy serialization — dict, JSON, YAML round-tripping."""

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

from secure_ingest import (
    
    ContentType,
    ValueRule,
    InjectionPattern,
    PatternRegistry,
    StrictPolicy,
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
        d = policy_to_dict(make_policy())
        assert "allowed_types" in d
        assert d["max_depth"] == 50
        assert d["max_size_bytes"] == 100000
        assert d["mutation_mode"] == "IGNORE"

    def test_allowed_types(self):
        policy = make_policy(allowed_types=frozenset({ContentType.JSON, ContentType.TEXT}))
        d = policy_to_dict(policy)
        assert sorted(d["allowed_types"]) == ["json", "text"]

    def test_max_depth(self):
        d = policy_to_dict(make_policy(max_depth=10))
        assert d["max_depth"] == 10

    def test_max_size(self):
        d = policy_to_dict(make_policy(max_size_bytes=50000))
        assert d["max_size_bytes"] == 50000

    

    def test_strip_injections_default_omitted(self):
        """strip_injections=True (default) is omitted from output."""
        d = policy_to_dict(make_policy(strip_injections=True))
        assert "strip_injections" not in d

    def test_strip_injections_false(self):
        d = policy_to_dict(make_policy(strip_injections=False))
        assert d["mutation_mode"] == "IGNORE"

    def test_deny_rules(self):
        rules = (
            ValueRule("no_pii", r"\b\d{3}-\d{2}-\d{4}\b", description="SSN pattern"),
            ValueRule("no_keys", r"(?i)api[_-]?key"),
        )
        d = policy_to_dict(make_policy(deny_rules=rules))
        assert len(d["value_rules"]) == 2
        assert d["value_rules"][0]["name"] == "no_pii"
        assert d["value_rules"][1]["name"] == "no_keys"
        assert d["value_rules"][0].get("description") == "SSN pattern"

    def test_patterns(self):
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("custom1", r"test", "test pattern"))
        d = policy_to_dict(make_policy(patterns=reg))
        assert "patterns" in d
        assert len(d["patterns"]["custom"]) == 1
        assert d["patterns"]["custom"][0]["name"] == "custom1"


class TestPolicyFromDict:
    def test_empty_dict(self):
        import pytest
        with pytest.raises(ValueError):
            policy_from_dict({})

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
        policy = policy_from_dict({"allowed_types": ["text"], "max_depth": 5})
        assert policy.max_depth == 5

    def test_max_size(self):
        policy = policy_from_dict({"allowed_types": ["text"], "max_size_bytes": 10000})
        assert policy.max_size_bytes == 10000

    

    def test_strip_injections_false(self):
        policy = policy_from_dict({"allowed_types": ["text"], "mutation_mode": "IGNORE"})
        assert policy.mutation_mode == "IGNORE"

    def test_deny_rules(self):
        policy = policy_from_dict({
            "allowed_types": ["text"],
            "value_rules": [
                {"name": "r1", "pattern": "abc", "description": "test"},
                {"name": "r2", "pattern": "def"},
            ]
        })
        assert len(policy.value_rules) == 2
        assert policy.value_rules[0].name == "r1"
        assert policy.value_rules[0].description == "test"
        assert policy.value_rules[1].name == "r2"
        assert policy.value_rules[1].description == ""

    def test_deny_rules_missing_fields(self):
        with pytest.raises(ValueError, match="requires 'name' and 'pattern'"):
            policy_from_dict({"allowed_types": ["json"], "value_rules": [{"name": "only_name"}]})

    def test_deny_rules_not_list(self):
        with pytest.raises(ValueError, match="must be a list"):
            policy_from_dict({"allowed_types": ["json"], "value_rules": "not a list"})

    def test_patterns_with_builtins(self):
        policy = policy_from_dict({"allowed_types": ["text"],
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
        policy = policy_from_dict({"allowed_types": ["text"],
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
        policy = policy_from_dict({"allowed_types": ["text"],
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
        with pytest.raises(ValueError, match="pattern requires 'name' and 'regex'"):
            policy_from_dict({"allowed_types": ["text"],
                "patterns": {"custom": [{"name": "incomplete"}]}
            })


class TestRoundTrip:
    def test_full_policy_round_trip(self):
        """A fully-configured policy survives dict round-trip."""
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("custom_pat", r"test\d+", "numeric test"))
        original = make_policy(
            allowed_types=frozenset({ContentType.JSON, ContentType.MARKDOWN}),
            max_depth=15,
            max_size_bytes=100000,
            strip_injections=False,
            deny_rules=(
                ValueRule("no_secrets", r"(?i)secret", "block secrets"),
            ),
            patterns=reg,
        )
        d = policy_to_dict(original)
        restored = policy_from_dict(d)

        assert restored.allowed_types == original.allowed_types
        assert restored.max_depth == original.max_depth
        assert restored.max_size_bytes == original.max_size_bytes
        
        assert restored.mutation_mode == original.mutation_mode
        assert len(restored.value_rules) == len(original.value_rules)
        assert restored.value_rules[0].name == "no_secrets"
        assert restored.patterns is not None
        assert restored.patterns.names() == ["custom_pat"]

    def test_default_policy_round_trip(self):
        """Default policy survives round-trip."""
        original = make_policy()
        d = policy_to_dict(original)
        restored = policy_from_dict(d)
        assert len(restored.allowed_types) == 5
        assert restored.max_depth == 50
        assert restored.mutation_mode == "IGNORE"


# --- JSON I/O ---

class TestJsonIO:
    def test_to_json_string(self):
        policy = make_policy(max_depth=5)
        s = policy_to_json(policy)
        d = json.loads(s)
        assert d["max_depth"] == 5

    def test_to_json_file(self, tmp_path):
        policy = make_policy(allowed_types=frozenset({ContentType.TEXT}))
        path = tmp_path / "policy.json"
        policy_to_json(policy, path)
        assert path.exists()
        d = json.loads(path.read_text())
        assert d["allowed_types"] == ["text"]

    def test_from_json_string(self):
        s = '{"allowed_types": ["text"], "max_depth": 10, "allowed_types": ["json"]}'
        policy = policy_from_json(s)
        assert policy.max_depth == 10
        

    def test_from_json_file(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text('{"allowed_types": ["json"], "max_size_bytes": 5000}')
        policy = policy_from_json(str(path))
        assert policy.max_size_bytes == 5000

    def test_json_round_trip_via_file(self, tmp_path):
        original = make_policy(
            allowed_types=frozenset({ContentType.JSON, ContentType.TEXT}),
            max_depth=8,
            deny_rules=(ValueRule("test", r"abc"),),
        )
        path = tmp_path / "rt.json"
        policy_to_json(original, path)
        restored = policy_from_json(str(path))
        assert restored.allowed_types == original.allowed_types
        assert restored.max_depth == 8
        assert len(restored.value_rules) == 1


# --- YAML I/O ---

class TestYamlIO:
    def test_to_yaml_string(self):
        policy = make_policy(max_depth=5)
        s = policy_to_yaml(policy)
        d = yaml.safe_load(s)
        assert d["max_depth"] == 5

    def test_to_yaml_file(self, tmp_path):
        policy = make_policy(allowed_types=frozenset({ContentType.JSON, ContentType.TEXT}))
        path = tmp_path / "policy.yaml"
        policy_to_yaml(policy, path)
        assert path.exists()
        d = yaml.safe_load(path.read_text())
        assert sorted(d["allowed_types"]) == ["json", "text"]

    def test_from_yaml_string(self):
        s = "allowed_types: [json, text]\nmax_depth: 10\nallowed_types: [json, text]\n"
        policy = policy_from_yaml(s)
        assert policy.max_depth == 10
        

    def test_from_yaml_file(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text("allowed_types: [json, text]\nmax_size_bytes: 5000\n")
        policy = policy_from_yaml(str(path))
        assert policy.max_size_bytes == 5000

    def test_yaml_round_trip_via_file(self, tmp_path):
        original = make_policy(
            allowed_types=frozenset({ContentType.YAML, ContentType.XML}),
            max_size_bytes=25000,
            strip_injections=False,
            deny_rules=(ValueRule("block_it", r"bad_pattern", description="test"),),
        )
        path = tmp_path / "rt.yaml"
        policy_to_yaml(original, path)
        restored = policy_from_yaml(str(path))
        assert restored.allowed_types == original.allowed_types
        assert restored.max_size_bytes == 25000
        assert restored.mutation_mode == "IGNORE"
        assert len(restored.value_rules) == 1

    def test_from_yaml_non_dict(self):
        with pytest.raises(ValueError, match="must deserialize to a dict"):
            policy_from_yaml("- just\n- a\n- list\n")

    def test_yaml_with_patterns(self, tmp_path):
        """Full YAML config with patterns, deny rules, the works."""
        config = """
allowed_types: [json, text]
allowed_types: [json, text]\nmax_depth: 10
allowed_types: [json, text]\nmax_size_bytes: 50000
allowed_types: [json, text]
strip_injections: true
allowed_types: [json, text]\nvalue_rules:
  - name: no_api_keys
    pattern: "(?i)api[_-]?key\\\\s*[:=]\\\\s*\\\\S+"
    description: Block content containing API keys
allowed_types: [json, text]\npatterns:
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
        assert policy.max_size_bytes == 50000
        
        assert len(policy.value_rules) == 1
        assert policy.value_rules[0].name == "no_api_keys"
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
        assert policy.allowed_types == frozenset()

    def test_deny_rule_description_optional(self):
        d = policy_to_dict(make_policy(deny_rules=(ValueRule("r", r"x"),)))
        # No description key when empty
        assert "description" not in d["value_rules"][0]

    def test_pattern_description_optional(self):
        reg = PatternRegistry(include_builtins=False)
        reg.add(InjectionPattern("p", r"x"))
        d = policy_to_dict(make_policy(patterns=reg))
        assert "description" not in d["patterns"]["custom"][0]


class TestAllowRuleSerialization:
    """Allow rules round-trip through dict, JSON, YAML."""

    def test_to_dict_with_allow_rules(self):
        policy = make_policy(allow_rules=(
            ValueRule("has_id", r'"id"\s*:', action="ALLOW", description="Requires an id field"),
        ))
        d = policy_to_dict(policy)
        assert "value_rules" in d
        assert len(d["value_rules"]) == 1
        assert d["value_rules"][0]["name"] == "has_id"
        assert d["value_rules"][0].get("description") == "Requires an id field"

    def test_from_dict_with_allow_rules(self):
        d = {
            "allowed_types": ["json"],
            "value_rules": [
                {"name": "has_ts", "pattern": r'"timestamp":', "description": "Must have timestamp"},
            ]
        }
        policy = policy_from_dict(d)
        assert len(policy.value_rules) == 1
        assert policy.value_rules[0].name == "has_ts"

    def test_dict_round_trip(self):
        original = make_policy(
            allow_rules=(
                ValueRule("r1", r"AAA", action="ALLOW", description="first"),
                ValueRule("r2", r"BBB", action="ALLOW"),
            ),
            deny_rules=(ValueRule("d1", r"CCC"),),
        )
        d = policy_to_dict(original)
        restored = policy_from_dict(d)
        assert len(restored.value_rules) == 3
        assert restored.value_rules[0].name == "d1"
        assert restored.value_rules[1].name == "r1"
        assert restored.value_rules[2].name == "r2"

    def test_json_round_trip(self, tmp_path):
        original = make_policy(allow_rules=(ValueRule("req", r"REQUIRED", action="ALLOW"),))
        path = tmp_path / "policy.json"
        policy_to_json(original, path)
        restored = policy_from_json(str(path))
        assert len(restored.value_rules) == 1
        assert restored.value_rules[0].pattern == r"REQUIRED"

    def test_yaml_round_trip(self, tmp_path):
        original = make_policy(allow_rules=(
            ValueRule("has_data", r'"data":', action="ALLOW", description="Must contain data"),
        ))
        path = tmp_path / "policy.yaml"
        policy_to_yaml(original, path)
        restored = policy_from_yaml(str(path))
        assert len(restored.value_rules) == 1
        assert restored.value_rules[0].name == "has_data"

    def test_empty_allow_rules_not_in_dict(self):
        """Empty allow_rules tuple omitted from dict output."""
        policy = make_policy(allow_rules=())
        d = policy_to_dict(policy)
        assert "value_rules" not in d

    def test_allow_rule_description_optional(self):
        d = policy_to_dict(make_policy(allow_rules=(ValueRule("r", r"x", action="ALLOW"),)))
        assert "description" not in d["value_rules"][0]

    def test_from_dict_invalid_allow_rules_type(self):
        with pytest.raises(ValueError, match="value_rules must be a list"):
            policy_from_dict({"allowed_types": ["json"], "value_rules": "not a list"})

    def test_from_dict_missing_allow_rule_fields(self):
        with pytest.raises(ValueError, match="value_rule requires"):
            policy_from_dict({"allowed_types": ["json"], "value_rules": [{"name": "missing_pattern"}]})


def make_policy(**kwargs):
    from secure_ingest import StrictPolicy, ContentType
    opts = {
        'allowed_types': frozenset([ContentType.JSON, ContentType.TEXT, ContentType.MARKDOWN, ContentType.YAML, ContentType.XML]),
        'max_size_bytes': 100000,
        'max_depth': 50
    }
    if 'max_size' in kwargs:
        kwargs['max_size_bytes'] = kwargs.pop('max_size')
    if 'strip_injections' in kwargs:
        val = kwargs.pop('strip_injections')
        kwargs['mutation_mode'] = "REJECT" if val else "IGNORE"
    rules = []
    if 'deny_rules' in kwargs:
        rules.extend(kwargs.pop('deny_rules'))
    if 'allow_rules' in kwargs:
        rules.extend(kwargs.pop('allow_rules'))
    if rules:
        kwargs['value_rules'] = tuple(rules)
    opts.update(kwargs)
    return StrictPolicy(**opts)
