"""Tests for secure_ingest.semantic — SemanticValidator Protocol and backward-compat."""

import types

import pytest

from secure_ingest import ContentType, SemanticValidator, StrictPolicy, TaintLevel, parse
from secure_ingest.semantic import BaseSemanticScanner

# ---------------------------------------------------------------------------
# New Protocol-based implementations
# ---------------------------------------------------------------------------


class AllowAll:
    """SemanticValidator that always accepts."""

    def validate(self, payload: str) -> bool:
        return True


class DenyEvil:
    """SemanticValidator that rejects payloads containing 'evil'."""

    def validate(self, payload: str) -> bool:
        return "evil" not in payload.lower()


class DenyToxic:
    """SemanticValidator that rejects payloads containing 'toxic'."""

    def validate(self, payload: str) -> bool:
        return "toxic" not in payload.lower()


# ---------------------------------------------------------------------------
# Legacy scan()-based implementation (backward compat)
# ---------------------------------------------------------------------------


class LegacyScanner(BaseSemanticScanner):
    def scan(self, text: str) -> list[str]:
        if "evil" in text.lower():
            return ["malicious_intent"]
        return []


# ---------------------------------------------------------------------------
# Protocol duck-typing check
# ---------------------------------------------------------------------------


def test_semantic_validator_is_protocol():
    assert isinstance(DenyEvil(), SemanticValidator)
    assert isinstance(AllowAll(), SemanticValidator)


# ---------------------------------------------------------------------------
# parse() with semantic_scanner= kwarg (backward compat path via scan())
# ---------------------------------------------------------------------------


def test_legacy_scanner_clean_text():
    scanner = LegacyScanner()
    result = parse("Hello world", ContentType.TEXT, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "malicious_intent" not in result.warnings
    assert "malicious_intent" not in result.stripped


def test_legacy_scanner_flagged_text():
    scanner = LegacyScanner()
    result = parse("I have evil intent", ContentType.TEXT, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "semantic_violation:malicious_intent" in result.warnings
    assert "malicious_intent" in result.stripped


def test_legacy_scanner_json():
    scanner = LegacyScanner()
    result = parse('{"message": "I have evil intent"}', ContentType.JSON, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "semantic_violation:malicious_intent" in result.warnings
    assert "malicious_intent" in result.stripped


# ---------------------------------------------------------------------------
# parse() with new validate() Protocol validators via StrictPolicy
# ---------------------------------------------------------------------------


def _make_policy(**extra):
    base = dict(
        allowed_types=frozenset({ContentType.TEXT, ContentType.JSON}),
        max_size_bytes=100_000,
        max_depth=50,
    )
    base.update(extra)
    return StrictPolicy(**base)


def test_validate_protocol_clean_passes():
    policy = _make_policy(semantic_validators=(DenyEvil(),))
    result = parse("Hello world", ContentType.TEXT, policy=policy)
    assert result.taint == TaintLevel.SANITIZED


def test_validate_protocol_rejects_payload():
    policy = _make_policy(semantic_validators=(DenyEvil(),))
    from secure_ingest import ParseError

    with pytest.raises(ParseError) as exc_info:
        parse("I have evil intent", ContentType.TEXT, policy=policy)
    assert any("semantic_validator_rejected" in v for v in exc_info.value.violations)


def test_multiple_validators_both_must_pass():
    """If any validator rejects, ParseError is raised."""
    policy = _make_policy(semantic_validators=(AllowAll(), DenyEvil()))
    from secure_ingest import ParseError

    with pytest.raises(ParseError):
        parse("this is evil content", ContentType.TEXT, policy=policy)


def test_multiple_validators_all_pass():
    policy = _make_policy(semantic_validators=(AllowAll(), DenyEvil()))
    result = parse("this is fine content", ContentType.TEXT, policy=policy)
    assert result.taint == TaintLevel.SANITIZED


def test_compose_merges_semantic_validators():
    v1 = DenyEvil()
    v2 = DenyToxic()
    p1 = _make_policy(semantic_validators=(v1,))
    p2 = _make_policy(semantic_validators=(v2,))
    combined = StrictPolicy.compose(p1, p2)
    assert v1 in combined.semantic_validators
    assert v2 in combined.semantic_validators


def test_compose_deduplicates_same_validator_instance():
    v1 = DenyEvil()
    p1 = _make_policy(semantic_validators=(v1,))
    p2 = _make_policy(semantic_validators=(v1,))
    combined = StrictPolicy.compose(p1, p2)
    assert combined.semantic_validators.count(v1) == 1


# ---------------------------------------------------------------------------
# MappingProxyType — validated content must be frozen
# ---------------------------------------------------------------------------


def test_validated_content_is_mapping_proxy():
    from pydantic import BaseModel

    class UserSchema(BaseModel):
        name: str
        role: str

    result = parse('{"name": "Alice", "role": "admin"}', ContentType.JSON, schema=UserSchema)
    assert result.taint == TaintLevel.VALIDATED
    assert isinstance(result.content, types.MappingProxyType)


def test_validated_content_is_read_only():
    from pydantic import BaseModel

    class UserSchema(BaseModel):
        name: str

    result = parse('{"name": "Bob"}', ContentType.JSON, schema=UserSchema)
    with pytest.raises(TypeError):
        result.content["name"] = "hacked"  # type: ignore[index]


def test_deeply_frozen_content_serializes_correctly():
    """Verify that nested MappingProxyType objects are correctly serialized to JSON."""
    from pydantic import BaseModel

    class Nested(BaseModel):
        foo: str

    class DeepSchema(BaseModel):
        inner: Nested

    class InspectJSONValidator:
        def validate(self, payload: str) -> bool:
            # Ensure the nested structure was properly encoded as JSON,
            # not fallback stringified into 'mappingproxy(...)'
            import json

            parsed = json.loads(payload)
            return isinstance(parsed.get("inner"), dict) and parsed["inner"].get("foo") == "bar"

    policy = _make_policy(semantic_validators=(InspectJSONValidator(),))

    result = parse('{"inner": {"foo": "bar"}}', ContentType.JSON, schema=DeepSchema, policy=policy)
    assert result.taint == TaintLevel.VALIDATED
