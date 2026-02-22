"""Tests for taint tracking, provenance, and compose() — v0.2 features."""

import pytest

from secure_ingest import (
    parse, ContentType, TaintLevel, ParseResult,
)


class TestTaintLevel:
    """Tests for TaintLevel enum ordering."""

    def test_ordering(self):
        assert TaintLevel.UNTRUSTED < TaintLevel.SANITIZED
        assert TaintLevel.SANITIZED < TaintLevel.VALIDATED
        assert TaintLevel.UNTRUSTED < TaintLevel.VALIDATED

    def test_equality(self):
        assert TaintLevel.SANITIZED == TaintLevel.SANITIZED
        assert not (TaintLevel.SANITIZED < TaintLevel.SANITIZED)

    def test_ge_le(self):
        assert TaintLevel.VALIDATED >= TaintLevel.SANITIZED
        assert TaintLevel.SANITIZED <= TaintLevel.VALIDATED
        assert TaintLevel.SANITIZED >= TaintLevel.SANITIZED

    def test_min_selects_least_trusted(self):
        levels = [TaintLevel.VALIDATED, TaintLevel.SANITIZED, TaintLevel.UNTRUSTED]
        assert min(levels) == TaintLevel.UNTRUSTED


class TestParseTaint:
    """Tests for taint metadata in parse() results."""

    def test_default_taint_is_sanitized(self):
        result = parse("hello", ContentType.TEXT)
        assert result.taint == TaintLevel.SANITIZED

    def test_schema_validation_promotes_to_validated(self):
        from pydantic import BaseModel
        class MySchema(BaseModel):
            name: str
        result = parse('{"name": "Alice"}', ContentType.JSON, schema=MySchema)
        assert result.taint == TaintLevel.VALIDATED

    def test_no_schema_stays_sanitized(self):
        result = parse('{"name": "Alice"}', ContentType.JSON)
        assert result.taint == TaintLevel.SANITIZED

    def test_provenance_passed_through(self):
        result = parse("hello", ContentType.TEXT, provenance="agent-alpha")
        assert result.provenance == "agent-alpha"

    def test_empty_provenance_default(self):
        result = parse("hello", ContentType.TEXT)
        assert result.provenance == ""

    def test_chain_id_auto_generated(self):
        result = parse("hello", ContentType.TEXT)
        assert result.chain_id != ""
        assert len(result.chain_id) == 12

    def test_chain_id_passed_through(self):
        result = parse("hello", ContentType.TEXT, chain_id="my-chain-001")
        assert result.chain_id == "my-chain-001"

    def test_taint_on_json(self):
        result = parse('{"x": 1}', ContentType.JSON, provenance="src")
        assert result.taint == TaintLevel.SANITIZED
        assert result.provenance == "src"

    def test_taint_on_markdown(self):
        result = parse("# Hello", ContentType.MARKDOWN, provenance="md-src")
        assert result.taint == TaintLevel.SANITIZED
        assert result.provenance == "md-src"

    def test_taint_on_yaml(self):
        result = parse("key: value", ContentType.YAML, provenance="yaml-src")
        assert result.taint == TaintLevel.SANITIZED
        assert result.provenance == "yaml-src"

    def test_taint_on_xml(self):
        result = parse("<root><a>1</a></root>", ContentType.XML, provenance="xml-src")
        assert result.taint == TaintLevel.SANITIZED
        assert result.provenance == "xml-src"

    def test_chain_id_consistent_across_types(self):
        """Same chain_id can be used across different content types."""
        chain = "shared-chain"
        r1 = parse("hello", ContentType.TEXT, chain_id=chain)
        r2 = parse('{"a":1}', ContentType.JSON, chain_id=chain)
        assert r1.chain_id == r2.chain_id == chain



class TestContentHash:
    """Tests for content_hash integrity verification."""

    def test_hash_present_on_parse_result(self):
        result = parse("hello", ContentType.TEXT)
        assert result.content_hash != ""
        assert len(result.content_hash) == 64  # SHA-256 hex

    def test_hash_deterministic(self):
        """Same content always produces the same hash."""
        r1 = parse("hello", ContentType.TEXT)
        r2 = parse("hello", ContentType.TEXT)
        assert r1.content_hash == r2.content_hash

    def test_hash_differs_for_different_content(self):
        r1 = parse("hello", ContentType.TEXT)
        r2 = parse("world", ContentType.TEXT)
        assert r1.content_hash != r2.content_hash

    def test_hash_on_json(self):
        result = parse('{"a": 1, "b": 2}', ContentType.JSON)
        assert result.content_hash != ""
        assert len(result.content_hash) == 64

    def test_json_hash_key_order_independent(self):
        """JSON hash is deterministic regardless of key order."""
        r1 = parse('{"a": 1, "b": 2}', ContentType.JSON)
        r2 = parse('{"b": 2, "a": 1}', ContentType.JSON)
        assert r1.content_hash == r2.content_hash

    def test_hash_on_yaml(self):
        result = parse("key: value", ContentType.YAML)
        assert result.content_hash != ""

    def test_hash_on_xml(self):
        result = parse("<root><a>1</a></root>", ContentType.XML)
        assert result.content_hash != ""

    def test_hash_on_markdown(self):
        result = parse("# Title\nContent", ContentType.MARKDOWN)
        assert result.content_hash != ""

    def test_verify_passes_on_unmodified(self):
        result = parse("hello", ContentType.TEXT)
        assert result.verify() is True

    def test_verify_on_json(self):
        result = parse('{"key": "value"}', ContentType.JSON)
        assert result.verify() is True



    def test_verify_backwards_compat_no_hash(self):
        """ParseResult without hash (backwards compat) returns True for verify."""
        result = ParseResult(
            content="hello",
            content_type=ContentType.TEXT,
            sanitized=True,
        )
        assert result.content_hash == ""
        assert result.verify() is True


class TestBackwardsCompatibility:
    """Ensure v0.1 behavior is preserved."""

    def test_parse_without_taint_args(self):
        """parse() works without provenance/chain_id args."""
        result = parse("hello", ContentType.TEXT)
        assert result.content == "hello"
        assert result.sanitized is True
        assert result.taint == TaintLevel.SANITIZED

    def test_parse_result_still_frozen(self):
        result = parse("hello", ContentType.TEXT)
        with pytest.raises(AttributeError):
            result.taint = TaintLevel.UNTRUSTED  # type: ignore


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
    if 'deny_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('deny_rules')
    if 'allow_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('allow_rules')
    opts.update(kwargs)
    return StrictPolicy(**opts)


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
    if 'deny_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('deny_rules')
    if 'allow_rules' in kwargs:
        kwargs['value_rules'] = kwargs.pop('allow_rules')
    opts.update(kwargs)
    return StrictPolicy(**opts)
