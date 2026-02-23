"""Tests for all round-2 improvements:
- Exception hierarchy (SizeExceededError, DepthExceededError, etc.)
- ParseResult.as_validated()
- @require_validated decorator
- secure_ingest.testing helpers
- parse_async() with AsyncSemanticValidator
"""

import asyncio
import types

import pytest
from pydantic import BaseModel

from secure_ingest import (
    ContentType,
    DepthExceededError,
    ParseError,
    ParseResult,
    PolicyTypeError,
    SchemaValidationError,
    SemanticRejectedError,
    SizeExceededError,
    StrictPolicy,
    TaintLevel,
    parse,
    require_validated,
)
from secure_ingest.async_parse import parse_async
from secure_ingest.testing import make_sanitized_result, make_validated_result

# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_all_are_parse_error_subclasses(self):
        assert issubclass(SizeExceededError, ParseError)
        assert issubclass(DepthExceededError, ParseError)
        assert issubclass(SchemaValidationError, ParseError)
        assert issubclass(SemanticRejectedError, ParseError)
        assert issubclass(PolicyTypeError, ParseError)

    def test_size_exceeded_error_attributes(self):
        with pytest.raises(SizeExceededError) as exc_info:
            policy = StrictPolicy(
                allowed_types=frozenset({ContentType.TEXT}),
                max_size_bytes=5,
                max_depth=10,
            )
            parse("hello world this is too long", ContentType.TEXT, policy=policy)
        e = exc_info.value
        assert e.limit == 5
        assert e.actual > 5
        assert "policy_size_exceeded" in e.violations
        # Catchable as ParseError
        assert isinstance(e, ParseError)

    def test_depth_exceeded_error_attributes(self):
        nested = '{"a": {"b": {"c": {"d": 1}}}}'
        with pytest.raises(DepthExceededError) as exc_info:
            policy = StrictPolicy(
                allowed_types=frozenset({ContentType.JSON}),
                max_size_bytes=10_000,
                max_depth=2,
            )
            parse(nested, ContentType.JSON, policy=policy)
        e = exc_info.value
        assert e.max_depth == 2
        assert "excessive_nesting" in e.violations

    def test_schema_validation_error_attributes(self):
        class Strict(BaseModel):
            name: str
            age: int

        with pytest.raises(SchemaValidationError) as exc_info:
            parse('{"name": "Alice", "age": "not-an-int"}', ContentType.JSON, schema=Strict)
        e = exc_info.value
        assert len(e.pydantic_errors) >= 1
        assert any("schema_violation" in v for v in e.violations)

    def test_semantic_rejected_error_attributes(self):
        class NeverPass:
            def validate(self, payload: str) -> bool:
                return False

        policy = StrictPolicy(
            allowed_types=frozenset({ContentType.TEXT}),
            max_size_bytes=10_000,
            max_depth=10,
            semantic_validators=(NeverPass(),),
        )
        with pytest.raises(SemanticRejectedError) as exc_info:
            parse("hello", ContentType.TEXT, policy=policy)
        e = exc_info.value
        assert "NeverPass" in e.rejected_by
        assert any("semantic_validator_rejected" in v for v in e.violations)

    def test_policy_type_error_attributes(self):
        policy = StrictPolicy(
            allowed_types=frozenset({ContentType.JSON}),
            max_size_bytes=10_000,
            max_depth=10,
        )
        with pytest.raises(PolicyTypeError) as exc_info:
            parse("hello", ContentType.TEXT, policy=policy)
        e = exc_info.value
        assert e.attempted == "text"
        assert "json" in e.allowed
        assert "policy_type_denied" in e.violations

    def test_catch_by_base_class_still_works(self):
        """All failures remain catchable by except ParseError."""
        policy = StrictPolicy(
            allowed_types=frozenset({ContentType.TEXT}),
            max_size_bytes=5,
            max_depth=10,
        )
        with pytest.raises(ParseError):
            parse("too long for the policy", ContentType.TEXT, policy=policy)


# ---------------------------------------------------------------------------
# ParseResult.as_validated()
# ---------------------------------------------------------------------------


class TestAsValidated:
    def test_as_validated_on_validated_passes(self):
        class S(BaseModel):
            name: str

        result = parse('{"name": "Alice"}', ContentType.JSON, schema=S)
        safe = result.as_validated()
        assert safe is result
        assert safe.content["name"] == "Alice"

    def test_as_validated_on_sanitized_raises(self):
        result = parse("hello", ContentType.TEXT)
        assert result.taint == TaintLevel.SANITIZED
        with pytest.raises(ParseError) as exc_info:
            result.as_validated()
        assert "insufficient_taint" in exc_info.value.violations

    def test_as_validated_chains(self):
        """as_validated() is chainable from parse()."""

        class S(BaseModel):
            x: int

        safe = parse('{"x": 42}', ContentType.JSON, schema=S).as_validated()
        assert safe.content["x"] == 42


# ---------------------------------------------------------------------------
# @require_validated
# ---------------------------------------------------------------------------


class TestRequireValidated:
    def test_sync_function_passes_with_validated(self):
        class S(BaseModel):
            name: str

        @require_validated
        def handler(result: ParseResult) -> str:
            return result.content["name"]

        result = parse('{"name": "Bob"}', ContentType.JSON, schema=S)
        assert handler(result) == "Bob"

    def test_sync_function_raises_with_sanitized(self):
        @require_validated
        def handler(result: ParseResult) -> str:
            return str(result.content)

        result = parse("hello", ContentType.TEXT)
        with pytest.raises(ParseError) as exc_info:
            handler(result)
        assert "insufficient_taint" in exc_info.value.violations

    def test_async_function_passes_with_validated(self):
        class S(BaseModel):
            value: int

        @require_validated
        async def async_handler(result: ParseResult) -> int:
            return result.content["value"]

        result = parse('{"value": 7}', ContentType.JSON, schema=S)
        output = asyncio.run(async_handler(result))
        assert output == 7

    def test_async_function_raises_with_sanitized(self):
        @require_validated
        async def async_handler(result: ParseResult) -> str:
            return str(result.content)

        result = parse("hello", ContentType.TEXT)
        with pytest.raises(ParseError):
            asyncio.run(async_handler(result))

    def test_keyword_arg_is_checked(self):
        @require_validated
        def handler(*, result: ParseResult) -> str:
            return str(result.content)

        bad = parse("raw text", ContentType.TEXT)
        with pytest.raises(ParseError):
            handler(result=bad)


# ---------------------------------------------------------------------------
# secure_ingest.testing helpers
# ---------------------------------------------------------------------------


class TestTestingHelpers:
    def test_make_validated_result_taint(self):
        r = make_validated_result({"name": "Alice"})
        assert r.taint == TaintLevel.VALIDATED

    def test_make_validated_result_content_is_frozen(self):
        r = make_validated_result({"user": {"role": "admin"}})
        assert isinstance(r.content, types.MappingProxyType)
        with pytest.raises(TypeError):
            r.content["user"] = "hacked"

    def test_make_validated_result_nested_frozen(self):
        r = make_validated_result({"users": [{"name": "Alice"}]})
        assert isinstance(r.content["users"], tuple)  # list → tuple

    def test_make_validated_passes_require_validated(self):
        @require_validated
        def handler(result: ParseResult) -> str:
            return result.content["name"]

        r = make_validated_result({"name": "test"})
        assert handler(r) == "test"

    def test_make_sanitized_result_taint(self):
        r = make_sanitized_result("some raw text")
        assert r.taint == TaintLevel.SANITIZED

    def test_make_sanitized_fails_require_validated(self):
        @require_validated
        def handler(result: ParseResult) -> str:
            return str(result.content)

        r = make_sanitized_result("raw text")
        with pytest.raises(ParseError):
            handler(r)

    def test_make_validated_custom_provenance(self):
        r = make_validated_result({"x": 1}, provenance="unittest", chain_id="abc123")
        assert r.provenance == "unittest"
        assert r.chain_id == "abc123"

    def test_make_validated_auto_chain_id(self):
        r = make_validated_result({"x": 1})
        assert r.chain_id  # non-empty


# ---------------------------------------------------------------------------
# parse_async()
# ---------------------------------------------------------------------------


class TestParseAsync:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_parse_async_basic(self):
        result = self._run(parse_async("hello", ContentType.TEXT))
        assert result.content == "hello"
        assert result.taint == TaintLevel.SANITIZED

    def test_parse_async_with_schema(self):
        class S(BaseModel):
            x: int

        result = self._run(parse_async('{"x": 1}', ContentType.JSON, schema=S))
        assert result.taint == TaintLevel.VALIDATED
        assert result.content["x"] == 1

    def test_parse_async_with_accepting_validator(self):
        class AlwaysOk:
            async def validate(self, payload: str) -> bool:
                return True

        result = self._run(
            parse_async("hello", ContentType.TEXT, async_semantic_validators=(AlwaysOk(),))
        )
        assert result.content == "hello"

    def test_parse_async_with_rejecting_validator(self):
        class AlwaysBad:
            async def validate(self, payload: str) -> bool:
                return False

        with pytest.raises(SemanticRejectedError) as exc_info:
            self._run(
                parse_async("hello", ContentType.TEXT, async_semantic_validators=(AlwaysBad(),))
            )
        assert "AlwaysBad" in exc_info.value.rejected_by

    def test_parse_async_validators_run_concurrently(self):
        """Multiple validators all awaited — result reflects all rejections."""

        class Bad1:
            async def validate(self, p: str) -> bool:
                return False

        class Bad2:
            async def validate(self, p: str) -> bool:
                return False

        class Good:
            async def validate(self, p: str) -> bool:
                return True

        with pytest.raises(SemanticRejectedError) as exc_info:
            self._run(
                parse_async(
                    "text",
                    ContentType.TEXT,
                    async_semantic_validators=(Bad1(), Good(), Bad2()),
                )
            )
        rejected = exc_info.value.rejected_by
        assert "Bad1" in rejected
        assert "Bad2" in rejected
        assert "Good" not in rejected

    def test_parse_async_raises_parse_error_on_invalid_json(self):
        with pytest.raises(ParseError):
            self._run(parse_async("{bad}", ContentType.JSON))
