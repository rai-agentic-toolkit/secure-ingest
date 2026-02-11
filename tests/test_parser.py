"""Tests for the stateless sandboxed content parser."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secure_ingest.parser import ContentParser, ParseResult, ParserConfig


@pytest.fixture
def parser():
    return ContentParser()


class TestParseValidJSON:
    def test_parse_plain_json_object(self, parser):
        content = json.dumps({"key": "value", "number": 42})
        result = parser.parse(content, "test")
        assert result.success is True
        assert result.parsed_content == {"key": "value", "number": 42}

    def test_parse_nested_json(self, parser):
        content = json.dumps({"outer": {"inner": [1, 2, 3]}})
        result = parser.parse(content, "test")
        assert result.success is True
        assert result.parsed_content["outer"]["inner"] == [1, 2, 3]

    def test_parse_json_embedded_in_text(self, parser):
        content = 'Here is the finding: {"severity": "HIGH", "id": 123} end of report'
        result = parser.parse(content, "test")
        assert result.success is True
        assert result.parsed_content == {"severity": "HIGH", "id": 123}

    def test_metadata_includes_content_type(self, parser):
        result = parser.parse('{"a": 1}', "security_finding")
        assert result.metadata["content_type"] == "security_finding"
        assert "parse_time" in result.metadata


class TestParseInvalidInput:
    def test_empty_content(self, parser):
        result = parser.parse("", "test")
        assert result.success is False
        assert result.error == "empty_content"

    def test_whitespace_only(self, parser):
        result = parser.parse("   \n\t  ", "test")
        assert result.success is False
        assert result.error == "empty_content"

    def test_no_json_found(self, parser):
        result = parser.parse("This is just plain text with no JSON.", "test")
        assert result.success is False
        assert result.error == "no_json_found"

    def test_malformed_json(self, parser):
        result = parser.parse('{"key": "value",}', "test")
        assert result.success is False

    def test_json_array_returns_expected_object_error(self, parser):
        result = parser.parse('[1, 2, 3]', "test")
        assert result.success is False
        assert result.error == "expected_object"


class TestSizeLimit:
    def test_content_within_limit(self):
        parser = ContentParser(ParserConfig(max_content_bytes=100))
        result = parser.parse('{"a": 1}', "test")
        assert result.success is True

    def test_content_exceeds_limit(self):
        parser = ContentParser(ParserConfig(max_content_bytes=10))
        result = parser.parse('{"a": "toolong"}', "test")
        assert result.success is False
        assert result.error == "content_too_large"


class TestStatelessness:
    def test_successive_parses_are_independent(self, parser):
        """Each parse is independent - no state leaks between calls."""
        r1 = parser.parse('{"session": 1}', "test")
        r2 = parser.parse('{"session": 2}', "test")
        assert r1.parsed_content == {"session": 1}
        assert r2.parsed_content == {"session": 2}

    def test_failed_parse_does_not_affect_next(self, parser):
        parser.parse("bad content", "test")  # fails
        result = parser.parse('{"ok": true}', "test")  # should succeed
        assert result.success is True


class TestSecurityProperties:
    def test_no_tools_in_config(self):
        config = ParserConfig()
        assert config.tools == ()

    def test_no_memory_in_config(self):
        config = ParserConfig()
        assert config.memory is False

    def test_no_network_in_config(self):
        config = ParserConfig()
        assert config.network_access is False

    def test_parse_result_is_immutable(self, parser):
        result = parser.parse('{"a": 1}', "test")
        with pytest.raises(AttributeError):
            result.success = False  # type: ignore[misc]
