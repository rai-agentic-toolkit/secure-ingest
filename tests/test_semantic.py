import pytest

from secure_ingest import parse, ContentType, TaintLevel
from secure_ingest.semantic import BaseSemanticScanner

class DummyScanner(BaseSemanticScanner):
    def scan(self, text: str) -> list[str]:
        if "evil" in text.lower():
            return ["malicious_intent"]
        return []

def test_semantic_scanner_clean_text():
    scanner = DummyScanner()
    result = parse("Hello world", ContentType.TEXT, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "malicious_intent" not in result.warnings
    assert "malicious_intent" not in result.stripped

def test_semantic_scanner_flagged_text():
    scanner = DummyScanner()
    result = parse("I have evil intent", ContentType.TEXT, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "semantic_violation:malicious_intent" in result.warnings
    assert "malicious_intent" in result.stripped

def test_semantic_scanner_json():
    scanner = DummyScanner()
    result = parse('{"message": "I have evil intent"}', ContentType.JSON, semantic_scanner=scanner)
    assert result.taint == TaintLevel.SANITIZED
    assert "semantic_violation:malicious_intent" in result.warnings
    assert "malicious_intent" in result.stripped
