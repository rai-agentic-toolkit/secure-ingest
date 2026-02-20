"""Tests for the CLI module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from secure_ingest.cli import main


@pytest.fixture
def json_file(tmp_path: Path) -> Path:
    """Create a temporary JSON file with valid security finding content."""
    data = {
        "vulnerability_id": "CVE-2024-1234",
        "severity": "HIGH",
        "description": "Test vulnerability found in the system component",
        "recommendation": "Update to the latest version immediately",
    }
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def policy_yaml(tmp_path: Path) -> Path:
    """Create a temporary YAML policy file."""
    content = """\
allowed_types:
  - json
  - text
max_size: 10000
strip_injections: true
deny_rules:
  - name: block_secrets
    pattern: "SECRET_KEY=[A-Za-z0-9]+"
    description: Block content containing secret keys
"""
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def policy_json(tmp_path: Path) -> Path:
    """Create a temporary JSON policy file."""
    data = {
        "allowed_types": ["json", "text"],
        "max_size": 10000,
        "strip_injections": True,
        "deny_rules": [
            {
                "name": "block_secrets",
                "pattern": "SECRET_KEY=[A-Za-z0-9]+",
                "description": "Block content containing secret keys",
            }
        ],
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_no_command_shows_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = main([])
        assert result == 1

    def test_schemas_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = main(["schemas"])
        assert result == 0
        captured = capsys.readouterr()
        assert "security_finding" in captured.out

    def test_ingest_missing_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = main(["ingest", "--type", "security_finding", "nonexistent.json"])
        assert result == 1
        captured = capsys.readouterr()
        assert "file not found" in captured.err

    def test_ingest_no_file_no_stdin(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = main(["ingest", "--type", "security_finding"])
        assert result == 1

    def test_ingest_valid_file(
        self, json_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["ingest", "--type", "security_finding", str(json_file)])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "accepted"
        assert result == 0

    def test_scan_valid_content(
        self, json_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["scan", str(json_file)])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "is_anomaly" in output
        assert result == 0

    def test_validate_valid_content(
        self, json_file: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["validate", "--type", "security_finding", str(json_file)])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["valid"] is True
        assert result == 0


class TestCLIPolicy:
    """Test --policy flag integration."""

    def test_ingest_with_yaml_policy(
        self,
        json_file: Path,
        policy_yaml: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        result = main([
            "ingest",
            "--type", "security_finding",
            "--policy", str(policy_yaml),
            str(json_file),
        ])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "accepted"
        assert result == 0

    def test_ingest_with_json_policy(
        self,
        json_file: Path,
        policy_json: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        result = main([
            "ingest",
            "--type", "security_finding",
            "--policy", str(policy_json),
            str(json_file),
        ])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "accepted"
        assert result == 0

    def test_ingest_policy_deny_rule_blocks(
        self, tmp_path: Path, policy_yaml: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Content matching a deny rule should be rejected."""
        data = {
            "vulnerability_id": "CVE-2024-5678",
            "severity": "LOW",
            "description": "Contains SECRET_KEY=abc123def secret leak detected",
            "recommendation": "Rotate the compromised key immediately",
        }
        content_file = tmp_path / "secret.json"
        content_file.write_text(json.dumps(data), encoding="utf-8")

        result = main([
            "ingest",
            "--type", "security_finding",
            "--policy", str(policy_yaml),
            str(content_file),
        ])
        # The deny rule should cause a parse failure → rejection
        assert result == 1

    def test_scan_with_policy(
        self,
        json_file: Path,
        policy_yaml: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        result = main([
            "scan",
            "--policy", str(policy_yaml),
            str(json_file),
        ])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["policy_applied"] is True
        assert result == 0

    def test_scan_with_policy_deny(
        self, tmp_path: Path, policy_yaml: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scan with policy should reject content matching deny rules."""
        content_file = tmp_path / "bad.txt"
        content_file.write_text("This has SECRET_KEY=hunter2 in it", encoding="utf-8")

        result = main([
            "scan",
            "--policy", str(policy_yaml),
            str(content_file),
        ])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["rejected"] is True
        assert result == 1

    def test_policy_file_not_found(self, json_file: Path) -> None:
        with pytest.raises(SystemExit):
            main([
                "ingest",
                "--type", "security_finding",
                "--policy", "/nonexistent/policy.yaml",
                str(json_file),
            ])

    def test_policy_unsupported_format(
        self, tmp_path: Path, json_file: Path
    ) -> None:
        bad_policy = tmp_path / "policy.toml"
        bad_policy.write_text("x = 1", encoding="utf-8")
        with pytest.raises(SystemExit):
            main([
                "ingest",
                "--type", "security_finding",
                "--policy", str(bad_policy),
                str(json_file),
            ])

    def test_ingest_with_audit_and_policy(
        self,
        json_file: Path,
        policy_yaml: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        result = main([
            "ingest",
            "--type", "security_finding",
            "--policy", str(policy_yaml),
            "--audit",
            str(json_file),
        ])
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "accepted"
        assert "audit_trail" in output
        assert result == 0


class TestParserConfigPolicy:
    """Test that ParserConfig passes policy through to parse()."""

    def test_content_parser_with_policy(self, policy_yaml: Path) -> None:
        from secure_ingest.parser import ContentParser, ParserConfig, Policy
        from secure_ingest.serialization import policy_from_yaml

        policy = policy_from_yaml(policy_yaml.read_text())
        config = ParserConfig(policy=policy)
        parser = ContentParser(config)

        result = parser.parse('{"key": "value"}', "json")
        assert result.success is True

    def test_content_parser_policy_blocks_denied(self, policy_yaml: Path) -> None:
        from secure_ingest.parser import ContentParser, ParserConfig
        from secure_ingest.serialization import policy_from_yaml

        policy = policy_from_yaml(policy_yaml.read_text())
        config = ParserConfig(policy=policy)
        parser = ContentParser(config)

        result = parser.parse('{"secret": "SECRET_KEY=abc123"}', "json")
        assert result.success is False
