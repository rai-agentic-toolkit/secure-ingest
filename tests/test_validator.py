"""Tests for the schema validation layer."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secure_ingest.validator import SchemaValidator, ValidationResult


@pytest.fixture
def validator():
    return SchemaValidator()


# --- Valid content fixtures ---

VALID_SECURITY_FINDING = {
    "vulnerability_id": "CVE-2024-12345",
    "severity": "HIGH",
    "cvss_score": 7.5,
    "description": "SQL injection vulnerability in user authentication module allows attackers to bypass login.",
    "affected_systems": ["auth-service", "user-db"],
    "recommendation": "Apply security patches and parameterize all SQL queries.",
}

VALID_ANALYSIS_REPORT = {
    "report_id": "RPT-20240115-A1B2C3",
    "analysis_type": "threat_intelligence",
    "key_findings": [
        {"finding": "New malware variant detected targeting financial sector", "confidence": 0.85},
        {"finding": "Attack patterns consistent with known APT group", "confidence": 0.72},
    ],
    "confidence": 0.78,
    "methodology": "Automated threat feed analysis combined with manual review",
}

VALID_DATA_SUMMARY = {
    "summary_id": "SUM-20240115-X1Y2Z3",
    "category": "metrics",
    "key_points": [
        "System uptime at 99.97% for the month",
        "Alert volume decreased 15% from previous period",
    ],
    "numeric_data": {"uptime_percent": 99.97, "alert_count": 142},
}


class TestStructuralValidation:
    def test_valid_security_finding(self, validator):
        result = validator.validate(VALID_SECURITY_FINDING, "security_finding")
        assert result.valid is True
        assert result.errors == []

    def test_valid_analysis_report(self, validator):
        result = validator.validate(VALID_ANALYSIS_REPORT, "analysis_report")
        assert result.valid is True

    def test_valid_data_summary(self, validator):
        result = validator.validate(VALID_DATA_SUMMARY, "data_summary")
        assert result.valid is True

    def test_unknown_content_type(self, validator):
        result = validator.validate({"a": 1}, "nonexistent_type")
        assert result.valid is False
        assert any("unknown content type" in e for e in result.errors)

    def test_missing_required_field(self, validator):
        incomplete = {"vulnerability_id": "CVE-2024-12345", "severity": "HIGH"}
        result = validator.validate(incomplete, "security_finding")
        assert result.valid is False
        assert any("required" in e.lower() for e in result.errors)

    def test_additional_properties_rejected(self, validator):
        finding = {**VALID_SECURITY_FINDING, "extra_field": "should fail"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False

    def test_invalid_enum_value(self, validator):
        finding = {**VALID_SECURITY_FINDING, "severity": "SUPER_HIGH"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False

    def test_cvss_out_of_range(self, validator):
        finding = {**VALID_SECURITY_FINDING, "cvss_score": 11.0}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False

    def test_invalid_vulnerability_id_pattern(self, validator):
        finding = {**VALID_SECURITY_FINDING, "vulnerability_id": "bad-id"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False

    def test_description_too_short(self, validator):
        finding = {**VALID_SECURITY_FINDING, "description": "short"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False


class TestFormatValidation:
    def test_cvss_severity_mismatch(self, validator):
        """CVSS 9.5 should map to CRITICAL, not HIGH."""
        finding = {**VALID_SECURITY_FINDING, "cvss_score": 9.5, "severity": "HIGH"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False
        assert any("cvss_score" in e and "CRITICAL" in e for e in result.errors)

    def test_cvss_severity_match(self, validator):
        finding = {**VALID_SECURITY_FINDING, "cvss_score": 7.5, "severity": "HIGH"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is True

    def test_mostly_uppercase_description(self, validator):
        finding = {
            **VALID_SECURITY_FINDING,
            "description": "THIS IS ALL UPPERCASE TEXT AND VERY SUSPICIOUS LOOKING CONTENT HERE",
        }
        result = validator.validate(finding, "security_finding")
        assert result.valid is False
        assert any("uppercase" in e for e in result.errors)

    def test_confidence_divergence(self, validator):
        """Overall confidence 0.1 with average finding confidence 0.85 should fail."""
        report = {
            **VALID_ANALYSIS_REPORT,
            "confidence": 0.1,
            "key_findings": [
                {"finding": "Finding with high confidence score", "confidence": 0.9},
                {"finding": "Another finding with high confidence", "confidence": 0.8},
            ],
        }
        result = validator.validate(report, "analysis_report")
        assert result.valid is False
        assert any("diverges" in e for e in result.errors)


class TestBusinessRules:
    def test_null_byte_in_field(self, validator):
        finding = {**VALID_SECURITY_FINDING, "description": "Has a null\x00byte in here for injection"}
        result = validator.validate(finding, "security_finding")
        assert result.valid is False
        assert any("null byte" in e for e in result.errors)

    def test_long_unbroken_string(self, validator):
        """Very long string without spaces suggests encoded/binary data."""
        finding = {
            **VALID_SECURITY_FINDING,
            "description": "x" * 600,  # 600 chars no spaces
        }
        result = validator.validate(finding, "security_finding")
        assert result.valid is False
        assert any("unbroken string" in e for e in result.errors)

    def test_validation_time_is_recorded(self, validator):
        result = validator.validate(VALID_SECURITY_FINDING, "security_finding")
        assert result.validation_time > 0

    def test_supported_types(self, validator):
        types = validator.supported_types
        assert "security_finding" in types
        assert "analysis_report" in types
        assert "data_summary" in types
