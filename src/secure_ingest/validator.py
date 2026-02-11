"""Schema validation layer.

Multi-layer validation pipeline:
1. Structural: JSON Schema compliance
2. Format: Field format validation (dates, IDs, ranges)
3. Business logic: Domain-specific rules and constraints

Content that fails ANY layer is rejected.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import jsonschema

from .schemas import SCHEMA_REGISTRY


@dataclass
class ValidationResult:
    """Result of the multi-layer validation pipeline."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    validation_time: float = 0.0


class SchemaValidator:
    """Multi-layer schema validation system.

    Validates content through three independent layers. Any failure
    at any layer means the content is rejected.
    """

    def __init__(self, schemas: dict[str, dict] | None = None) -> None:
        self._schemas = schemas or SCHEMA_REGISTRY

    def validate(self, content: dict[str, Any], content_type: str) -> ValidationResult:
        """Run the full validation pipeline."""
        start = time.monotonic()
        result = ValidationResult(valid=False)

        # Layer 1: Structural - JSON Schema compliance
        schema = self._schemas.get(content_type)
        if schema is None:
            result.errors.append(f"unknown content type: {content_type}")
            result.validation_time = time.monotonic() - start
            return result

        structural_errors = self._validate_structural(content, schema)
        result.errors.extend(structural_errors)
        if structural_errors:
            result.validation_time = time.monotonic() - start
            return result

        # Layer 2: Format validation
        format_errors = self._validate_format(content, content_type)
        result.errors.extend(format_errors)

        # Layer 3: Business logic
        business_errors = self._validate_business_rules(content, content_type)
        result.errors.extend(business_errors)

        result.valid = len(result.errors) == 0
        result.validation_time = time.monotonic() - start
        return result

    @property
    def supported_types(self) -> list[str]:
        return list(self._schemas.keys())

    def _validate_structural(self, content: dict[str, Any], schema: dict) -> list[str]:
        """Layer 1: JSON Schema structural validation."""
        errors: list[str] = []
        validator = jsonschema.Draft202012Validator(schema)
        for error in validator.iter_errors(content):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            errors.append(f"schema: {path}: {error.message}")
        return errors

    def _validate_format(self, content: dict[str, Any], content_type: str) -> list[str]:
        """Layer 2: Format validation beyond JSON Schema."""
        errors: list[str] = []

        if content_type == "security_finding":
            errors.extend(self._validate_security_finding_format(content))
        elif content_type == "analysis_report":
            errors.extend(self._validate_analysis_report_format(content))

        return errors

    def _validate_security_finding_format(self, content: dict[str, Any]) -> list[str]:
        errors: list[str] = []

        # CVSS score must be consistent with severity
        cvss = content.get("cvss_score")
        severity = content.get("severity")
        if cvss is not None and severity is not None:
            expected = _cvss_to_severity(cvss)
            if expected != severity:
                errors.append(
                    f"format: cvss_score {cvss} implies severity {expected}, got {severity}"
                )

        # Description should not be mostly uppercase (screaming = suspicious)
        desc = content.get("description", "")
        if desc and len(desc) > 20:
            upper_ratio = sum(1 for c in desc if c.isupper()) / len(desc)
            if upper_ratio > 0.7:
                errors.append("format: description is mostly uppercase")

        return errors

    def _validate_analysis_report_format(self, content: dict[str, Any]) -> list[str]:
        errors: list[str] = []

        # Overall confidence should be consistent with finding confidences
        overall = content.get("confidence", 0)
        findings = content.get("key_findings", [])
        if findings:
            avg = sum(f.get("confidence", 0) for f in findings) / len(findings)
            if abs(overall - avg) > 0.3:
                errors.append(
                    f"format: overall confidence {overall:.2f} diverges from "
                    f"finding average {avg:.2f}"
                )

        return errors

    def _validate_business_rules(
        self, content: dict[str, Any], content_type: str
    ) -> list[str]:
        """Layer 3: Domain-specific business logic validation."""
        errors: list[str] = []

        # String fields must not contain null bytes
        for key, value in _iter_strings(content):
            if "\x00" in value:
                errors.append(f"business: null byte in field {key}")

        # String fields must not contain excessively long lines without spaces
        # (potential binary/encoded data injection)
        for key, value in _iter_strings(content):
            for line in value.split("\n"):
                if len(line) > 500 and " " not in line:
                    errors.append(
                        f"business: suspicious long unbroken string in field {key}"
                    )

        return errors


def _cvss_to_severity(score: float) -> str:
    """Map CVSS 3.1 score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


def _iter_strings(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Recursively iterate all string values in a nested dict/list."""
    results: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            results.extend(_iter_strings(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            results.extend(_iter_strings(v, f"{prefix}[{i}]"))
    elif isinstance(obj, str):
        results.append((prefix, obj))
    return results
