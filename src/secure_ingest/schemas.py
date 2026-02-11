"""Content schemas for the ingestion system.

Defines the strict JSON schemas that all ingested content must conform to.
Content that doesn't match is discarded.
"""

from __future__ import annotations

SECURITY_FINDING_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Security Finding",
    "type": "object",
    "required": ["vulnerability_id", "severity", "description", "recommendation"],
    "properties": {
        "vulnerability_id": {
            "type": "string",
            "pattern": r"^(CVE-[0-9]{4}-[0-9]{4,}|CUSTOM-[A-Z0-9]{8})$",
            "description": "Standardized vulnerability identifier",
        },
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        },
        "cvss_score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 10.0,
        },
        "description": {
            "type": "string",
            "maxLength": 2000,
            "minLength": 10,
        },
        "affected_systems": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$",
                "maxLength": 100,
            },
            "maxItems": 20,
        },
        "recommendation": {
            "type": "string",
            "maxLength": 1000,
            "minLength": 5,
        },
        "references": {
            "type": "array",
            "items": {"type": "string", "format": "uri", "maxLength": 500},
            "maxItems": 10,
        },
    },
    "additionalProperties": False,
}

ANALYSIS_REPORT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Analysis Report",
    "type": "object",
    "required": ["report_id", "analysis_type", "key_findings", "confidence"],
    "properties": {
        "report_id": {
            "type": "string",
            "pattern": r"^RPT-[0-9]{8}-[A-Z0-9]{6}$",
        },
        "analysis_type": {
            "type": "string",
            "enum": [
                "threat_intelligence",
                "market_research",
                "technical_analysis",
                "risk_assessment",
            ],
        },
        "key_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding", "confidence"],
                "properties": {
                    "finding": {"type": "string", "maxLength": 500, "minLength": 5},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "supporting_evidence": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": 200},
                        "maxItems": 5,
                    },
                },
                "additionalProperties": False,
            },
            "minItems": 1,
            "maxItems": 20,
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "methodology": {
            "type": "string",
            "maxLength": 300,
        },
        "data_sources": {
            "type": "array",
            "items": {"type": "string", "maxLength": 200},
            "maxItems": 10,
        },
    },
    "additionalProperties": False,
}

DATA_SUMMARY_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Data Summary",
    "type": "object",
    "required": ["summary_id", "category", "key_points"],
    "properties": {
        "summary_id": {
            "type": "string",
            "pattern": r"^SUM-[0-9]{8}-[A-Z0-9]{6}$",
        },
        "category": {
            "type": "string",
            "enum": ["metrics", "trends", "incidents", "inventory"],
        },
        "key_points": {
            "type": "array",
            "items": {"type": "string", "maxLength": 300, "minLength": 5},
            "minItems": 1,
            "maxItems": 20,
        },
        "numeric_data": {
            "type": "object",
            "additionalProperties": {"type": "number"},
        },
        "time_range": {
            "type": "object",
            "properties": {
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
            },
            "required": ["start", "end"],
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

# Registry of all known content types -> schemas
SCHEMA_REGISTRY: dict[str, dict] = {
    "security_finding": SECURITY_FINDING_SCHEMA,
    "analysis_report": ANALYSIS_REPORT_SCHEMA,
    "data_summary": DATA_SUMMARY_SCHEMA,
}
