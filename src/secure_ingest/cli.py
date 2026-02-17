"""CLI tool for the Secure Agent Content Ingestion System.

Usage:
    secure-ingest ingest --type security_finding --agent agent-001 content.json
    secure-ingest ingest --type security_finding --agent agent-001 --stdin < content.json
    secure-ingest validate --type security_finding content.json
    secure-ingest scan content.json
    secure-ingest schemas
    echo '{"vulnerability_id": "CVE-2024-1234", ...}' | secure-ingest ingest --type security_finding --agent test --stdin
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .anomaly import SemanticAnomalyDetector
from .pipeline import IngestionPipeline
from .schemas import SCHEMA_REGISTRY
from .validator import SchemaValidator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secure-ingest",
        description="Secure Agent Content Ingestion System",
    )
    sub = parser.add_subparsers(dest="command")

    # --- ingest command ---
    p_ingest = sub.add_parser("ingest", help="Ingest content through the full pipeline")
    p_ingest.add_argument("file", nargs="?", help="Path to content file (JSON or raw text)")
    p_ingest.add_argument("--stdin", action="store_true", help="Read content from stdin")
    p_ingest.add_argument("--type", "-t", required=True, choices=list(SCHEMA_REGISTRY.keys()),
                          help="Content type")
    p_ingest.add_argument("--agent", "-a", default="unknown", help="Source agent ID")
    p_ingest.add_argument("--audit", action="store_true", help="Include audit trail in output")

    # --- validate command ---
    p_validate = sub.add_parser("validate", help="Validate content against a schema (no anomaly detection)")
    p_validate.add_argument("file", nargs="?", help="Path to JSON content file")
    p_validate.add_argument("--stdin", action="store_true", help="Read from stdin")
    p_validate.add_argument("--type", "-t", required=True, choices=list(SCHEMA_REGISTRY.keys()))

    # --- scan command ---
    p_scan = sub.add_parser("scan", help="Scan content for prompt injection patterns")
    p_scan.add_argument("file", nargs="?", help="Path to content file")
    p_scan.add_argument("--stdin", action="store_true", help="Read from stdin")

    # --- schemas command ---
    sub.add_parser("schemas", help="List available content schemas")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "schemas":
        return _cmd_schemas()
    elif args.command == "ingest":
        return _cmd_ingest(args)
    elif args.command == "validate":
        return _cmd_validate(args)
    elif args.command == "scan":
        return _cmd_scan(args)

    return 1


def _read_content(args: argparse.Namespace) -> str | None:
    """Read content from file or stdin."""
    if getattr(args, "stdin", False):
        return sys.stdin.read()
    if hasattr(args, "file") and args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            return None
        return path.read_text(encoding="utf-8")
    print("Error: provide a file path or --stdin", file=sys.stderr)
    return None


def _cmd_schemas() -> int:
    print("Available content schemas:")
    for name, schema in SCHEMA_REGISTRY.items():
        title = schema.get("title", name)
        required = schema.get("required", [])
        props = list(schema.get("properties", {}).keys())
        print(f"\n  {name} ({title})")
        print(f"    Required fields: {', '.join(required)}")
        print(f"    All fields:      {', '.join(props)}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    content = _read_content(args)
    if content is None:
        return 1

    pipeline = IngestionPipeline()
    result = pipeline.ingest(
        source_agent_id=args.agent,
        content_type=args.type,
        raw_content=content,
        include_audit=args.audit,
    )

    output = result.to_dict()
    print(json.dumps(output, indent=2, default=str))

    if result.decision == "accepted":
        return 0
    elif result.decision == "quarantined":
        return 2
    else:
        return 1


def _cmd_validate(args: argparse.Namespace) -> int:
    content = _read_content(args)
    if content is None:
        return 1

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    validator = SchemaValidator()
    result = validator.validate(data, args.type)

    output = {
        "valid": result.valid,
        "errors": result.errors,
        "warnings": result.warnings,
        "validation_time": result.validation_time,
    }
    print(json.dumps(output, indent=2))
    return 0 if result.valid else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    content = _read_content(args)
    if content is None:
        return 1

    # Try to parse as JSON, fall back to treating as raw text
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        data = {"text": content}

    detector = SemanticAnomalyDetector()
    result = detector.analyze(data)

    output = {
        "is_anomaly": result.is_anomaly,
        "composite_score": result.composite_score,
        "component_scores": result.component_scores,
        "decision": result.decision,
        "confidence": result.confidence,
        "triggered_patterns": result.triggered_patterns,
    }
    print(json.dumps(output, indent=2))
    return 0 if not result.is_anomaly else 1


def entry_point() -> None:
    """Entry point for console_scripts — calls main() and exits with its return code."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
