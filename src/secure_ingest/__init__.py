"""secure-ingest: Stateless sandboxed content parser for AI agent ingestion."""

from .parser import (
    parse, compose, ParseResult, ParseError, ContentType, TaintLevel,
    InjectionPattern, PatternRegistry, BUILTIN_PATTERNS,
)
from .schema import Schema, Field, SchemaError

__version__ = "0.2.0"
__all__ = [
    "parse", "compose", "ParseResult", "ParseError", "ContentType", "TaintLevel",
    "InjectionPattern", "PatternRegistry", "BUILTIN_PATTERNS",
    "Schema", "Field", "SchemaError",
]
