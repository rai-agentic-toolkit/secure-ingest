"""secure-ingest: Stateless sandboxed content parser for AI agent ingestion."""

from .parser import (
    parse, compose, ParseResult, ParseError, ContentType, TaintLevel,
    Policy, DenyRule, InjectionPattern, PatternRegistry, BUILTIN_PATTERNS,
)
from .schema import Schema, Field, SchemaError
from .serialization import (
    policy_to_dict, policy_from_dict,
    policy_to_json, policy_from_json,
    policy_to_yaml, policy_from_yaml,
)

__version__ = "0.6.0"
__all__ = [
    "parse", "compose", "ParseResult", "ParseError", "ContentType", "TaintLevel",
    "Policy", "DenyRule", "InjectionPattern", "PatternRegistry", "BUILTIN_PATTERNS",
    "Schema", "Field", "SchemaError",
    "policy_to_dict", "policy_from_dict",
    "policy_to_json", "policy_from_json",
    "policy_to_yaml", "policy_from_yaml",
]
