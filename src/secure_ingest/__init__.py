"""secure-ingest: Strict payload hygiene and validation gateway for Python."""

from .parser import (
    parse, ParseResult, ParseError, ContentType, TaintLevel,
    StrictPolicy, InjectionPattern, PatternRegistry, BUILTIN_PATTERNS,
    # Exception hierarchy
    SizeExceededError, DepthExceededError, SchemaValidationError,
    SemanticRejectedError, PolicyTypeError,
    # Trust enforcement
    require_validated,
)
from .rules import ValueRule
from .semantic import SemanticValidator, BaseSemanticScanner
from .async_parse import parse_async, AsyncSemanticValidator
from .serialization import (
    policy_to_dict, policy_from_dict,
    policy_to_json, policy_from_json,
    policy_to_yaml, policy_from_yaml,
    PolicyVersionError,
)
from .budget import (
    BudgetConfig, RequestBudget,
    BudgetExhaustedError, CycleDetectedError,
)
from .pipeline import IngestionPipeline, IngestResult
from .structure import (
    ToolGraph, StructureMonitor, StructureViolationError,
)
from .reliability import ReliabilityProfiler, ReliabilityReport, DimensionScore
from .llm import ValidatedPayload

__version__ = "2.1.0"
__all__ = [
    # Core parse API
    "parse", "parse_async", "ParseResult", "ContentType", "TaintLevel",
    "StrictPolicy", "ValueRule", "InjectionPattern", "PatternRegistry", "BUILTIN_PATTERNS",
    # Exception hierarchy
    "ParseError", "SizeExceededError", "DepthExceededError",
    "SchemaValidationError", "SemanticRejectedError", "PolicyTypeError",
    # Semantic validation
    "SemanticValidator", "AsyncSemanticValidator", "BaseSemanticScanner",
    # Trust enforcement
    "require_validated",
    # Policy serialization
    "policy_to_dict", "policy_from_dict",
    "policy_to_json", "policy_from_json",
    "policy_to_yaml", "policy_from_yaml",
    "PolicyVersionError",
    # Budget & structure
    "BudgetConfig", "RequestBudget",
    "BudgetExhaustedError", "CycleDetectedError",
    "IngestionPipeline", "IngestResult",
    "ToolGraph", "StructureMonitor", "StructureViolationError",
    # Observability
    "ReliabilityProfiler", "ReliabilityReport", "DimensionScore",
    # LLM helpers
    "ValidatedPayload",
]
