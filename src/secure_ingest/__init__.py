"""secure-ingest: Strict payload hygiene and validation gateway for Python."""

from .parser import (
    parse, ParseResult, ParseError, ContentType, TaintLevel,
    StrictPolicy, InjectionPattern, PatternRegistry, BUILTIN_PATTERNS,
)
from .rules import ValueRule
from .semantic import SemanticValidator, BaseSemanticScanner
from .serialization import (
    policy_to_dict, policy_from_dict,
    policy_to_json, policy_from_json,
    policy_to_yaml, policy_from_yaml,
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

__version__ = "2.0.0"
__all__ = [
    "parse", "ParseResult", "ParseError", "ContentType", "TaintLevel",
    "StrictPolicy", "ValueRule", "InjectionPattern", "PatternRegistry", "BUILTIN_PATTERNS",
    "SemanticValidator", "BaseSemanticScanner",
    "policy_to_dict", "policy_from_dict",
    "policy_to_json", "policy_from_json",
    "policy_to_yaml", "policy_from_yaml",
    "BudgetConfig", "RequestBudget",
    "BudgetExhaustedError", "CycleDetectedError",
    "IngestionPipeline", "IngestResult",
    "ToolGraph", "StructureMonitor", "StructureViolationError",
    "ReliabilityProfiler", "ReliabilityReport", "DimensionScore",
    "ValidatedPayload"
]
