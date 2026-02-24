"""secure-ingest: Strict payload hygiene and validation gateway for Python."""

from .anomaly import AnomalyConfig, SemanticAnomalyDetector
from .async_parse import AsyncSemanticValidator, parse_async
from .budget import (
    BudgetConfig,
    BudgetExhaustedError,
    CycleDetectedError,
    RequestBudget,
)
from .llm import ValidatedPayload
from .parser import (
    BUILTIN_PATTERNS,
    ContentType,
    DepthExceededError,
    InjectionPattern,
    ParseError,
    ParseResult,
    PatternRegistry,
    PolicyTypeError,
    SchemaValidationError,
    SemanticRejectedError,
    # Exception hierarchy
    SizeExceededError,
    StrictPolicy,
    TaintLevel,
    content_hash_of,
    parse,
    # Trust enforcement
    require_validated,
)
from .pipeline import IngestionPipeline, IngestResult
from .reliability import DimensionScore, ReliabilityProfiler, ReliabilityReport
from .rules import ValueRule
from .semantic import BaseSemanticScanner, SemanticValidator
from .serialization import (
    PolicyVersionError,
    policy_from_dict,
    policy_from_json,
    policy_from_yaml,
    policy_to_dict,
    policy_to_json,
    policy_to_yaml,
)
from .structure import (
    StructureMonitor,
    StructureViolationError,
    ToolGraph,
)

__version__ = "2.1.0"
__all__ = [
    # Core parse API
    "parse",
    "parse_async",
    "ParseResult",
    "ContentType",
    "TaintLevel",
    "StrictPolicy",
    "ValueRule",
    "InjectionPattern",
    "PatternRegistry",
    "BUILTIN_PATTERNS",
    "content_hash_of",
    # Exception hierarchy
    "ParseError",
    "SizeExceededError",
    "DepthExceededError",
    "SchemaValidationError",
    "SemanticRejectedError",
    "PolicyTypeError",
    # Semantic validation
    "SemanticValidator",
    "AsyncSemanticValidator",
    "BaseSemanticScanner",
    # Trust enforcement
    "require_validated",
    # Policy serialization
    "policy_to_dict",
    "policy_from_dict",
    "policy_to_json",
    "policy_from_json",
    "policy_to_yaml",
    "policy_from_yaml",
    "PolicyVersionError",
    # Budget & structure
    "BudgetConfig",
    "RequestBudget",
    "BudgetExhaustedError",
    "CycleDetectedError",
    "IngestionPipeline",
    "IngestResult",
    "AnomalyConfig",
    "SemanticAnomalyDetector",
    "ToolGraph",
    "StructureMonitor",
    "StructureViolationError",
    # Observability
    "ReliabilityProfiler",
    "ReliabilityReport",
    "DimensionScore",
    # LLM helpers
    "ValidatedPayload",
]
