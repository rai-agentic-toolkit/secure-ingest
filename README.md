# secure-ingest

Strict payload hygiene and validation gateway for Python.

Provides a structural validation boundary that enforces size, depth, encoding, and schema
constraints on untrusted content before it reaches any business logic — AI-adjacent or otherwise.

**Built on Pydantic and defusedxml. Pure Python 3.10+. 458 tests.**

> See [ROADMAP.md](ROADMAP.md) for planned improvements and known architectural gaps.

## Install

```bash
pip install secure-ingest

# With YAML support:
pip install secure-ingest[yaml]
```

## Quick Start

```python
from secure_ingest import parse, ContentType
from pydantic import BaseModel

# Parse untrusted JSON — returns validated data with taint level
result = parse('{\"name\": \"Alice\", \"role\": \"admin\"}', ContentType.JSON)
print(result.content)    # {'name': 'Alice', 'role': 'admin'}
print(result.taint)      # TaintLevel.SANITIZED
print(result.chain_id)   # 'a1b2c3d4e5f6' (correlation ID for tracking)

# Strict schema validation promotes taint to VALIDATED
class UserSchema(BaseModel):
    name: str
    role: str

result = parse('{\"name\": \"Alice\", \"role\": \"admin\"}', ContentType.JSON, schema=UserSchema)
print(result.taint)      # TaintLevel.VALIDATED
print(type(result.content))  # <class 'mappingproxy'> — immutable after validation
```

## What It Does

`secure-ingest` parses untrusted content (from external APIs, user uploads, or inter-service messages) and
returns structurally validated data. It enforces size/depth limits, handles safe deserialization,
optionally validates against Pydantic schemas, and freezes content once validated.

**Design principles:**

- **Stateless** — no side effects, no persistence, pure functions
- **Isolated** — no code execution, no network, no file I/O
- **Deny-by-default** — only explicitly allowed content passes
- **Strict Typing** — uses Pydantic to tightly control data shapes
- **Immutable on VALIDATED** — `result.content` becomes a read-only `MappingProxyType` after schema validation

## Core API vs Pipeline API

`secure-ingest` offers two entry points depending on your needs:

1. **`parse(...)`** (Core API)
   A pure, stateless function. It performs structural validation, payload truncation, and schema checking. Use this when you just want to guarantee that a payload matches a Pydantic schema and isn't a zip bomb or million-token DOS attack. It is fast and has zero dependencies outside of standard Python and Pydantic.

2. **`IngestionPipeline(...)`** (Advanced API)
   A stateful pipeline built *on top* of `parse()`. It adds:
   - **Semantic Anomaly Detection** (prompt injection heuristics)
   - **Request Budgets** (rate limiting and infinite-loop breaking)
   - **Graph Traversal Limits** (preventing infinite tool-call cycles)
   - **Trust Decisions** (explicit Accept/Quarantine/Reject routing)
   Use the pipeline when ingesting content directly into an autonomous agent or executing function calls.

   *Anomaly thresholds can be tuned when constructing the pipeline:*
   ```python
   from secure_ingest import IngestionPipeline, AnomalyConfig

   # Stricter thresholds for highly sensitive agents
   config = AnomalyConfig(quarantine_threshold=0.3, reject_threshold=0.6)
   pipeline = IngestionPipeline(anomaly_config=config)
   ```

## Content Types

| Type | Key Security Features |
| ------ | ---------------------- |
| **JSON** | Depth limiting (zip bomb defense), schema validation |
| **Text** | Length limiting to protect context windows |
| **Markdown** | Markdown limits and strict encoding |
| **YAML** | `safe_load` only (no arbitrary object construction), depth checking |
| **XML** | `defusedxml` protects against XXE, DOCTYPE parsing |

## Taint Tracking

Every `ParseResult` carries a taint level — the trust state of the content:

| Level | Meaning |
| ----- | ------- |
| `UNTRUSTED` | Raw content |
| `SANITIZED` | Parsed; structural limits checked (default after `parse()`) |
| `VALIDATED` | Passed strict Pydantic schema validation; content is frozen (highest trust) |

### Type-level Enforcements

Use type enforcements to explicitly require validated payloads in your application functions:

```python
from secure_ingest import parse, ParseResult, ContentType
from pydantic import BaseModel
import openai

class UserPrompt(BaseModel):
    user_id: int
    query: str

def call_llm(payload: ParseResult):
    # The type signature enforces that only parsed results are accepted.
    # We can guarantee it's validated payload using the decorator @require_validated
    # or by calling .as_validated() when passing it in.
    return openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": str(payload.content)}]
    )

raw_input = '{"user_id": 123, "query": "hello"}'
# .as_validated() will raise a ParseError if the schema validation failed
safe_payload = parse(raw_input, ContentType.JSON, schema=UserPrompt).as_validated()

call_llm(safe_payload)
```

### Provenance & Integrity

Track where content came from and verify it hasn't been tampered with:

```python
result = parse(content, ContentType.JSON, provenance=\"api.example.com/v1/data\")
print(result.provenance)     # 'api.example.com/v1/data'
print(result.chain_id)       # auto-generated correlation ID
print(result.content_hash)   # structural fingerprint (for deduplication)
print(result.raw_hash)       # strict SHA-256 of unparsed input bytes

# Verify integrity downstream
assert result.verify()  # True if structural fingerprint exactly matches content
```

## Policy Enforcement

### Structural Constraints

Enforce structural constraints per-call:

```python
from secure_ingest import parse, StrictPolicy, ContentType

strict = StrictPolicy(
    allowed_types=frozenset({ContentType.JSON, ContentType.YAML}),
    max_size_bytes=1024 * 100, # 100KB limit
    max_depth=5,               # shallow nesting only
)

result = parse(content, ContentType.JSON, policy=strict, schema=my_schema)
parse(content, ContentType.TEXT, policy=strict)  # raises ParseError immediately
```

### Value Rules

Block or require specific patterns in any parsed string fields, evaluated safely AFTER parsing structure:

```python
from secure_ingest import StrictPolicy, ValueRule

policy = StrictPolicy(
    allowed_types=frozenset({ContentType.JSON}),
    max_size_bytes=1024 * 1024,
    value_rules=(
        ValueRule(name=\"no_ssn\", pattern=r\"\\d{3}-\\d{2}-\\d{4}\", action=\"DENY\", description=\"Block SSNs\"),
        ValueRule(name=\"has_id\", pattern=r\"(?i)^id-\\d+$\", action=\"ALLOW\", description=\"Must contain an ID\"),
    )
)
```

### Semantic Validation

Plug in custom classifiers for intent-level checks. This is the correct layer for handling
semantic threats — after structure is validated, before content is trusted:

```python
from secure_ingest import StrictPolicy, ContentType, SemanticValidator

class MyClassifier:
    \"\"\"Implement SemanticValidator.validate() to hook into the parse pipeline.\"\"\"
    def validate(self, payload: str) -> bool:
        # Return True = acceptable, False = reject with ParseError
        return \"<your classifier logic here>\"

policy = StrictPolicy(
    allowed_types=frozenset({ContentType.TEXT}),
    max_size_bytes=1024 * 100,
    max_depth=10,
    semantic_validators=(MyClassifier(),),
)

# ParseError raised if MyClassifier.validate() returns False
result = parse(content, ContentType.TEXT, policy=policy)
```

`SemanticValidator` is a `typing.Protocol` — no base class required. Any class with a
`validate(payload: str) -> bool` method satisfies it.

### Policy Composition

Layer multiple policies with most-restrictive-wins semantics:

```python
org_policy = StrictPolicy(allowed_types=frozenset({ContentType.JSON}), max_size_bytes=1024 * 1024, max_depth=10)
team_policy = StrictPolicy(allowed_types=frozenset({ContentType.JSON}), max_size_bytes=1024 * 100, max_depth=5)

combined = StrictPolicy.compose(org_policy, team_policy)
# max_size_bytes=102400 (smaller wins), max_depth=5
# allowed_types: intersection, value_rules: union, semantic_validators: union
```

### Policy Serialization

Load policies from config files:

```python
from secure_ingest import policy_from_yaml, policy_to_yaml

policy = policy_from_yaml(\"\"\"
allowed_types: [json, yaml]
max_size_bytes: 102400
max_depth: 5
value_rules:
  - name: no_ssn
    pattern: '\\\\d{3}-\\\\d{2}-\\\\d{4}'
    action: DENY
    description: Block SSNs
\"\"\")
```

## CLI

```bash
# Scan content for anomalies
secure-ingest scan content.json

# Scan with policy enforcement
secure-ingest scan --policy policy.yaml content.json

# Full ingestion pipeline (parse + validate + anomaly detection)
secure-ingest ingest --type security_finding --agent agent-001 content.json

# Ingest with policy
secure-ingest ingest --policy policy.yaml --type security_finding content.json

# Read from stdin
echo '{\"data\": \"test\"}' | secure-ingest ingest --type security_finding --stdin

# List available schemas
secure-ingest schemas
```

All commands output structured JSON. Exit codes: 0 = accepted, 1 = rejected, 2 = quarantined.

## Integrations

`secure-ingest` can be used to protect existing AI agent frameworks and web endpoints. We provide detailed recipes for common architectures:

- [FastAPI Integration](docs/integrations/fastapi.md) — Protect webhooks from zip bombs and memory allocation attacks before Pydantic parsing.
- [LlamaIndex Integration](docs/integrations/llamaindex.md) — Secure vector embeddings by filtering out massive or anomalous documents from your `IngestionPipeline`.
- [LangChain Integration](docs/integrations/langchain.md) — Wrap generic tools so untrusted API responses never leak into the LLM context.
- [AutoGen Integration](docs/integrations/autogen.md) — Intercept inter-agent messages via `register_reply` before the receiving agent processes them.
- [CrewAI Integration](docs/integrations/crewai.md) — Validate task outputs before they're handed off to the next agent in the crew.

## Async Support

For FastAPI, LangChain async chains, and AutoGen — use `parse_async()`:

```python
from secure_ingest import parse_async, AsyncSemanticValidator, ContentType

class MyClassifier:
    async def validate(self, payload: str) -> bool:
        result = await my_remote_classifier.score(payload)
        return result.score < 0.8  # True = accept

@app.post("/ingest")
async def ingest(request: Request):
    raw = await request.body()
    result = await parse_async(
        raw, ContentType.JSON,
        schema=MySchema,
        async_semantic_validators=(MyClassifier(),),
    )
    return result.as_validated().content
```

`parse_async()` runs all synchronous validation (parsing, size/depth limits, schema) in a thread executor and awaits async validators concurrently — zero event loop blocking.

## Testing Utilities

Use `secure_ingest.testing` to construct `ParseResult` fixtures in tests without running the full parser. This decouples downstream unit tests from parser internals:

```python
from secure_ingest.testing import make_validated_result, make_sanitized_result
from secure_ingest import require_validated, ParseError
import pytest

def test_my_handler_accepts_validated():
    result = make_validated_result({"user_id": 1, "query": "hello"})
    assert my_handler(result) == "expected output"

def test_my_handler_rejects_sanitized():
    result = make_sanitized_result("raw untrusted text")
    with pytest.raises(ParseError):
        my_handler(result)  # decorated with @require_validated
```

`make_validated_result()` deep-freezes content (`MappingProxyType` for dicts, `tuple` for lists) to match real VALIDATED results. `make_sanitized_result()` produces SANITIZED taint for testing rejection paths.

## Advanced Modules

For production multi-agent services needing loop detection, structured workflow enforcement, and observability, see the [Advanced Modules guide](docs/advanced-modules.md):

- **`IngestionPipeline`** — full stage-by-stage pipeline with audit trail
- **`RequestBudget`** — hard call ceilings + cycle detection (guards against agentic overthinking loops)
- **`StructureMonitor` / `ToolGraph`** — enforce tool calls happen in valid topological order
- **`ReliabilityProfiler`** — tracks 12 metrics across consistency, robustness, predictability, and safety

## Error Handling

All failures raise `ParseError` subclasses, so you can be as precise or coarse as you need:

```python
from secure_ingest import (
    ParseError,           # catch-all
    SizeExceededError,    # e.limit, e.actual
    DepthExceededError,   # e.max_depth
    SchemaValidationError, # e.pydantic_errors
    SemanticRejectedError, # e.rejected_by
    PolicyTypeError,       # e.attempted, e.allowed
)

try:
    result = parse(raw, ContentType.JSON, policy=policy, schema=MySchema)
except SizeExceededError:
    return Response(status_code=413)
except SchemaValidationError as e:
    return Response(status_code=422, content={"errors": e.pydantic_errors})
except ParseError:
    return Response(status_code=400)
```

## Security Model

This acts as a structural and schema boundary — content is parsed into constrained data before it
ever reaches your application logic. Policies are compiled into structure. Validated content is
frozen at the Python level (`MappingProxyType`).

**What it protects against:**

- XML External Entity (XXE) attacks via `defusedxml`
- YAML deserialization attacks
- ZIP bomb / deeply nested structure attacks
- Content tampered after validation (via SHA-256 integrity hashing + `MappingProxyType` freeze)
- Policy drift (via structural enforcement with `StrictPolicy`)
- Data exfiltration patterns (via deny rules)

**What it doesn't do:**

- Runtime behavior monitoring
- Network-level filtering
- Semantic/intent classification (that is your `SemanticValidator` to implement)

**Known limitations:**

- `SchemaValidationError.violations` truncates nested Pydantic field paths to the first segment. The full path is available via `e.pydantic_errors` (list of raw Pydantic error dicts).
- `SemanticAnomalyDetector` inside `IngestionPipeline` has configurable thresholds not yet exposed via `StrictPolicy`. Use `ReliabilityProfiler` to observe its behavior.
- `_compute_content_hash()` hashes the parsed representation, not the raw wire bytes. Two JSON strings that parse to identical dicts produce the same hash (semantic, not wire, identity).

## License

MIT

## Authors

Jesse Castro & Raven
