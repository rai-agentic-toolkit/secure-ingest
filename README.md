# secure-ingest

Payload hygiene and content validation layer for AI agent ingestion.
Prevents structural manipulation, protocol-level garbage, and basic anomalies
at the architectural level — with taint tracking, policy enforcement, and structure safety
for multi-agent flows.

**Zero required dependencies for core execution. Pure Python 3.10+. 400+ tests.**

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

# Parse untrusted JSON — returns sanitized data with taint level
result = parse('{"name": "Alice", "role": "admin"}', ContentType.JSON)
print(result.content)    # {'name': 'Alice', 'role': 'admin'}
print(result.taint)      # TaintLevel.SANITIZED
print(result.chain_id)   # 'a1b2c3d4e5f6' (correlation ID for tracking)

# Strict schema validation promotes taint to VALIDATED
class UserSchema(BaseModel):
    name: str
    role: str

result = parse('{"name": "Alice", "role": "admin"}', ContentType.JSON, schema=UserSchema)
print(result.taint)      # TaintLevel.VALIDATED
```

## What It Does

`secure-ingest` parses untrusted content (from other agents, APIs, user uploads) and
returns sanitized, validated data. It enforces size/depth limits, handles safe deserialization,
and optionally validates against Pydantic schemas.

**Design principles:**

- **Stateless** — no side effects, no persistence, pure functions
- **Sandboxed** — no code execution, no network, no file I/O
- **Deny-by-default** — only explicitly allowed content passes
- **Strict Typing** — Uses Pydantic to tightly control data shapes

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
| `SANITIZED` | Parsed structure limits checked (default after `parse()`) |
| `VALIDATED` | Passed strict `pydantic` schema validation (highest trust) |

### Type-level Enforcements

Use type enforcements to ensure that LLM wrappers don't accidentally receive raw strings or unverified dicts, by taking advantage of `ValidatedPayload`.

```python
from secure_ingest import ValidatedPayload, ContentType

payload = ValidatedPayload(
    content={'name': 'Alice'},
    content_type=ContentType.JSON,
    chain_id="abc-123"
)
```

### Provenance & Integrity

Track where content came from and verify it hasn't been tampered with:

```python
result = parse(content, ContentType.JSON, provenance="api.example.com/v1/data")
print(result.provenance)     # 'api.example.com/v1/data'
print(result.chain_id)       # auto-generated correlation ID
print(result.content_hash)   # SHA-256 digest of parsed content

# Verify integrity downstream
assert result.verify()  # True if content matches stored hash
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
        ValueRule(name="no_ssn", pattern=r"\d{3}-\d{2}-\d{4}", action="DENY", description="Block SSNs"),
        ValueRule(name="has_id", pattern=r"(?i)^id-\d+$", action="ALLOW", description="Must contain an ID"),
    )
)
```

### Policy Composition

Layer multiple policies with most-restrictive-wins semantics:

```python
org_policy = StrictPolicy(allowed_types=frozenset({ContentType.JSON}), max_size_bytes=1024 * 1024, max_depth=10)
team_policy = StrictPolicy(allowed_types=frozenset({ContentType.JSON}), max_size_bytes=1024 * 100, max_depth=5)

combined = StrictPolicy.compose(org_policy, team_policy)
# max_size_bytes=102400 (smaller wins), max_depth=5
# allowed_types: intersection, value_rules: union
```

Composition can only tighten constraints, never loosen them. Raises `ValueError`
if the resulting policy would allow zero content types.

### Policy Serialization

Load policies from config files:

```python
from secure_ingest import policy_from_yaml, policy_to_yaml

# Load from YAML
policy = policy_from_yaml("""
allowed_types: [json, yaml]
max_size_bytes: 102400
max_depth: 5
value_rules:
  - name: no_ssn
    pattern: '\\d{3}-\\d{2}-\\d{4}'
    action: DENY
    description: Block SSNs
  - name: has_id
    pattern: '^id-\\d+$'
    action: ALLOW
    description: Must contain ID field
""")
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
echo '{"data": "test"}' | secure-ingest ingest --type security_finding --stdin

# List available schemas
secure-ingest schemas
```

All commands output structured JSON. Exit codes: 0 = accepted, 1 = rejected, 2 = quarantined.

## Security Model

This acts as a structural boundary — content is parsed into constrained data before it ever reaches your agent's LLM context window. Policies are compiled into structure.

**What it protects against:**

- XML External Entity (XXE) attacks via `defusedxml`
- YAML deserialization attacks
- ZIP bomb / deeply nested structure attacks
- Taint confusion in multi-agent pipelines (via taint tracking and `ValidatedPayload`)
- Content tampering (via SHA-256 integrity hashing)
- Policy drift (via structural enforcement with `StrictPolicy`)
- Data exfiltration patterns (via deny rules)

**What it doesn't do:**

- Runtime behavior monitoring
- Network-level filtering
- LLM output validation

## License

MIT

## Authors

Jesse Castro & Raven
