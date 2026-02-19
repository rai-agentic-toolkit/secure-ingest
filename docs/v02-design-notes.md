# secure-ingest v0.2 Design Notes

## Research Input: PCAS (Policy Compiler for Agentic Systems)

**Paper:** arXiv:2602.16708v1 (2026-02-18)
**Key idea:** Model agentic system state as a dependency graph to track
information flow and enforce policies deterministically.

### What PCAS Does That We Don't (Yet)

1. **Information flow tracking.** PCAS tracks *where* data came from and
   *what* it influenced — a causal dependency graph. secure-ingest v0.1
   sanitizes content in isolation. It doesn't know that field A was used
   to construct prompt B, which was sent to agent C. That's a gap.

2. **Transitive taint.** If untrusted content touches a field, everything
   derived from that field is also tainted. We strip injections at parse
   time, but a consumer could concatenate our "clean" output with
   untrusted data downstream. We can't prevent that, but we could provide
   taint metadata to help consumers track it.

3. **Policy compilation vs. runtime detection.** PCAS compiles policies
   into the system structure, not into prompts. This aligns perfectly
   with our "architectural defense over detection" principle. v0.1 does
   pattern matching (detection). v0.2 should add structural guarantees.

### Concrete Ideas for v0.2

#### 1. Taint Tracking in ParseResult

Add provenance metadata to `ParseResult`:

```python
@dataclass
class ParseResult:
    content: Any
    sanitized: bool
    warnings: list[str]
    stripped: list[str]
    # NEW in v0.2:
    taint: TaintLevel  # UNTRUSTED | SANITIZED | VALIDATED
    provenance: str     # source identifier
    chain_id: str       # for tracking through multi-hop flows
```

This lets consumers build their own dependency graphs. When agent A
passes content to agent B, B can see: "this was parsed by secure-ingest,
taint=SANITIZED, provenance=agent-A, chain_id=abc123."

#### 2. Policy Profiles

Instead of one-size-fits-all sanitization, let consumers define policies:

```python
policy = Policy(
    allow_patterns=["json", "markdown"],
    max_depth=5,
    require_schema=True,
    taint_propagation="strict",  # any tainted field taints the parent
)
result = parse(content, "json", policy=policy)
```

This is the "compilation" step from PCAS — the policy is structural,
not a prompt instruction that can be subverted.

#### 3. Composition Safety

Add a `compose()` function that safely combines multiple ParseResults:

```python
combined = compose(result_a, result_b, policy=policy)
# Taint level = max(result_a.taint, result_b.taint)
# Chain tracks both provenance sources
```

This addresses the transitive taint problem without requiring consumers
to implement their own tracking.

### What NOT to Do

- Don't build a full dependency graph engine. That's PCAS's job. We're
  a library, not a framework.
- Don't add runtime state. secure-ingest must stay stateless. Taint
  metadata is *output*, not stored state.
- Don't try to enforce downstream behavior. We provide the metadata;
  consumers decide what to do with it.

### Also Relevant

**arXiv:2602.16666v1** — "Towards a Science of AI Agent Reliability"
proposes 12 reliability metrics (consistency, robustness, predictability,
safety). We should evaluate secure-ingest against these dimensions,
especially robustness (does sanitization hold under adversarial
perturbation?) and consistency (same input → same output, always?).

v0.1 already scores well on these by design (stateless = consistent,
pattern-based = predictable). But formal evaluation would strengthen
the README and build trust with adopters.

---

### Implementation Status

All three v0.2 features are now shipped:

1. **Taint tracking** — ✅ HB54. `TaintLevel`, `provenance`, `chain_id` on `ParseResult`.
2. **Policy profiles** — ✅ HB55. `Policy` dataclass with `allowed_types`, `max_depth`,
   `max_size`, `require_schema`, `patterns`, `strip_injections`. 23 tests.
3. **Composition safety** — ✅ HB54. `compose()` with min-taint propagation.

Version bumped to 0.2.1. 211 tests total.

*Written during HB53, 2026-02-19. Updated HB55.*
