# Roadmap

Items are ordered by priority within each milestone. "Ship blocker" means it affects library correctness or safety for users who've already adopted. "Adoption blocker" means it stops specific developer workflows. "Quality" means it builds long-term confidence and maintainability.

Contributions welcome — if an item has a linked issue, start there.

---

## v2.2.0 — Correctness & Trust

These are the things a senior engineer reviewing this library right now would flag before recommending wider adoption.

### 🔴 `PatternRegistry` is mutable inside a frozen `StrictPolicy` *(ship blocker)*

`@dataclass(frozen=True)` prevents *field rebinding*, not mutation of objects stored in fields. `PatternRegistry.add()` mutates a registry embedded in a supposedly immutable policy. Sharing a `StrictPolicy` across threads or request handlers today is an undetected race condition.

**Fix:** either make `PatternRegistry` copy-on-construct into `StrictPolicy` (snapshotting its patterns into a frozen structure), or expose a `PatternRegistry.freeze()` method that disables `add()` and call it during `StrictPolicy.__post_init__`.

### 🔴 Serialized policy format has no schema version field *(ship blocker)*

The `mutation_mode` default changed from `"REJECT"` to `"IGNORE"` in v2.1.0. Any policy file serialized in v1.x that relied on the default now behaves differently after deserialization — silently. There is no way to detect this without a schema version.

**Fix:** add `schema_version: 2` to `policy_to_dict()` output and validate/migrate on `policy_from_dict()`. Raise a `PolicyVersionError` for unknown versions.

### 🟡 Deprecate `ValidatedPayload` *(adoption blocker)*

`ValidatedPayload` and `ParseResult.as_validated()` now both exist in `__all__`. They do the same thing. Having two paths teaches users the wrong one lives alongside the right one.

**Fix:** attach a `DeprecationWarning` to `ValidatedPayload.__init__` pointing users to `as_validated()`. Remove in v3.0.

### 🟡 Add `py.typed` marker *(adoption blocker for typed codebases)*

Without `py.typed`, mypy and pyright treat the entire library as untyped. All the `Protocol`, `@runtime_checkable`, and generic annotations are invisible to users' type checkers despite being correct.

**Fix:** `touch src/secure_ingest/py.typed` and add `[tool.setuptools.package-data] secure_ingest = ["py.typed"]` to `pyproject.toml`. One-line change, meaningful impact for typed consumers.

---

## v2.3.0 — API Clarity & Docs

### 🟡 Clarify `content_hash` semantics

The hash is computed on the *parsed, normalized representation* — not the raw input bytes. This is correct for deduplication but wrong for tamper detection. The docstring doesn't say which use case is intended.

**Fix:** rename to `content_fingerprint` or add a `raw_hash` field for wire-byte integrity. Document clearly in `ParseResult` docstring and README Security Model section.

### 🟡 Expose `SemanticAnomalyDetector` thresholds via `StrictPolicy`

`IngestionPipeline` runs `SemanticAnomalyDetector` on every call, but its thresholds are internal and not configurable without subclassing `IngestionPipeline`. Users can observe behavior via `ReliabilityProfiler` but cannot tune it declaratively.

**Fix:** add `anomaly_config: AnomalyConfig | None = None` to `StrictPolicy` (or `IngestionPipeline` constructor). Document what triggers quarantine vs. reject.

### 🟢 Unify `content_hash` / `testing._hash()` implementations

`parser._compute_content_hash()` and `testing._hash()` are separate implementations of the same algorithm. If the hashing strategy changes, test fixtures will produce hashes that don't match real parse results.

**Fix:** expose `_compute_content_hash` as a public utility `content_hash_of(content)` in `parser.py` and have `testing.py` import and use it.

---

## v3.0.0 — Architecture

### 🔴 Refactor monolithic `parse()` into composable pipeline stages

`parse()` is 200+ lines with 9 parameters and 6 internal phases: admission, size/type enforcement, value rules, structural parsing, schema validation, semantic validation. Every new feature has been bolted on. This is where future bugs will accumulate.

**Fix:** define internal stage functions with explicit contracts:

```
_admit(content, content_type, policy) -> AdmissionResult
_parse_structure(content, content_type, ...) -> ParseResult
_validate_schema(result, schema) -> ParseResult
_check_value_rules(result, policy) -> ParseResult
_run_semantic(result, validators) -> ParseResult
_promote_taint(result) -> ParseResult
```

Each stage is independently testable. `parse()` becomes an orchestrator of ~15 lines.

### 🟢 Remove `ValidatedPayload` entirely *(follows 2.2.0 deprecation)*

---

## Not Planned (and Why)

| Item | Why not |
|------|---------|
| Pre-body-read HTTP size limiting | Requires HTTP middleware-level streaming integration — out of scope for a pure-Python validation library. Document recommended proxy/gateway patterns instead. |
| Built-in ML classifier SemanticValidator | Would add heavy dependencies (torch/transformers) and opinionated model choices. The `AsyncSemanticValidator` Protocol exists precisely to let callers wire their own. |
| Streaming content parsing | Fundamentally different architecture. All current parsing assumes fully-buffered input. |
