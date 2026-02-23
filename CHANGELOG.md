# Changelog

All notable changes to `secure-ingest` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.1.0] — 2026-02-23

### Added

- **Exception hierarchy** — `ParseError` now has typed subclasses, each with structured attributes for precise error handling:
  - `SizeExceededError(limit, actual)` — replaces generic size violation
  - `DepthExceededError(max_depth)` — replaces generic nesting violation
  - `SchemaValidationError(pydantic_errors)` — exposes raw Pydantic error list
  - `SemanticRejectedError(rejected_by)` — names which validators rejected
  - `PolicyTypeError(attempted, allowed)` — names the denied and permitted types
  - All are subclasses of `ParseError`; existing `except ParseError` handlers are unaffected.

- **`ParseResult.as_validated()`** — raises `ParseError(insufficient_taint)` if taint < VALIDATED, returns self otherwise. Chainable from `parse()`.

- **`@require_validated` decorator** — asserts any `ParseResult` argument has VALIDATED taint. Works on both sync and async (coroutine) functions.

- **`secure_ingest.testing` module** — test helpers to construct `ParseResult` fixtures without running the parser:
  - `make_validated_result(content, ...)` — VALIDATED taint, content deep-frozen
  - `make_sanitized_result(content, ...)` — SANITIZED taint

- **`parse_async()` + `AsyncSemanticValidator` Protocol** — async complement to `parse()`. Runs synchronous parsing in a thread executor (no event loop blocking) and concurrently awaits `AsyncSemanticValidator` instances via `asyncio.gather()`.

- **`docs/advanced-modules.md`** — full guide for `IngestionPipeline`, `RequestBudget`, `StructureMonitor`/`ToolGraph`, and `ReliabilityProfiler`.

### Changed

- **`mutation_mode` default changed from `"REJECT"` to `"IGNORE"`** *(breaking)* — injection pattern scanning is now opt-in. Set `mutation_mode="REJECT"` or `mutation_mode="STRIP_AND_WARN"` explicitly to enable it.

- **Deep recursive freeze** — VALIDATED content is now recursively frozen. Previously only the top-level dict was wrapped in `MappingProxyType`; nested dicts remained mutable. Now all nested dicts become `MappingProxyType` and all lists become `tuple`.

- **`pyproject.toml` version** synced to `2.1.0`. `importlib.metadata.version("secure-ingest")` now returns the correct value.

- **Terminology** — removed "sandbox" and "AI Security" claims from docstrings and marketing copy. Updated tagline to "Strict payload hygiene and validation gateway for Python."

- **`SemanticValidator`** — replaced ABC-based `BaseSemanticScanner` with a `typing.Protocol`. Legacy `scan()`-based implementations remain supported via the `BaseSemanticScanner` backward-compat alias.

- **`AsyncSemanticValidator`** — now a `@runtime_checkable Protocol` (was a plain base class). Duck-typing is supported; no inheritance required.

### Fixed

- `import functools` and `import inspect` moved to top-level imports in `parser.py` (were inline mid-file).
- Unused `hints = func.__annotations__` dead code removed from `_enforce_validated`.
- Duplicate `SemanticValidator` import removed from `async_parse.py`.
- `asyncio.get_event_loop()` replaced with `asyncio.get_running_loop()` in `async_parse.py` (deprecated in Python 3.12+, raises in 3.14).

### Known Limitations

- `SchemaValidationError.violations` truncates nested Pydantic field paths to the first segment (e.g., `schema_violation:user_...` for a nested `user.name` error). Full paths are available via `e.pydantic_errors`.
- `SemanticAnomalyDetector` thresholds inside `IngestionPipeline` are not yet exposed via `StrictPolicy`. Use `ReliabilityProfiler` to observe behavior.
- `_compute_content_hash()` hashes the parsed object representation, not raw wire bytes — two JSON strings that parse to identical dicts produce the same hash.
- `testing._hash()` and `parser._compute_content_hash()` are separate implementations of the same algorithm. A future refactor should unify them.

---

## [2.0.0] — 2026-02-21

### Changed

- Complete library rebranding: removed "sandbox", "prompt injection resistant", and "AI Security" claims.
- `SemanticValidator` Protocol introduced; `BaseSemanticScanner` retained as backward-compat alias.
- `StrictPolicy` gains `semantic_validators` field.
- `StrictPolicy.compose()` supports semantic validator union merging.
- README rewritten for factual accuracy.

---

## [1.0.0] — Initial Release

- `parse()` with JSON, YAML, XML, Text, Markdown, Binary content types.
- `StrictPolicy` with `allowed_types`, `max_size_bytes`, `max_depth`, `value_rules`, `patterns`.
- `PatternRegistry` / `InjectionPattern` for configurable pattern scanning.
- `IngestionPipeline`, `RequestBudget`, `StructureMonitor`, `ReliabilityProfiler`.
- 400+ tests.
