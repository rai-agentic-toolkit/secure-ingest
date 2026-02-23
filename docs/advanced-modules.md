# Advanced Modules

These modules make up the full ingestion pipeline. You don't need all of them — start with `parse()` alone, then add layers as you need them.

---

## `IngestionPipeline` — The Full Stack

**When to use it**: You're building a service that receives content from multiple agents or sources and need a single, observable entry point with audit trails.

`IngestionPipeline` wires all components together in a fixed sequence:

```
Budget check → Structure check → Admission → Parse → Schema Validate → Anomaly Detect → Promote to TRUSTED
```

```python
from secure_ingest import IngestionPipeline, IngestResult

pipeline = IngestionPipeline()
result: IngestResult = pipeline.ingest(
    source_agent_id="agent-001",
    content_type="security_finding",  # must match a registered schema
    raw_content='{"vulnerability_id": "CVE-2024-1234", "severity": "HIGH", ...}',
    include_audit=True,               # capture full stage-by-stage trail
)

print(result.decision)          # "accepted" | "quarantined" | "rejected"
print(result.validated_content) # dict if accepted, None otherwise
print(result.audit_trail)       # list of {stage, action, details} dicts
```

> [!NOTE]
> `content_type` values like `"security_finding"` and `"analysis_report"` map to registered Pydantic schemas in `schemas.py`. Unknown types fall back to raw JSON parsing.

**Exit codes when used via CLI**: `0` = accepted, `1` = rejected, `2` = quarantined.

---

## `RequestBudget` — Loop and Amplification Guard

**When to use it**: Any multi-turn agent loop where you need hard guarantees that the agent can't spend more than N tool calls, or get stuck in a cycle.

The research motivation: agentic overthinking loops have been shown to amplify token usage up to **142x** (arXiv:2602.14798). `RequestBudget` catches this structurally before it hits your LLM.

```python
from secure_ingest import BudgetConfig, RequestBudget, BudgetExhaustedError, CycleDetectedError

config = BudgetConfig(
    max_calls=20,           # hard ceiling across all tools
    max_calls_per_tool=5,   # per-tool ceiling
    max_cycle_repeats=2,    # raise if same tool sequence repeats > 2x
)

budget = RequestBudget(config)

# Call before each tool invocation in your agent loop:
try:
    budget.record("fetch_data")
    budget.record("analyze")
    budget.record("fetch_data")  # fine
    budget.record("analyze")     # fine
    budget.record("fetch_data")  # CycleDetectedError: fetch_data -> analyze repeated 2x
except CycleDetectedError as e:
    print(f"Loop detected: {e.cycle} repeated {e.occurrences}x")
except BudgetExhaustedError as e:
    print(f"Budget gone: {e.budget_type} at {e.current}/{e.limit}")
```

Pass the budget into the pipeline to get automatic enforcement:

```python
pipeline = IngestionPipeline(budget=RequestBudget(BudgetConfig(max_calls=10)))
```

---

## `StructureMonitor` + `ToolGraph` — Tool-Call Topology Enforcement

**When to use it**: You have a defined workflow and want to guarantee agents follow it — reject any tool calls that occur out of sequence.

```python
from secure_ingest import ToolGraph, StructureMonitor, StructureViolationError

# Define valid workflow transitions
graph = ToolGraph(
    entry_points=frozenset({"ingest:security_finding"}),
    transitions={
        "ingest:security_finding": frozenset({"ingest:analysis_report"}),
        "ingest:analysis_report": frozenset(),  # terminal
    },
    mode="allow",  # only listed transitions are valid
)

monitor = StructureMonitor(graph)

try:
    monitor.check("ingest:security_finding")  # OK — valid entry point
    monitor.check("ingest:analysis_report")   # OK — valid transition
    monitor.check("ingest:security_finding")  # StructureViolationError — not a valid transition from analysis_report
except StructureViolationError as e:
    print(f"Out-of-sequence tool call: {e}")
```

```python
# Pass into the pipeline:
pipeline = IngestionPipeline(structure_monitor=monitor)
```

---

## `ReliabilityProfiler` — Observability Wrapper

**When to use it**: Staging environments, evaluation runs, or any time you want to measure how your pipeline is actually behaving across a session.

Wraps `IngestionPipeline` transparently and tracks 12 metrics across 4 dimensions: **Consistency**, **Robustness**, **Predictability**, and **Safety**.

```python
from secure_ingest import IngestionPipeline, ReliabilityProfiler

pipeline = IngestionPipeline()
profiler = ReliabilityProfiler(pipeline)

# Use profiler.ingest() instead of pipeline.ingest() — same API
for content in my_agent_session:
    result = profiler.ingest(
        source_agent_id=content.agent_id,
        content_type=content.type,
        raw_content=content.body,
    )

report = profiler.report()
print(report.summary())
# ReliabilityReport(calls=47, overall=0.91, [cons=0.98, robu=1.00, pred=0.87, safe=0.79])

# Full structured output for dashboards:
import json
print(json.dumps(report.to_dict(), indent=2))
```

**Metrics by dimension:**

| Dimension | Metrics |
|-----------|---------|
| Consistency | Decision consistency rate, anomaly score stability |
| Robustness | Parse success rate, exception-free rate |
| Predictability | Budget utilization, stage completion rate, decision entropy |
| Safety | Acceptance rate, violation rate, anomaly rate, safety score |

All scores normalized to `[0, 1]` where `1.0 = best possible`.

---

## Putting It All Together

```python
from secure_ingest import (
    IngestionPipeline, RequestBudget, BudgetConfig,
    ToolGraph, StructureMonitor, ReliabilityProfiler,
)

pipeline = IngestionPipeline(
    budget=RequestBudget(BudgetConfig(max_calls=50, max_cycle_repeats=3)),
    structure_monitor=StructureMonitor(
        ToolGraph(
            entry_points=frozenset({"ingest:security_finding"}),
            transitions={"ingest:security_finding": frozenset({"ingest:analysis_report"})},
            mode="allow",
        )
    ),
)

profiler = ReliabilityProfiler(pipeline)

# Your agent loop:
result = profiler.ingest(source_agent_id="agent-001", content_type="security_finding", raw_content=raw)
report = profiler.report()
```
