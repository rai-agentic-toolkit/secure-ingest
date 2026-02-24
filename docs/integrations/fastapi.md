# Bare Metal FastAPI Integration Recipe

## The Problem
Many senior AI engineering teams avoid bloated agent frameworks entirely, preferring high-performance, async Python loops calling LLM SDKs directly. When exposing a webhook or ingestion endpoint that accepts heavy, untrusted text or arbitrary JSON schema payloads, FastAPI's built-in Pydantic validation handles standard schema, but the underlying JSON decoder remains vulnerable to Zip Bombs (billion laughs attacks via deeply nested structures) or massive string allocations *before* Pydantic can even run.

## The Architecture
`secure-ingest` operates as a high-performance middleware or direct route dependency inside FastAPI. By fetching the raw request body as bytes, it enforces structural length, depth, and anomaly checking *before* full deserialization or Pydantic validation occurs, acting as an enterprise-grade WAF (Web Application Firewall) for AI endpoints.

## The Recipe

```python
from fastapi import FastAPI, Request, HTTPException, status
from secure_ingest import parse, ContentType, ParseError, StrictPolicy
from pydantic import BaseModel
import openai

app = FastAPI()

class AnalysisPayload(BaseModel):
    document_id: str
    raw_text: str

# Define an unapologetic structural firewall policy for the endpoint
endpoint_defense_policy = StrictPolicy(
    allowed_types=frozenset({ContentType.JSON}),
    max_size_bytes=1024 * 500,  # Hard 500 KB limit to prevent OOM
    max_depth=5                 # Prevent Zip bomb attacks
)

@app.post("/api/v1/analyze", response_model=dict)
async def analyze_document(request: Request):
    """A heavily guarded webhook that ingests text for LLM analysis."""

    # 1. Fetch raw bytes. Do NOT use await request.json() here,
    # because that triggers the vulnerable Python json decoder.
    body_bytes = await request.body()

    try:
        # 2. Strict C/Rust-backed Parse and Validate
        result = parse(
            content=body_bytes.decode('utf-8'),
            content_type=ContentType.JSON,
            schema=AnalysisPayload,  # Instructs parse() to enforce the Pydantic schema
            policy=endpoint_defense_policy,
            provenance=request.client.host if request.client else "unknown"
        )

    except ParseError as e:
        # 3. If invalid, reject immediately with a 422
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"SECURITY INCIDENT: The payload was structurally rejected. Reason: {str(e)}"
        )

    # 4. Extract strict, validated data (frozen dictionary matching the schema)
    validated_data = result.content

    # 5. Execute Core Business Logic safely (Bare Metal)
    response = await openai.ChatCompletion.acreate(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "Analyze this user document."},
            {"role": "user", "content": validated_data["raw_text"]}
        ]
    )

    return {"analysis": response.choices[0].message.content, "chain_id": result.chain_id}
```

## The Escape Hatch
By utilizing `fastapi.HTTPException`, `secure-ingest` perfectly maps Python-level string allocations and structural validation failures directly to standard HTTP networking concepts.

When an adversary POSTs an 8MB JSON file or attempts a deeply nested Zip bomb, `secure-ingest` raises a `ParseError` instantly, catching the attack *before* `json.loads` allocates memory. FastAPI catches the resulting `HTTPException` and immediately terminates the request with a clean `422 Unprocessable Entity` response, completely insulating your asynchronous workers and background LLM jobs.
