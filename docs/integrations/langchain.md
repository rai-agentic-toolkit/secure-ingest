# LangChain Integration Recipe

## The Problem
LangChain tools blindly execute and return raw strings or generic dictionaries straight back into the LLM context window. An agent fetching a malicious or 5MB-large payload from an external API will instantly consume its context window and potentially poison its conversational trace.

## The Architecture
`secure-ingest` sits inside the LangChain `@tool` decorator. As soon as the external data is fetched by the tool, it is passed through `secure-ingest.parse()` before the tool returns to the LangChain orchestration loop.

## The Recipe

```python
from langchain.tools import tool
from langchain_core.tools import ToolException
from secure_ingest import parse, ContentType, ParseError, StrictPolicy
import requests
from pydantic import BaseModel

class ExternalDataSchema(BaseModel):
    id: int
    payload: str
    status: str

# Define a strict structural policy for the tool's bounds
safe_policy = StrictPolicy(
    allowed_types=frozenset({ContentType.JSON}),
    max_size_bytes=1024 * 50,  # 50 KB max
    max_depth=5
)

@tool(handle_tool_error=True)
def fetch_user_data(user_id: str) -> dict:
    """Fetches user data from an external API and strictly validates it."""
    
    # 1. Untrusted fetch
    response = requests.get(f"https://api.example.com/users/{user_id}")
    raw_payload = response.text
    
    try:
        # 2. Strict Parse and Validate
        result = parse(
            content=raw_payload,
            content_type=ContentType.JSON,
            schema=ExternalDataSchema,
            policy=safe_policy
        )
        # 3. Return the sanitized dict back to LangChain
        return result.content
        
    except ParseError as e:
        # 4. If invalid, throw a Native LangChain ToolException
        raise ToolException(f"Failed to ingest: payload structurally invalid or too large. Details: {str(e)}")
```

## The Escape Hatch
By utilizing LangChain's native `handle_tool_error=True` flag combined with `ToolException`, LangChain's orchestrator automatically catches the `ParseError` raised by `secure-ingest`.

Instead of crashing the application, LangChain intercepts the `ToolException`, passes the secure error message back to the LLM agent, and allows the agent to self-correct ("The payload was too large, I should try a different endpoint"). The malicious or oversized payload never touches the LLM context.
