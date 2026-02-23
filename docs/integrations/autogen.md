# Microsoft AutoGen Integration Recipe

## The Problem
In multi-agent conversations, one agent might fetch a massive 5MB payload or generate structurally malformed data and pass it directly to the next agent in the sequence. If left unchecked, this inter-agent message passing explodes the context window of receiving agents or propagates corrupted schema data downward.

## The Architecture
`secure-ingest` intercepts all incoming messages by leveraging AutoGen's `register_reply` middleware hook. Before the receiving agent processes or evaluates the message, the raw string/dict payload is intercepted, parsed, and restricted by strict byte/depth limits, enforcing validation before the agent acts.

## The Recipe

```python
from autogen import ConversableAgent
from secure_ingest import parse, ContentType, ParseError, StrictPolicy
from typing import Dict, Optional, Union

# Define the structural boundary policy for all incoming agents
agent_defense_policy = StrictPolicy(
    allowed_types=frozenset({ContentType.JSON, ContentType.TEXT, ContentType.MARKDOWN}),
    max_size_bytes=1024 * 100,  # Max 100 KB payload per message
    max_depth=5
)

def secure_ingest_middleware(
    recipient: ConversableAgent, 
    messages: Optional[list[Dict]] = None, 
    sender: Optional[ConversableAgent] = None, 
    config: Optional[Any] = None
) -> Union[str, Dict, None]:
    """Middleware hook to intercept and validate raw incoming AutoGen messages."""
    
    if not messages:
        return False, None
        
    latest_message = messages[-1]
    raw_content = latest_message.get("content", "")
    
    # 1. Skip validation if the message is empty or system-generated empty calls
    if not raw_content:
        return False, None
        
    try:
        # 2. Strict Parse and Validate
        result = parse(
            content=raw_content,
            content_type=ContentType.JSON if isinstance(raw_content, dict) else ContentType.TEXT,
            policy=agent_defense_policy,
            provenance=sender.name if sender else "unknown"
        )
        
        # 3. Message is safe. Overwrite the raw context with the validated structure.
        latest_message["content"] = result.content
        return False, None  # False = Continue regular agent processing
        
    except ParseError as e:
        # 4. Message is unsafe. Intercept and block.
        error_reply = f"SYSTEM REJECTION: The previous payload was rejected by structural validation protocols. REASON: {str(e)}"
        
        # True = Halt regular processing and return this error reply immediately to the sender
        return True, error_reply

# -----------------
# Setup Agents
# -----------------
worker = ConversableAgent("data_fetcher", llm_config=...)
manager = ConversableAgent("system_manager", llm_config=...)

# 5. Register the middleware hook on the manager
manager.register_reply(
    [ConversableAgent, None],
    reply_func=secure_ingest_middleware,
    config=None,
    position=1  # Execute this BEFORE other standard AutoGen reply mechanics
)
```

## The Escape Hatch
When `secure-ingest` rejects an inter-agent message (e.g., throwing a `ParseError` due to a 5MB payload), the `secure_ingest_middleware` catches the exception.

Instead of crashing the entire script, the middleware returns `True, error_reply`. AutoGen interprets this as a final response, bypassing the receiving agent entirely and immediately bouncing the error text back to the sending agent. The sender can then iterate and try again with a smaller payload.
