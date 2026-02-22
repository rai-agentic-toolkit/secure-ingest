"""Secure LLM Delegation Pattern.

Provides a generic framework-level wrapper to ensure that only 
pre-validated payloads (ParseResult) are sent to underlying LLM SDKs
like OpenAI or Anthropic.

Design principles:
- Zero dependencies (no importing `openai` or `anthropic`)
- Intercepts generation methods
- Enforces a minimum taint level before sending
"""

from dataclasses import dataclass
from typing import Any, Callable
from .parser import ContentType

@dataclass(frozen=True)
class ValidatedPayload:
    """A strictly validated payload ready for backend execution."""
    content: Any
    content_type: ContentType
    chain_id: str
