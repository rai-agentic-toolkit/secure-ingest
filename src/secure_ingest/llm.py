"""Secure LLM Delegation Pattern.

Provides a generic framework-level wrapper to ensure that only
pre-validated payloads (ParseResult) are sent to underlying LLM SDKs
like OpenAI or Anthropic.

Design principles:
- Zero dependencies (no importing `openai` or `anthropic`)
- Intercepts generation methods
- Enforces a minimum taint level before sending
"""

import warnings
from dataclasses import dataclass
from typing import Any
from .parser import ContentType


@dataclass(frozen=True)
class ValidatedPayload:
    """A strictly validated payload ready for backend execution.

    .. deprecated:: 2.2.0
        Use ``ParseResult.as_validated()`` instead — it enforces taint level
        inline and returns the same ``ParseResult`` in one chain::

            safe = parse(raw, ContentType.JSON, schema=MySchema).as_validated()

        ``ValidatedPayload`` will be removed in v3.0.
    """

    content: Any
    content_type: ContentType
    chain_id: str

    def __post_init__(self):
        warnings.warn(
            "ValidatedPayload is deprecated and will be removed in v3.0. "
            "Use ParseResult.as_validated() instead: "
            "result = parse(raw, schema=MySchema).as_validated()",
            DeprecationWarning,
            stacklevel=2,
        )
