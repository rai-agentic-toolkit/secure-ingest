"""Async parse interface for secure-ingest.

Drop-in complement to ``parse()`` for async runtimes (FastAPI, aiohttp,
LangChain async chains, AutoGen async agents).

The key addition over the sync interface is ``AsyncSemanticValidator`` — a
Protocol whose ``validate()`` coroutine can await external calls (classifier
APIs, vector DB lookups, etc.) without blocking the event loop.

Usage::

    from secure_ingest.async_parse import parse_async, AsyncSemanticValidator
    from secure_ingest import ContentType, StrictPolicy

    class MyClassifier:
        async def validate(self, payload: str) -> bool:
            result = await my_classifier_client.score(payload)
            return result.score < 0.8

    policy = StrictPolicy(
        allowed_types=frozenset({ContentType.JSON}),
        max_size_bytes=1024 * 100,
        max_depth=10,
    )

    # In a FastAPI route:
    @app.post("/ingest")
    async def ingest(request: Request):
        raw = await request.body()
        result = await parse_async(
            raw,
            ContentType.JSON,
            policy=policy,
            schema=MySchema,
            async_semantic_validators=(MyClassifier(),),
        )
        return result.as_validated().content
"""

from __future__ import annotations

import asyncio
import json
import types
from typing import Any

from pydantic import BaseModel

from .parser import (
    ParseResult, ParseError, SemanticRejectedError,
    ContentType, TaintLevel, StrictPolicy, PatternRegistry,
    BaseSemanticScanner, SemanticValidator,
    parse,  # sync parse handles all structural work
)
from .semantic import SemanticValidator


class AsyncSemanticValidator:
    """Protocol for async semantic validators.

    Implement this if your classifier needs to make network calls —
    an HTTP request to an external API, a vector DB lookup, etc.

    ``parse_async()`` will ``await`` each validator's ``validate()``
    coroutine after structural parsing completes.
    """

    async def validate(self, payload: Any) -> bool:
        """Return True = accept, False = reject (raises SemanticRejectedError)."""
        ...  # pragma: no cover


async def parse_async(
    content: str | bytes,
    content_type: ContentType | str = ContentType.TEXT,
    *,
    strict: bool = True,
    patterns: PatternRegistry | None = None,
    schema: type[BaseModel] | None = None,
    semantic_scanner: BaseSemanticScanner | None = None,
    async_semantic_validators: tuple[AsyncSemanticValidator, ...] = (),
    provenance: str = "",
    chain_id: str = "",
    policy: StrictPolicy | None = None,
    mutation_mode: str = "IGNORE",
) -> ParseResult:
    """Async version of ``parse()`` — awaits async SemanticValidator instances.

    All structural validation (size, depth, schema) runs synchronously via
    the standard ``parse()`` pipeline. Only the async semantic validators are
    awaited, keeping the sync path free of event-loop concerns.

    Args:
        content: Raw content to parse.
        content_type: ``ContentType`` enum or string (``"json"``, ``"text"``...).
        strict: Forward to sync ``parse()``.
        patterns: Optional ``PatternRegistry``.
        schema: Optional Pydantic model for VALIDATED taint promotion.
        semantic_scanner: Legacy sync ``BaseSemanticScanner``.
        async_semantic_validators: Tuple of ``AsyncSemanticValidator`` instances
            whose ``validate()`` coroutines will be awaited concurrently.
        provenance: Origin label for audit.
        chain_id: Correlation ID.
        policy: ``StrictPolicy`` (may also include sync ``semantic_validators``).
        mutation_mode: ``"IGNORE"`` (default), ``"STRIP_AND_WARN"``, ``"REJECT"``.

    Returns:
        ``ParseResult`` — identical contract to sync ``parse()``.

    Raises:
        ``ParseError`` (or subclass) on any validation failure.
        ``SemanticRejectedError`` if any async validator returns ``False``.
    """
    # Run all synchronous parsing in a thread so we don't block the event loop
    # on regex work, defusedxml parsing, or schema validation.
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: parse(
            content,
            content_type,
            strict=strict,
            patterns=patterns,
            schema=schema,
            semantic_scanner=semantic_scanner,
            provenance=provenance,
            chain_id=chain_id,
            policy=policy,
            mutation_mode=mutation_mode,
        ),
    )

    # Run async semantic validators concurrently
    if async_semantic_validators:
        if isinstance(result.content, str):
            text_repr = result.content
        else:
            text_repr = json.dumps(
                dict(result.content) if isinstance(result.content, types.MappingProxyType)
                else result.content,
                default=str,
            )

        # Await all validators concurrently
        outcomes = await asyncio.gather(
            *[v.validate(text_repr) for v in async_semantic_validators],
            return_exceptions=False,
        )

        rejected_by = [
            type(validator).__name__
            for validator, passed in zip(async_semantic_validators, outcomes)
            if not passed
        ]
        if rejected_by:
            raise SemanticRejectedError(
                rejected_by=rejected_by,
                content_type=result.content_type.value,
            )

    return result
