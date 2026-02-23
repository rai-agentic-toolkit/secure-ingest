"""Pluggable semantic validation interface for secure-ingest.

Provides the ``SemanticValidator`` Protocol so callers can inject
custom classifiers (ONNX, external API, regex heuristics, etc.)
without coupling the core library to any ML dependency.

Usage::

    from secure_ingest.semantic import SemanticValidator
    from secure_ingest import StrictPolicy, ContentType

    class MyClassifier:
        def validate(self, payload: str) -> bool:
            # Return True = payload is acceptable, False = reject it
            return "evil" not in payload.lower()

    policy = StrictPolicy(
        allowed_types=frozenset({ContentType.TEXT}),
        max_size_bytes=1024 * 100,
        max_depth=10,
        semantic_validators=(MyClassifier(),),
    )
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SemanticValidator(Protocol):
    """Protocol for pluggable semantic payload validators.

    Implement this interface to hook a custom classifier into the
    ``secure-ingest`` parse pipeline. The validator is called **after**
    structural parsing and ValueRule enforcement, but **before** the
    taint level is promoted to ``VALIDATED``.

    A validator should be stateless and raise no exceptions — return
    ``False`` to signal rejection; ``parse()`` will raise a ``ParseError``.
    """

    def validate(self, payload: Any) -> bool:
        """Evaluate a payload for semantic acceptability.

        Args:
            payload: A ``str`` for text/markdown content, or a JSON-serialized
                     ``str`` representation for structured types (JSON/YAML/XML).

        Returns:
            ``True`` if the payload is acceptable, ``False`` to reject it.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Backward-compatibility shim
# ---------------------------------------------------------------------------


class BaseSemanticScanner:
    """Deprecated. Subclass ``SemanticValidator`` and implement ``validate()``
    instead.  This shim is preserved so existing ``scan()``-based
    implementations continue to work via the legacy code path in ``parse()``.
    """

    def scan(self, text: str) -> list[str]:  # pragma: no cover
        """Return a list of violation names, or an empty list if safe.

        Deprecated: implement ``SemanticValidator.validate()`` instead.
        """
        raise NotImplementedError
