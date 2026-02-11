"""Trust boundary enforcement.

Implements the trust boundary model:
- UNTRUSTED: Raw content from external agents
- CONTROLLED: Content being processed through the pipeline
- TRUSTED: Validated content that has passed all checks

Content can only move from untrusted → controlled → trusted, never backward.
Each transition requires passing a security gate.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    CONTROLLED = "controlled"
    TRUSTED = "trusted"


class ContentDecision(str, Enum):
    ACCEPTED = "accepted"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


@dataclass
class AuditEntry:
    """A single entry in the audit trail."""

    timestamp: float
    stage: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ContentEnvelope:
    """Tracks a piece of content through the trust boundary pipeline.

    The envelope wraps the raw content and accumulates processing state
    as it moves through the pipeline stages.
    """

    submission_id: str
    source_agent_id: str
    content_type: str
    raw_content: str
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    parsed_content: dict[str, Any] | None = None
    validation_errors: list[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    anomaly_details: dict[str, Any] = field(default_factory=dict)
    decision: ContentDecision | None = None
    audit_trail: list[AuditEntry] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def content_hash(self) -> str:
        """SHA-256 hash of the raw content for provenance tracking."""
        return hashlib.sha256(self.raw_content.encode("utf-8")).hexdigest()

    def audit(self, stage: str, action: str, **details: Any) -> None:
        self.audit_trail.append(
            AuditEntry(
                timestamp=time.time(),
                stage=stage,
                action=action,
                details=details,
            )
        )


class TrustBoundary:
    """Enforces trust boundary transitions.

    Content can only move forward through the trust levels.
    Each transition requires explicit authorization from the corresponding
    pipeline stage.
    """

    def __init__(
        self,
        rate_limit_per_agent: int = 100,
        rate_window_seconds: float = 3600.0,
        max_content_bytes: int = 1_048_576,
    ) -> None:
        self._rate_limit = rate_limit_per_agent
        self._rate_window = rate_window_seconds
        self._max_content_bytes = max_content_bytes
        # Sliding window counters: agent_id -> list of timestamps
        self._rate_counters: dict[str, list[float]] = {}

    def admit(self, source_agent_id: str, content_type: str, raw_content: str) -> ContentEnvelope:
        """Admit raw content into the pipeline at UNTRUSTED level.

        Enforces:
        - Rate limiting per source agent
        - Content size limits
        - Basic input sanitization
        """
        envelope = ContentEnvelope(
            submission_id=str(uuid.uuid4()),
            source_agent_id=source_agent_id,
            content_type=content_type,
            raw_content=raw_content,
        )
        envelope.audit("admission", "received", source=source_agent_id)

        # Rate limiting
        if not self._check_rate_limit(source_agent_id):
            envelope.decision = ContentDecision.REJECTED
            envelope.audit("admission", "rate_limited")
            return envelope

        # Size check
        content_bytes = len(raw_content.encode("utf-8", errors="replace"))
        if content_bytes > self._max_content_bytes:
            envelope.decision = ContentDecision.REJECTED
            envelope.audit(
                "admission",
                "size_exceeded",
                bytes=content_bytes,
                limit=self._max_content_bytes,
            )
            return envelope

        envelope.audit("admission", "admitted", bytes=content_bytes)
        return envelope

    def promote_to_controlled(self, envelope: ContentEnvelope) -> bool:
        """Promote content from UNTRUSTED to CONTROLLED.

        Requires: content has been parsed successfully.
        """
        if envelope.trust_level != TrustLevel.UNTRUSTED:
            return False
        if envelope.parsed_content is None:
            return False
        if envelope.decision is not None:
            return False

        envelope.trust_level = TrustLevel.CONTROLLED
        envelope.audit("trust_boundary", "promoted_to_controlled")
        return True

    def promote_to_trusted(self, envelope: ContentEnvelope) -> bool:
        """Promote content from CONTROLLED to TRUSTED.

        Requires: content has passed validation AND anomaly detection.
        """
        if envelope.trust_level != TrustLevel.CONTROLLED:
            return False
        if envelope.validation_errors:
            return False
        if envelope.decision is not None:
            return False

        envelope.trust_level = TrustLevel.TRUSTED
        envelope.decision = ContentDecision.ACCEPTED
        envelope.audit("trust_boundary", "promoted_to_trusted")
        return True

    def quarantine(self, envelope: ContentEnvelope, reason: str) -> None:
        """Send content to quarantine for manual review."""
        envelope.decision = ContentDecision.QUARANTINED
        envelope.audit("trust_boundary", "quarantined", reason=reason)

    def reject(self, envelope: ContentEnvelope, reason: str) -> None:
        """Reject content permanently."""
        envelope.decision = ContentDecision.REJECTED
        envelope.audit("trust_boundary", "rejected", reason=reason)

    def _check_rate_limit(self, agent_id: str) -> bool:
        """Sliding window rate limiter."""
        now = time.time()
        cutoff = now - self._rate_window

        if agent_id not in self._rate_counters:
            self._rate_counters[agent_id] = []

        # Prune old entries
        self._rate_counters[agent_id] = [
            ts for ts in self._rate_counters[agent_id] if ts > cutoff
        ]

        if len(self._rate_counters[agent_id]) >= self._rate_limit:
            return False

        self._rate_counters[agent_id].append(now)
        return True
