"""Tests for trust boundary enforcement."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from secure_ingest.trust import (
    ContentDecision,
    ContentEnvelope,
    TrustBoundary,
    TrustLevel,
)


@pytest.fixture
def boundary():
    return TrustBoundary(rate_limit_per_agent=5, rate_window_seconds=60.0)


class TestAdmission:
    def test_admit_creates_envelope(self, boundary):
        env = boundary.admit("agent-1", "security_finding", '{"test": true}')
        assert env.source_agent_id == "agent-1"
        assert env.content_type == "security_finding"
        assert env.trust_level == TrustLevel.UNTRUSTED
        assert env.decision is None

    def test_admit_records_audit(self, boundary):
        env = boundary.admit("agent-1", "security_finding", '{"test": true}')
        assert len(env.audit_trail) >= 1
        assert env.audit_trail[0].stage == "admission"

    def test_unique_submission_ids(self, boundary):
        e1 = boundary.admit("agent-1", "test", "content1")
        e2 = boundary.admit("agent-1", "test", "content2")
        assert e1.submission_id != e2.submission_id


class TestRateLimiting:
    def test_within_rate_limit(self, boundary):
        for i in range(5):
            env = boundary.admit("agent-1", "test", f"content-{i}")
            assert env.decision is None

    def test_exceeds_rate_limit(self, boundary):
        for i in range(5):
            boundary.admit("agent-1", "test", f"content-{i}")

        env = boundary.admit("agent-1", "test", "one-too-many")
        assert env.decision == ContentDecision.REJECTED

    def test_rate_limit_per_agent(self, boundary):
        """Rate limits are per agent, not global."""
        for i in range(5):
            boundary.admit("agent-1", "test", f"content-{i}")

        # Different agent should still be allowed
        env = boundary.admit("agent-2", "test", "content")
        assert env.decision is None


class TestSizeLimit:
    def test_content_within_limit(self):
        boundary = TrustBoundary(max_content_bytes=1000)
        env = boundary.admit("agent-1", "test", "small content")
        assert env.decision is None

    def test_content_exceeds_limit(self):
        boundary = TrustBoundary(max_content_bytes=10)
        env = boundary.admit("agent-1", "test", "this is way too long")
        assert env.decision == ContentDecision.REJECTED


class TestTrustPromotion:
    def test_promote_to_controlled(self, boundary):
        env = boundary.admit("agent-1", "test", '{"a": 1}')
        env.parsed_content = {"a": 1}
        assert boundary.promote_to_controlled(env) is True
        assert env.trust_level == TrustLevel.CONTROLLED

    def test_promote_to_controlled_requires_parsed_content(self, boundary):
        env = boundary.admit("agent-1", "test", "raw")
        assert boundary.promote_to_controlled(env) is False
        assert env.trust_level == TrustLevel.UNTRUSTED

    def test_promote_to_trusted(self, boundary):
        env = boundary.admit("agent-1", "test", '{"a": 1}')
        env.parsed_content = {"a": 1}
        boundary.promote_to_controlled(env)
        assert boundary.promote_to_trusted(env) is True
        assert env.trust_level == TrustLevel.TRUSTED
        assert env.decision == ContentDecision.ACCEPTED

    def test_cannot_skip_controlled(self, boundary):
        """Cannot go directly from UNTRUSTED to TRUSTED."""
        env = boundary.admit("agent-1", "test", '{"a": 1}')
        env.parsed_content = {"a": 1}
        assert boundary.promote_to_trusted(env) is False

    def test_cannot_promote_after_rejection(self, boundary):
        env = boundary.admit("agent-1", "test", '{"a": 1}')
        env.parsed_content = {"a": 1}
        boundary.reject(env, "test rejection")
        assert boundary.promote_to_controlled(env) is False

    def test_cannot_promote_with_validation_errors(self, boundary):
        env = boundary.admit("agent-1", "test", '{"a": 1}')
        env.parsed_content = {"a": 1}
        boundary.promote_to_controlled(env)
        env.validation_errors = ["some error"]
        assert boundary.promote_to_trusted(env) is False


class TestQuarantineAndReject:
    def test_quarantine(self, boundary):
        env = boundary.admit("agent-1", "test", "content")
        boundary.quarantine(env, "suspicious content")
        assert env.decision == ContentDecision.QUARANTINED

    def test_reject(self, boundary):
        env = boundary.admit("agent-1", "test", "content")
        boundary.reject(env, "bad content")
        assert env.decision == ContentDecision.REJECTED


class TestContentEnvelope:
    def test_content_hash_deterministic(self):
        e1 = ContentEnvelope(
            submission_id="1", source_agent_id="a", content_type="t", raw_content="hello"
        )
        e2 = ContentEnvelope(
            submission_id="2", source_agent_id="b", content_type="t", raw_content="hello"
        )
        assert e1.content_hash == e2.content_hash

    def test_different_content_different_hash(self):
        e1 = ContentEnvelope(
            submission_id="1", source_agent_id="a", content_type="t", raw_content="hello"
        )
        e2 = ContentEnvelope(
            submission_id="2", source_agent_id="a", content_type="t", raw_content="world"
        )
        assert e1.content_hash != e2.content_hash

    def test_audit_method(self):
        env = ContentEnvelope(
            submission_id="1", source_agent_id="a", content_type="t", raw_content="x"
        )
        env.audit("test_stage", "test_action", key="value")
        assert len(env.audit_trail) == 1
        assert env.audit_trail[0].stage == "test_stage"
        assert env.audit_trail[0].details == {"key": "value"}
