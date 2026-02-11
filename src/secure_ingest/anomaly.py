"""Semantic anomaly detection.

Detects prompt injection patterns and anomalous content using:
1. Pattern-based detection (regex for known injection techniques)
2. Instruction classification (heuristic detection of instruction-like language)
3. Linguistic feature analysis (statistical properties of text)

The ML embedding-based outlier detection is optional and only activated
when scikit-learn + numpy are available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Weighted scoring defaults
DEFAULT_WEIGHTS = {
    "pattern": 0.35,
    "instruction": 0.35,
    "linguistic": 0.30,
}

# Threshold above which content is flagged as anomalous
DEFAULT_THRESHOLD = 0.45


@dataclass
class AnomalyResult:
    """Result of semantic anomaly analysis."""

    is_anomaly: bool
    composite_score: float
    component_scores: dict[str, float]
    confidence: float
    triggered_patterns: list[str]
    decision: str  # "accept", "quarantine", "reject"


# Known prompt injection patterns with severity weights
INJECTION_PATTERNS: list[dict[str, Any]] = [
    # Direct instruction override attempts
    {"name": "ignore_previous", "regex": r"ignore\s+(all\s+)?previous\s+instructions?", "severity": 0.95},
    {"name": "forget_instructions", "regex": r"forget\s+(all\s+)?(your\s+)?instructions?", "severity": 0.95},
    {"name": "new_instructions", "regex": r"new\s+instructions?\s*:", "severity": 0.90},
    {"name": "system_prompt_override", "regex": r"system\s*:\s*you\s+are", "severity": 0.95},
    # Role manipulation
    {"name": "pretend_to_be", "regex": r"pretend\s+(to\s+be|you\s+are)", "severity": 0.85},
    {"name": "act_as", "regex": r"act\s+as\s+(a|an|if)", "severity": 0.80},
    {"name": "you_are_now", "regex": r"you\s+are\s+now\s+a", "severity": 0.85},
    # Action execution attempts
    {"name": "execute_command", "regex": r"(execute|run|eval)\s+(this|the\s+following)\s+command", "severity": 0.90},
    {"name": "download_url", "regex": r"download\s+(from|file\s+from)\s+https?://", "severity": 0.90},
    {"name": "call_api", "regex": r"(call|invoke|use)\s+(the\s+)?(api|tool|function)\s+", "severity": 0.80},
    # Data exfiltration attempts
    {"name": "include_secrets", "regex": r"include\s+(all\s+)?(api\s+)?keys?\s+", "severity": 0.90},
    {"name": "send_to_url", "regex": r"send\s+(it|this|data|results?)\s+to\s+https?://", "severity": 0.95},
    {"name": "output_env", "regex": r"(output|print|include|show)\s+(the\s+)?environment\s+variables?", "severity": 0.90},
    # Delimiter/framing attacks
    {"name": "hidden_tag", "regex": r"\[HIDDEN\s*:", "severity": 0.95},
    {"name": "system_tag", "regex": r"<\s*system\s*>", "severity": 0.90},
    {"name": "assistant_tag", "regex": r"<\s*/?assistant\s*>", "severity": 0.85},
    # Encoded/obfuscated injections
    {"name": "base64_payload", "regex": r"base64[:\s]+(decode|eval)", "severity": 0.85},
    {"name": "unicode_escape", "regex": r"(\\u[0-9a-fA-F]{4}){4,}", "severity": 0.70},
    # Jailbreak patterns
    {"name": "do_anything_now", "regex": r"do\s+anything\s+now", "severity": 0.90},
    {"name": "developer_mode", "regex": r"(enable|activate)\s+developer\s+mode", "severity": 0.85},
]

# Words/phrases that indicate instruction-like language in data fields
INSTRUCTION_INDICATORS: list[str] = [
    "ignore previous",
    "forget",
    "instead",
    "always",
    "never",
    "pretend",
    "act as",
    "you are",
    "you must",
    "you should",
    "your task",
    "your job",
    "your role",
    "system:",
    "assistant:",
    "user:",
    "execute",
    "run this",
    "download",
    "install",
    "delete",
    "from now on",
    "disregard",
    "override",
    "bypass",
]


class SemanticAnomalyDetector:
    """Detects prompt injection patterns and anomalous content.

    Uses a weighted ensemble of detection strategies with configurable
    thresholds. No external ML models required for the base implementation.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        weights: dict[str, float] | None = None,
        patterns: list[dict[str, Any]] | None = None,
    ) -> None:
        self._threshold = threshold
        self._weights = weights or DEFAULT_WEIGHTS
        self._patterns = patterns or INJECTION_PATTERNS

    def analyze(self, content: dict[str, Any]) -> AnomalyResult:
        """Run full anomaly analysis on structured content."""
        text_fields = _extract_text_fields(content)
        combined_text = " ".join(text_fields)

        if not combined_text.strip():
            return AnomalyResult(
                is_anomaly=False,
                composite_score=0.0,
                component_scores={"pattern": 0, "instruction": 0, "linguistic": 0},
                confidence=1.0,
                triggered_patterns=[],
                decision="accept",
            )

        # Run detection strategies
        pattern_score, triggered = self._detect_patterns(combined_text)
        instruction_score = self._classify_instructions(combined_text)
        linguistic_score = self._analyze_linguistic_features(combined_text)

        # Weighted ensemble - use max-of-high-confidence to ensure a single
        # strong signal (like a pattern match at 0.95) isn't diluted away.
        w = self._weights
        weighted_avg = (
            w.get("pattern", 0) * pattern_score
            + w.get("instruction", 0) * instruction_score
            + w.get("linguistic", 0) * linguistic_score
        )
        # A very high pattern score alone should dominate
        composite = max(weighted_avg, pattern_score * 0.85, instruction_score * 0.7)

        # Decision logic
        is_anomaly = composite > self._threshold
        if composite > 0.7:
            decision = "reject"
        elif composite > self._threshold:
            decision = "quarantine"
        else:
            decision = "accept"

        confidence = min(1.0, abs(composite - self._threshold) / max(self._threshold, 0.01))

        return AnomalyResult(
            is_anomaly=is_anomaly,
            composite_score=round(composite, 4),
            component_scores={
                "pattern_detection": round(pattern_score, 4),
                "instruction_classification": round(instruction_score, 4),
                "linguistic_analysis": round(linguistic_score, 4),
            },
            confidence=round(confidence, 4),
            triggered_patterns=triggered,
            decision=decision,
        )

    def _detect_patterns(self, text: str) -> tuple[float, list[str]]:
        """Detect known prompt injection patterns."""
        max_score = 0.0
        triggered: list[str] = []

        for pattern in self._patterns:
            if re.search(pattern["regex"], text, re.IGNORECASE):
                severity = pattern["severity"]
                triggered.append(pattern["name"])
                max_score = max(max_score, severity)

        return min(max_score, 1.0), triggered

    def _classify_instructions(self, text: str) -> float:
        """Detect instruction-like language in data fields."""
        text_lower = text.lower()
        hits = 0
        for indicator in INSTRUCTION_INDICATORS:
            if indicator.lower() in text_lower:
                hits += 1

        # Scale: each hit adds ~0.08, capped at 1.0
        return min(hits * 0.08, 1.0)

    def _analyze_linguistic_features(self, text: str) -> float:
        """Flag unusual linguistic properties that suggest injections."""
        if not text:
            return 0.0

        score = 0.0

        # Excessive punctuation
        punct_count = len(re.findall(r"[^\w\s]", text))
        punct_ratio = punct_count / max(len(text), 1)
        if punct_ratio > 0.25:
            score += 0.25

        # High uppercase ratio (excluding short texts)
        if len(text) > 30:
            upper_count = sum(1 for c in text if c.isupper())
            upper_ratio = upper_count / max(len(text), 1)
            if upper_ratio > 0.5:
                score += 0.2

        # Very long sentences (may indicate concatenated injection)
        sentences = re.split(r"[.!?]+", text)
        avg_words = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
        if avg_words > 40:
            score += 0.2

        # Presence of code-like patterns in non-code context
        code_patterns = len(re.findall(r"[{}\[\]<>]", text))
        code_ratio = code_patterns / max(len(text), 1)
        if code_ratio > 0.1:
            score += 0.15

        # Mixed languages / unusual character distributions
        non_ascii = len(re.findall(r"[^\x00-\x7f]", text))
        non_ascii_ratio = non_ascii / max(len(text), 1)
        if non_ascii_ratio > 0.3:
            score += 0.15

        return min(score, 1.0)


def _extract_text_fields(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a nested structure.

    Limits recursion depth to prevent DoS via deeply nested structures.
    """
    if depth > 10:
        return []

    results: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_text_fields(v, depth + 1))
    elif isinstance(obj, list):
        for v in obj:
            results.extend(_extract_text_fields(v, depth + 1))
    elif isinstance(obj, str):
        results.append(obj)
    return results
