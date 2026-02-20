"""Semantic anomaly detection for AI agent content ingestion.

Detects prompt injection patterns and anomalous content using a multi-layer
ensemble of deterministic analyzers — no ML models, no external dependencies.

Layers:
1. Pattern-based detection (regex for known injection techniques)
2. Instruction classification (heuristic detection of instruction-like language)
3. Linguistic feature analysis (statistical properties of text)
4. Entropy analysis (Shannon entropy to detect encoded/adversarial payloads)
5. Unicode analysis (homoglyphs, invisible characters, mixed scripts, RTL)
6. Encoding detection (base64, hex segments embedded in content)
7. Repetition analysis (GCG-style adversarial token patterns)

Research basis:
- Assessment docs identified regex as "adequate only as preliminary filter"
- Aura (arXiv:2602.10915) validated semantic intent sanitization
- MLC (arXiv:2602.16660) quantified multilingual safety degradation
- PCAS (arXiv:2602.16708) validated structural policy enforcement
"""

from __future__ import annotations

import math
import re
import string
import unicodedata
from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass, field
from typing import Any


# Weighted scoring defaults — expanded for new analyzers
DEFAULT_WEIGHTS: dict[str, float] = {
    "pattern": 0.25,
    "instruction": 0.20,
    "linguistic": 0.15,
    "entropy": 0.10,
    "unicode": 0.10,
    "encoding": 0.10,
    "repetition": 0.10,
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
    flags: list[str]
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

# Unicode categories that are invisible or control characters
# Used to detect zero-width character injection and RTL attacks
_INVISIBLE_CATEGORIES = {
    "Cf",  # Format characters (ZWJ, ZWNJ, RTL/LTR marks, etc.)
    "Cc",  # Control characters (except common whitespace)
}

# Common homoglyph mappings: Cyrillic/Greek chars that look like Latin
# Source: Unicode confusables database (subset of high-risk pairs)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u043e": "o",  # Cyrillic о → Latin o
    "\u0440": "p",  # Cyrillic р → Latin p
    "\u0441": "c",  # Cyrillic с → Latin c
    "\u0443": "y",  # Cyrillic у → Latin y
    "\u0445": "x",  # Cyrillic х → Latin x
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u0458": "j",  # Cyrillic ј → Latin j
    "\u04bb": "h",  # Cyrillic һ → Latin h
    "\u0391": "A",  # Greek Α → Latin A
    "\u0392": "B",  # Greek Β → Latin B
    "\u0395": "E",  # Greek Ε → Latin E
    "\u0397": "H",  # Greek Η → Latin H
    "\u0399": "I",  # Greek Ι → Latin I
    "\u039a": "K",  # Greek Κ → Latin K
    "\u039c": "M",  # Greek Μ → Latin M
    "\u039d": "N",  # Greek Ν → Latin N
    "\u039f": "O",  # Greek Ο → Latin O
    "\u03a1": "P",  # Greek Ρ → Latin P
    "\u03a4": "T",  # Greek Τ → Latin T
    "\u03a5": "Y",  # Greek Υ → Latin Y
    "\u03a7": "X",  # Greek Χ → Latin X
    "\u03b1": "a",  # Greek α → Latin a (lowercase)
    "\u03bf": "o",  # Greek ο → Latin o
}


class SemanticAnomalyDetector:
    """Detects prompt injection patterns and anomalous content.

    Uses a weighted ensemble of 7 detection strategies. All deterministic,
    all pure Python stdlib. No ML models required.

    Strategies:
        pattern: Regex matching against known injection signatures
        instruction: Keyword density for instruction-like language
        linguistic: Statistical text properties (punctuation, case, length)
        entropy: Shannon entropy analysis for encoded/adversarial content
        unicode: Invisible characters, homoglyphs, mixed scripts
        encoding: Embedded base64/hex payload detection
        repetition: GCG-style repetitive adversarial token patterns
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
                component_scores={
                    "pattern_detection": 0,
                    "instruction_classification": 0,
                    "linguistic_analysis": 0,
                    "entropy_analysis": 0,
                    "unicode_analysis": 0,
                    "encoding_detection": 0,
                    "repetition_analysis": 0,
                },
                confidence=1.0,
                triggered_patterns=[],
                flags=[],
                decision="accept",
            )

        flags: list[str] = []

        # Run all detection strategies
        pattern_score, triggered = self._detect_patterns(combined_text)
        instruction_score = self._classify_instructions(combined_text)
        linguistic_score, ling_flags = self._analyze_linguistic_features(combined_text)
        entropy_score, ent_flags = self._analyze_entropy(combined_text)
        unicode_score, uni_flags = self._analyze_unicode(combined_text)
        encoding_score, enc_flags = self._analyze_encoding(combined_text)
        repetition_score, rep_flags = self._analyze_repetition(combined_text)

        flags.extend(ling_flags)
        flags.extend(ent_flags)
        flags.extend(uni_flags)
        flags.extend(enc_flags)
        flags.extend(rep_flags)

        # Weighted ensemble
        w = self._weights
        weighted_avg = (
            w.get("pattern", 0) * pattern_score
            + w.get("instruction", 0) * instruction_score
            + w.get("linguistic", 0) * linguistic_score
            + w.get("entropy", 0) * entropy_score
            + w.get("unicode", 0) * unicode_score
            + w.get("encoding", 0) * encoding_score
            + w.get("repetition", 0) * repetition_score
        )

        # A very high single-signal score should dominate (not be diluted)
        composite = max(
            weighted_avg,
            pattern_score * 0.85,
            instruction_score * 0.7,
            unicode_score * 0.75,   # homoglyphs alone are highly suspicious
            encoding_score * 0.70,  # embedded base64 alone is suspicious
        )

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
                "entropy_analysis": round(entropy_score, 4),
                "unicode_analysis": round(unicode_score, 4),
                "encoding_detection": round(encoding_score, 4),
                "repetition_analysis": round(repetition_score, 4),
            },
            confidence=round(confidence, 4),
            triggered_patterns=triggered,
            flags=flags,
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

    def _analyze_linguistic_features(self, text: str) -> tuple[float, list[str]]:
        """Flag unusual linguistic properties that suggest injections."""
        if not text:
            return 0.0, []

        score = 0.0
        flags: list[str] = []

        # Excessive punctuation
        punct_count = len(re.findall(r"[^\w\s]", text))
        punct_ratio = punct_count / max(len(text), 1)
        if punct_ratio > 0.25:
            score += 0.25
            flags.append(f"high_punctuation_ratio:{punct_ratio:.2f}")

        # High uppercase ratio (excluding short texts)
        if len(text) > 30:
            upper_count = sum(1 for c in text if c.isupper())
            upper_ratio = upper_count / max(len(text), 1)
            if upper_ratio > 0.5:
                score += 0.2
                flags.append(f"high_uppercase_ratio:{upper_ratio:.2f}")

        # Very long sentences (may indicate concatenated injection)
        sentences = re.split(r"[.!?]+", text)
        avg_words = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
        if avg_words > 40:
            score += 0.2
            flags.append(f"long_avg_sentence:{avg_words:.0f}_words")

        # Presence of code-like patterns in non-code context
        code_patterns = len(re.findall(r"[{}\[\]<>]", text))
        code_ratio = code_patterns / max(len(text), 1)
        if code_ratio > 0.1:
            score += 0.15
            flags.append(f"high_code_char_ratio:{code_ratio:.2f}")

        return min(score, 1.0), flags

    def _analyze_entropy(self, text: str) -> tuple[float, list[str]]:
        """Shannon entropy analysis to detect encoded/adversarial payloads.

        Normal English text has entropy ~3.5-4.5 bits/char.
        Base64 encoded data: ~5.5-6.0
        Random/adversarial tokens: ~6.0-8.0
        Very low entropy (repeated chars): < 2.0

        Both extremes are suspicious in content that should be natural text.
        """
        if len(text) < 20:
            return 0.0, []

        score = 0.0
        flags: list[str] = []

        # Overall entropy
        overall_entropy = _shannon_entropy(text)

        # High entropy suggests encoded/random content
        if overall_entropy > 5.5:
            # Scale: 5.5 → 0.3, 6.5 → 0.7, 7.0+ → 1.0
            score += min(1.0, (overall_entropy - 5.5) * 0.47)
            flags.append(f"high_entropy:{overall_entropy:.2f}")

        # Very low entropy suggests repetitive padding/filler
        if overall_entropy < 2.0 and len(text) > 50:
            score += 0.4
            flags.append(f"low_entropy:{overall_entropy:.2f}")

        # Segment analysis: check for high-entropy segments within normal text
        # This catches embedded encoded payloads
        segments = _split_segments(text, min_length=40)
        for seg_text, seg_start in segments:
            seg_entropy = _shannon_entropy(seg_text)
            if seg_entropy > 5.8:
                score += 0.3
                flags.append(f"high_entropy_segment:pos={seg_start},entropy={seg_entropy:.2f}")
                break  # One high-entropy segment is enough signal

        return min(score, 1.0), flags

    def _analyze_unicode(self, text: str) -> tuple[float, list[str]]:
        """Detect unicode-based attacks: homoglyphs, invisible chars, mixed scripts.

        Attack vectors addressed:
        - Zero-width characters that break regex matching but are invisible
        - RTL/LTR override characters that visually reorder text
        - Homoglyphs (Cyrillic/Greek chars that look identical to Latin)
        - Mixed-script text (Latin + Cyrillic in same word = likely attack)
        """
        if not text:
            return 0.0, []

        score = 0.0
        flags: list[str] = []

        # Detect invisible/format characters
        invisible_count = 0
        invisible_types: set[str] = set()
        for ch in text:
            cat = unicodedata.category(ch)
            if cat in _INVISIBLE_CATEGORIES:
                # Exempt common whitespace-adjacent format chars
                if ch not in ("\t", "\n", "\r", "\x0c"):
                    invisible_count += 1
                    name = unicodedata.name(ch, f"U+{ord(ch):04X}")
                    invisible_types.add(name)

        if invisible_count > 0:
            # Any invisible chars in user-submitted content is suspicious
            score += min(0.6, invisible_count * 0.15)
            flags.append(f"invisible_chars:{invisible_count} ({', '.join(sorted(invisible_types)[:3])})")

        # Detect RTL override attacks specifically
        rtl_overrides = sum(1 for ch in text if ch in ("\u202e", "\u202d", "\u200f", "\u200e", "\u2066", "\u2067", "\u2068", "\u2069"))
        if rtl_overrides > 0:
            score += 0.5
            flags.append(f"rtl_override_chars:{rtl_overrides}")

        # Detect homoglyphs
        homoglyph_count = sum(1 for ch in text if ch in _HOMOGLYPH_MAP)
        if homoglyph_count > 0:
            # Homoglyphs mixed with Latin text = likely spoofing
            latin_count = sum(1 for ch in text if ch in string.ascii_letters)
            if latin_count > 0:
                score += min(0.8, homoglyph_count * 0.2)
                flags.append(f"homoglyphs:{homoglyph_count}")

        # Detect mixed scripts within words (strongest homoglyph signal)
        mixed_script_words = _detect_mixed_script_words(text)
        if mixed_script_words:
            score += 0.7
            examples = mixed_script_words[:3]
            flags.append(f"mixed_script_words:{examples}")

        return min(score, 1.0), flags

    def _analyze_encoding(self, text: str) -> tuple[float, list[str]]:
        """Detect encoded payloads embedded within content.

        Catches base64 segments, hex-encoded sequences, and common
        obfuscation patterns that evade regex-based injection detection.
        """
        if len(text) < 16:
            return 0.0, []

        score = 0.0
        flags: list[str] = []

        # Detect base64-encoded segments (min 24 chars = 18 bytes)
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
        b64_matches = b64_pattern.findall(text)
        valid_b64_count = 0
        for match in b64_matches:
            if _is_likely_base64(match):
                valid_b64_count += 1

        if valid_b64_count > 0:
            score += min(0.8, valid_b64_count * 0.3)
            flags.append(f"base64_segments:{valid_b64_count}")

        # Detect hex-encoded sequences (min 16 hex chars = 8 bytes)
        hex_pattern = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s:,;]?){8,}")
        hex_matches = hex_pattern.findall(text)
        if hex_matches:
            # Filter out things that are likely just IDs/hashes in normal context
            suspicious_hex = [m for m in hex_matches if len(m.strip()) > 32]
            if suspicious_hex:
                score += min(0.5, len(suspicious_hex) * 0.2)
                flags.append(f"hex_segments:{len(suspicious_hex)}")

        # Detect rot13-like patterns (text that becomes meaningful after rot13)
        # Only check if the text contains a suspiciously long alphabetic-only segment
        alpha_segments = re.findall(r"[a-zA-Z]{20,}", text)
        for seg in alpha_segments[:3]:
            decoded = _rot13(seg)
            # Check if the decoded version contains injection keywords
            decoded_lower = decoded.lower()
            injection_keywords = ["ignore", "system", "execute", "override", "admin"]
            if any(kw in decoded_lower for kw in injection_keywords):
                score += 0.6
                flags.append(f"rot13_injection:'{seg[:20]}...'")
                break

        return min(score, 1.0), flags

    def _analyze_repetition(self, text: str) -> tuple[float, list[str]]:
        """Detect GCG-style adversarial token patterns.

        GCG (Greedy Coordinate Gradient) attacks generate optimized adversarial
        suffixes that appear as nonsensical, highly repetitive character sequences.
        These bypass semantic classifiers but are structurally detectable.

        Characteristics of GCG suffixes:
        - High character-level repetition (same chars/ngrams repeat abnormally)
        - Low word-level coherence (not real words)
        - Unusual character class transitions (rapid switching between types)
        """
        if len(text) < 30:
            return 0.0, []

        score = 0.0
        flags: list[str] = []

        # Character n-gram repetition analysis
        # Normal text has diverse trigrams; GCG attacks repeat them
        if len(text) >= 50:
            trigram_ratio = _trigram_repetition_ratio(text)
            if trigram_ratio > 0.4:
                score += min(0.7, (trigram_ratio - 0.4) * 2.3)
                flags.append(f"high_trigram_repetition:{trigram_ratio:.2f}")

        # Character class transition frequency
        # GCG suffixes rapidly alternate between character classes
        if len(text) >= 30:
            transition_rate = _char_class_transition_rate(text)
            # Normal text: ~0.3-0.5, GCG-style: >0.7
            if transition_rate > 0.7:
                score += min(0.5, (transition_rate - 0.7) * 1.7)
                flags.append(f"rapid_char_transitions:{transition_rate:.2f}")

        # Consecutive repeated substrings
        # "abcabc" patterns that suggest optimization artifacts
        repeat_ratio = _consecutive_repeat_ratio(text)
        if repeat_ratio > 0.3:
            score += min(0.6, (repeat_ratio - 0.3) * 2.0)
            flags.append(f"consecutive_repeats:{repeat_ratio:.2f}")

        return min(score, 1.0), flags


# --- Utility functions ---

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of text in bits per character."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _split_segments(text: str, min_length: int = 40) -> list[tuple[str, int]]:
    """Split text into segments for per-segment analysis.

    Returns (segment_text, start_position) tuples.
    Splits on whitespace boundaries, producing segments of at least min_length.
    """
    segments: list[tuple[str, int]] = []
    words = text.split()
    if not words:
        return segments

    current: list[str] = []
    current_len = 0
    current_start = 0

    pos = 0
    for word in words:
        current.append(word)
        current_len += len(word) + 1  # +1 for space
        if current_len >= min_length:
            segments.append((" ".join(current), current_start))
            current_start = pos + current_len
            current = []
            current_len = 0
        pos += len(word) + 1

    # Don't add remainder if too short
    if current_len >= min_length:
        segments.append((" ".join(current), current_start))

    return segments


def _detect_mixed_script_words(text: str) -> list[str]:
    """Find words that mix Latin and Cyrillic/Greek characters.

    A word containing both Latin 'a' and Cyrillic 'а' (U+0430) is almost
    certainly a homoglyph attack — legitimate multilingual text doesn't
    mix scripts within individual words.
    """
    mixed: list[str] = []
    words = re.findall(r"\S+", text)

    for word in words:
        if len(word) < 2:
            continue
        has_latin = False
        has_other_script = False
        for ch in word:
            if ch in string.ascii_letters:
                has_latin = True
            elif ch in _HOMOGLYPH_MAP:
                has_other_script = True
            if has_latin and has_other_script:
                mixed.append(word)
                break

    return mixed


def _is_likely_base64(candidate: str) -> bool:
    """Check if a string is likely valid base64-encoded data.

    Filters out false positives like long English words or URL paths.
    """
    # Must be roughly the right length for base64 (multiple of 4, roughly)
    stripped = candidate.rstrip("=")
    if len(stripped) < 20:
        return False

    # Try to actually decode it
    try:
        # Pad to multiple of 4
        padded = candidate + "=" * (4 - len(candidate) % 4) if len(candidate) % 4 else candidate
        decoded = b64decode(padded, validate=True)
        # If it decodes to mostly printable ASCII or valid UTF-8, it's real base64
        try:
            text = decoded.decode("utf-8", errors="strict")
            # If decoded text is mostly printable, this is likely intentional encoding
            printable_ratio = sum(1 for c in text if c.isprintable() or c in "\n\r\t") / max(len(text), 1)
            return printable_ratio > 0.5
        except UnicodeDecodeError:
            # Binary data encoded as base64 — still suspicious in text content
            return True
    except (BinasciiError, ValueError):
        return False


def _rot13(text: str) -> str:
    """Apply ROT13 transformation."""
    result: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def _trigram_repetition_ratio(text: str) -> float:
    """Measure how repetitive the character trigrams are.

    Returns the ratio of repeated trigrams to total trigrams.
    Normal text: ~0.05-0.20, GCG attacks: >0.40.
    """
    if len(text) < 6:
        return 0.0

    trigrams: dict[str, int] = {}
    for i in range(len(text) - 2):
        tri = text[i:i + 3]
        trigrams[tri] = trigrams.get(tri, 0) + 1

    total = len(text) - 2
    if total == 0:
        return 0.0

    # Count trigrams that appear more than twice
    repeated = sum(count - 1 for count in trigrams.values() if count > 1)
    return repeated / total


def _char_class_transition_rate(text: str) -> float:
    """Measure how frequently the character class changes.

    Character classes: letter, digit, punctuation, whitespace, other.
    Normal text has moderate transitions; GCG attacks have rapid switching.
    """
    if len(text) < 2:
        return 0.0

    def _class(ch: str) -> int:
        if ch.isalpha():
            return 0
        if ch.isdigit():
            return 1
        if ch in string.punctuation:
            return 2
        if ch.isspace():
            return 3
        return 4

    transitions = 0
    prev = _class(text[0])
    for ch in text[1:]:
        curr = _class(ch)
        if curr != prev:
            transitions += 1
        prev = curr

    return transitions / (len(text) - 1)


def _consecutive_repeat_ratio(text: str) -> float:
    """Detect consecutive repeated substrings.

    Looks for patterns where 3-8 character sequences repeat back-to-back.
    """
    if len(text) < 10:
        return 0.0

    total_repeated = 0
    checked = set()

    for length in range(3, 9):
        for i in range(len(text) - length * 2 + 1):
            chunk = text[i:i + length]
            if chunk in checked:
                continue
            checked.add(chunk)
            # Count consecutive repetitions
            pos = i
            repeats = 0
            while pos + length <= len(text) and text[pos:pos + length] == chunk:
                repeats += 1
                pos += length
            if repeats >= 3:
                total_repeated += (repeats - 1) * length

    return min(1.0, total_repeated / max(len(text), 1))


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
