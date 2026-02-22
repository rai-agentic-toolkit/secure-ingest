"""Declarative rule definitions for content-level enforcement.

ValueRules execute strictly against parsed dictionary values or strings,
never against unbounded raw payloads. This prevents ReDoS attacks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ValueRule:
    """A declarative rule applied to parsed string values.
    
    Can be used as either a DENY rule (reject if matched) or an 
    ALLOW rule (reject if NOT matched).
    
    Args:
        name: Unique identifier for the rule.
        pattern: The regular expression to match.
        action: Either "DENY" or "ALLOW"
        description: Human readable explanation.
    """
    name: str
    pattern: str
    action: str = "DENY"
    description: str = ""

    @property
    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern)
