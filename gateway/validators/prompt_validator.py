"""
Prompt Injection Validator
Detects direct, indirect, and multi-stage injection patterns.
Aligned with OWASP LLM01 and AIRS AI Application and Agent Security curriculum.
"""

import re
from dataclasses import dataclass
from enum import Enum


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


@dataclass
class ValidationResult:
    allowed: bool
    threat_level: ThreatLevel
    matched_patterns: list[str]
    sanitized_prompt: str | None


# OWASP LLM01 — Prompt Injection pattern library
INJECTION_PATTERNS = {
    ThreatLevel.CRITICAL: [
        # Direct instruction overrides
        r"ignore\s+(all\s+)?(previous|prior|above|system)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior|above|system)\s+instructions?",
        r"forget\s+(all\s+)?(previous|prior|above|your)\s+instructions?",
        r"you\s+are\s+now\s+(a\s+)?(?!an?\s+AI).{0,30}\s*[,.]",
        r"new\s+instructions?\s*[:;]\s*.{10,}",
        r"override\s+(security|safety|system|all)\s+(rules?|instructions?|policies?)",
        # System prompt extraction
        r"(repeat|print|show|reveal|output|display)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)",
        r"what\s+(are|is)\s+your\s+(system\s+prompt|instructions?|guidelines?)",
        r"tell\s+me\s+(your\s+)?(system\s+prompt|secret\s+instructions?)",
        # Role/identity hijacking
        r"pretend\s+(you\s+are|to\s+be)\s+(?!an?\s+AI).{0,50}",
        r"act\s+as\s+(if\s+)?(you\s+are\s+)?(?!an?\s+AI).{0,50}(with\s+no\s+(restrictions?|limits?|filters?))?",
        r"roleplay\s+as.{0,50}(no\s+(restrictions?|limits?|filters?))",
        # Jailbreak patterns
        r"DAN\s+(mode|prompt)",
        r"developer\s+mode\s*(on|enabled|activated)",
        r"jailbreak",
        r"bypass\s+(safety|security|content|all)\s+(filters?|restrictions?|checks?)",
    ],
    ThreatLevel.HIGH: [
        # Indirect injection (data-borne)
        r"<\s*injection\s*>",
        r"\[\s*SYSTEM\s*\]",
        r"###\s*(instruction|system|override)",
        r"<<\s*(instruction|system|override)",
        # Context poisoning
        r"from\s+now\s+on\s+(you\s+will|always)",
        r"(always|never)\s+respond\s+(with|by|using)",
        r"your\s+new\s+(primary\s+)?directive",
        # Exfiltration setup
        r"(send|transmit|exfiltrate|leak)\s+(all\s+)?(data|information|context|history)\s+to",
        r"(before|after)\s+(each|every|all)\s+(response|reply|answer)\s+(include|add|append)",
        # Multi-turn setup
        r"(remember|memorize|store)\s+(this|the following)\s+(for\s+(future|later)|until\s+I)",
    ],
    ThreatLevel.MEDIUM: [
        # Prompt leakage probes
        r"(what|which)\s+(rules?|policies?|constraints?)\s+(do\s+you|are\s+you)\s+(follow|have|given)",
        r"(summarize|describe)\s+(your|the)\s+(guidelines?|policies?|rules?)",
        # Authority spoofing
        r"(as|from)\s+(your|the)\s+(developer|creator|admin|administrator|openai|anthropic|google)",
        r"(admin|administrator|root|superuser)\s+(mode|access|override)",
        # Subtle instruction injection
        r"(note|important|remember)\s*:\s*(ignore|disregard|forget)",
        r"p\.s\.?\s*(ignore|disregard|always|never).{5,}",
    ],
}

# Cross-app contamination markers — injections designed to propagate to other services
CROSS_APP_PATTERNS = [
    r"(when|if)\s+(you\s+)?(call|contact|forward|send\s+to)\s+(another|other|next)\s+(service|app|application|model)",
    r"(pass|forward|relay)\s+(this|the following)\s+(instruction|message|context)\s+to",
    r"(all|every)\s+(downstream|connected|linked)\s+(services?|apps?|models?)",
    r"propagate\s+(this|the following)",
]


def validate_prompt(prompt: str, app_id: str = "unknown") -> ValidationResult:
    """
    Validate a prompt for injection attempts.
    Returns ValidationResult with threat level and matched patterns.
    """
    prompt_lower = prompt.lower()
    matched = []
    highest_threat = ThreatLevel.CLEAN

    # Check injection patterns by severity (highest first)
    for level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM]:
        for pattern in INJECTION_PATTERNS[level]:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                matched.append(f"[{level.value}] {pattern}")
                if highest_threat == ThreatLevel.CLEAN or _severity_rank(level) > _severity_rank(highest_threat):
                    highest_threat = level

    # Check cross-app contamination
    for pattern in CROSS_APP_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            matched.append(f"[CROSS-APP] {pattern}")
            if highest_threat in (ThreatLevel.CLEAN, ThreatLevel.LOW):
                highest_threat = ThreatLevel.HIGH

    allowed = highest_threat in (ThreatLevel.CLEAN, ThreatLevel.LOW)

    return ValidationResult(
        allowed=allowed,
        threat_level=highest_threat,
        matched_patterns=matched,
        sanitized_prompt=_sanitize(prompt) if not allowed else prompt,
    )


def _severity_rank(level: ThreatLevel) -> int:
    return {ThreatLevel.CLEAN: 0, ThreatLevel.LOW: 1, ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3, ThreatLevel.CRITICAL: 4}[level]


def _sanitize(prompt: str) -> str:
    """Strip the most dangerous patterns, return a sanitized version."""
    sanitized = prompt
    for pattern in INJECTION_PATTERNS[ThreatLevel.CRITICAL]:
        sanitized = re.sub(pattern, "[BLOCKED]", sanitized, flags=re.IGNORECASE)
    return sanitized
