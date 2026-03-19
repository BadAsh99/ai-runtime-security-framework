"""
Output Filter — Data Exfiltration Detection
Detects when LLM responses contain leaked system context, credentials,
or are attempting to exfiltrate data across app boundaries.
Aligned with OWASP LLM06 (Sensitive Information Disclosure) and AIRS curriculum.
"""

import re
from dataclasses import dataclass


@dataclass
class OutputScanResult:
    clean: bool
    findings: list[str]
    risk_score: int          # 0-100
    redacted_output: str


# Patterns indicating the model revealed its system prompt or internal context
SYSTEM_LEAK_PATTERNS = [
    r"my\s+(system\s+prompt|instructions?)\s+(is|are|says?|reads?)\s*[:;]?",
    r"i\s+(was|am|have\s+been)\s+(instructed|told|configured|set\s+up)\s+to",
    r"(according\s+to\s+my|based\s+on\s+(my|the))\s+(instructions?|system\s+prompt|guidelines?)",
    r"my\s+(primary\s+)?(directive|goal|purpose|function)\s+is\s+to",
    r"as\s+(per\s+)?my\s+(configuration|setup|instructions?|system)",
]

# Patterns indicating credential or sensitive data exposure
CREDENTIAL_PATTERNS = [
    r"(api[_\s-]?key|secret[_\s-]?key|access[_\s-]?key|bearer[_\s-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}",
    r"(password|passwd|pwd)\s*[:=]\s*['\"]?.{6,}['\"]?",
    r"(private[_\s-]?key|rsa[_\s-]?key)\s*[:=]",
    r"sk-[A-Za-z0-9]{32,}",                # OpenAI key pattern
    r"sk-ant-[A-Za-z0-9\-]{50,}",          # Anthropic key pattern
    r"AIza[A-Za-z0-9_\-]{35}",             # Google API key pattern
]

# Cross-app data smuggling — injected instructions in output meant to poison downstream apps
CROSS_APP_EXFIL_PATTERNS = [
    r"(forward|relay|pass|send)\s+(the\s+)?(following|this|above)\s+to\s+(the\s+)?(next|other|downstream)",
    r"\[\s*(hidden|invisible|secret)\s*(instruction|message|payload)\s*\]",
    r"<!--.*?(inject|instruction|override).*?-->",
    r"<\s*inject\s*>.*?<\s*/inject\s*>",
    # Invisible Unicode injection attempts
    r"[\u200b\u200c\u200d\ufeff]",         # Zero-width chars (common in indirect injection)
]

# Indicators that a jailbreak succeeded
JAILBREAK_SUCCESS_PATTERNS = [
    r"(sure|okay|of course)[,!]?\s+i.{0,20}(ignore|bypass|disregard)\s+(my|the|all)\s+(safety|guidelines?|restrictions?)",
    r"as\s+(DAN|an?\s+unrestricted|an?\s+unfiltered)\s+(AI|model|assistant|version)",
    r"i\s+will\s+now\s+(ignore|disregard|forget)\s+(my|all)\s+(instructions?|guidelines?|restrictions?)",
    r"in\s+(DAN|developer|jailbreak)\s+mode",
]


def scan_output(response: str, app_id: str = "unknown") -> OutputScanResult:
    """
    Scan LLM output for exfiltration, leakage, or jailbreak success indicators.
    """
    findings = []
    risk_score = 0
    response_lower = response.lower()

    # System prompt leakage (HIGH risk)
    for pattern in SYSTEM_LEAK_PATTERNS:
        if re.search(pattern, response_lower, re.IGNORECASE):
            findings.append(f"[SYSTEM_LEAK] Possible system prompt disclosure: {pattern[:60]}")
            risk_score += 25

    # Credential exposure (CRITICAL)
    for pattern in CREDENTIAL_PATTERNS:
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            findings.append(f"[CREDENTIAL] Credential pattern detected: {pattern[:60]}")
            risk_score += 40

    # Cross-app data smuggling (HIGH)
    for pattern in CROSS_APP_EXFIL_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
            findings.append(f"[CROSS_APP_EXFIL] Cross-app payload detected: {pattern[:60]}")
            risk_score += 30

    # Jailbreak success (CRITICAL)
    for pattern in JAILBREAK_SUCCESS_PATTERNS:
        if re.search(pattern, response_lower, re.IGNORECASE):
            findings.append(f"[JAILBREAK_SUCCESS] Jailbreak indicators in response: {pattern[:60]}")
            risk_score += 45

    risk_score = min(risk_score, 100)
    clean = risk_score == 0

    return OutputScanResult(
        clean=clean,
        findings=findings,
        risk_score=risk_score,
        redacted_output=_redact(response) if not clean else response,
    )


def _redact(text: str) -> str:
    """Redact credential patterns from output."""
    redacted = text
    for pattern in CREDENTIAL_PATTERNS:
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted
