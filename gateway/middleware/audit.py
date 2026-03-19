"""
Audit Logger — structured JSON logging for all gateway events.
Covers: requests, responses, threats, rate limit hits, cross-app events.
Aligned with AIRS requirement: "Telemetry and observability" and "Alert routing".
"""

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("/tmp/airs_audit")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "audit.jsonl"

# Structured logger — outputs JSON lines
logger = logging.getLogger("airs.audit")
logger.setLevel(logging.INFO)

_handler = logging.FileHandler(LOG_FILE)
_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(_handler)

# Also log threats to stdout for visibility
_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter("[AIRS] %(message)s"))
logger.addHandler(_console)


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    event_type: str          # request | threat | rate_limit | cross_app | response
    app_id: str
    client_ip: str
    prompt_hash: str         # SHA-256 of prompt (never log raw prompts)
    threat_level: str
    matched_patterns: list
    action_taken: str        # allowed | blocked | sanitized
    latency_ms: float | None = None
    output_risk_score: int | None = None
    extra: dict | None = None


def log_request(
    app_id: str,
    client_ip: str,
    prompt: str,
    threat_level: str,
    matched_patterns: list,
    action_taken: str,
    latency_ms: float | None = None,
    output_risk_score: int | None = None,
    extra: dict | None = None,
) -> str:
    """Log a gateway audit event. Returns event_id for correlation."""
    import hashlib
    event_id = str(uuid.uuid4())[:8]
    event = AuditEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="threat" if threat_level not in ("clean", "low") else "request",
        app_id=app_id,
        client_ip=client_ip,
        prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16],
        threat_level=threat_level,
        matched_patterns=matched_patterns,
        action_taken=action_taken,
        latency_ms=latency_ms,
        output_risk_score=output_risk_score,
        extra=extra or {},
    )
    logger.info(json.dumps(asdict(event)))
    return event_id


def log_rate_limit(app_id: str, client_ip: str, limit: int, reset_in: int):
    event = {
        "event_id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "rate_limit",
        "app_id": app_id,
        "client_ip": client_ip,
        "limit": limit,
        "reset_in_seconds": reset_in,
    }
    logger.info(json.dumps(event))


def get_recent_events(n: int = 100) -> list[dict]:
    """Return the last N audit events from the log file."""
    events = []
    try:
        lines = LOG_FILE.read_text().strip().split("\n")
        for line in reversed(lines[-n:]):
            if line:
                events.append(json.loads(line))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return list(reversed(events))


def get_threat_summary() -> dict:
    """Aggregate threat stats from audit log."""
    events = get_recent_events(1000)
    summary = {
        "total_requests": 0,
        "blocked": 0,
        "threats_by_level": {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
        "threats_by_app": {},
        "rate_limit_hits": 0,
    }
    for e in events:
        if e.get("event_type") == "rate_limit":
            summary["rate_limit_hits"] += 1
            continue
        summary["total_requests"] += 1
        level = e.get("threat_level", "clean")
        summary["threats_by_level"][level] = summary["threats_by_level"].get(level, 0) + 1
        if e.get("action_taken") == "blocked":
            summary["blocked"] += 1
        app = e.get("app_id", "unknown")
        summary["threats_by_app"][app] = summary["threats_by_app"].get(app, 0) + (
            1 if level not in ("clean", "low") else 0
        )
    return summary
