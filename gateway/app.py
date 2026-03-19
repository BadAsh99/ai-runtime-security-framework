"""
AIRS Runtime Security Gateway
FastAPI gateway that intercepts all LLM traffic across the 3 mock enterprise apps.
Applies: prompt validation, output filtering, rate limiting, audit logging.

AIRS Alignment:
- Runtime Security API: request/response inspection
- Telemetry and observability
- Policy configuration and enforcement
"""

import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.middleware.audit import get_threat_summary, get_recent_events, log_request, log_rate_limit
from gateway.validators.output_filter import scan_output
from gateway.validators.prompt_validator import ThreatLevel, validate_prompt
from gateway.validators.rate_limiter import limiter

app = FastAPI(
    title="AIRS Runtime Security Gateway",
    description="AI Runtime Security — prompt inspection, output filtering, audit logging",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Policy: threat levels that are blocked vs. allowed
BLOCK_THRESHOLD = ThreatLevel.MEDIUM   # block MEDIUM, HIGH, CRITICAL


class PromptRequest(BaseModel):
    app_id: str
    prompt: str
    system_prompt: str | None = None
    max_tokens: int = 512


class GatewayResponse(BaseModel):
    allowed: bool
    content: str | None
    threat_level: str
    matched_patterns: list[str]
    action_taken: str
    event_id: str
    latency_ms: float
    output_risk_score: int | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "airs-gateway"}


@app.post("/gateway/inspect", response_model=GatewayResponse)
async def inspect_and_route(request: Request, body: PromptRequest):
    """
    Main gateway endpoint.
    1. Rate limit check
    2. Prompt injection validation
    3. Route to LLM (if allowed)
    4. Output scan
    5. Audit log
    """
    start = time.time()
    client_ip = request.client.host if request.client else "unknown"

    # 1. Rate limiting
    rate_result = limiter.check(body.app_id, client_ip)
    if not rate_result.allowed:
        log_rate_limit(body.app_id, client_ip, rate_result.limit, rate_result.reset_in_seconds)
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "reset_in_seconds": rate_result.reset_in_seconds,
                "limit": rate_result.limit,
            },
        )

    # 2. Prompt validation
    validation = validate_prompt(body.prompt, body.app_id)
    severity_rank = _rank(validation.threat_level)
    block_rank = _rank(BLOCK_THRESHOLD)

    if severity_rank >= block_rank:
        # Block the request
        latency = (time.time() - start) * 1000
        event_id = log_request(
            app_id=body.app_id,
            client_ip=client_ip,
            prompt=body.prompt,
            threat_level=validation.threat_level.value,
            matched_patterns=validation.matched_patterns,
            action_taken="blocked",
            latency_ms=latency,
        )
        return GatewayResponse(
            allowed=False,
            content=None,
            threat_level=validation.threat_level.value,
            matched_patterns=validation.matched_patterns,
            action_taken="blocked",
            event_id=event_id,
            latency_ms=latency,
        )

    # 3. Route to the appropriate app
    try:
        llm_response = await _route_to_app(body)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream app error: {e}")

    # 4. Output scan
    output_scan = scan_output(llm_response, body.app_id)
    content = output_scan.redacted_output if not output_scan.clean else llm_response
    action = "sanitized" if not output_scan.clean else (
        "sanitized_input" if validation.matched_patterns else "allowed"
    )

    latency = (time.time() - start) * 1000
    event_id = log_request(
        app_id=body.app_id,
        client_ip=client_ip,
        prompt=body.prompt,
        threat_level=validation.threat_level.value,
        matched_patterns=validation.matched_patterns,
        action_taken=action,
        latency_ms=latency,
        output_risk_score=output_scan.risk_score,
        extra={"output_findings": output_scan.findings},
    )

    return GatewayResponse(
        allowed=True,
        content=content,
        threat_level=validation.threat_level.value,
        matched_patterns=validation.matched_patterns,
        action_taken=action,
        event_id=event_id,
        latency_ms=latency,
        output_risk_score=output_scan.risk_score,
    )


@app.post("/gateway/validate-only")
async def validate_only(body: PromptRequest):
    """Validate a prompt without sending to LLM. Useful for scanner dry-runs."""
    result = validate_prompt(body.prompt, body.app_id)
    return {
        "app_id": body.app_id,
        "threat_level": result.threat_level.value,
        "allowed": result.allowed,
        "matched_patterns": result.matched_patterns,
    }


@app.get("/audit/events")
async def audit_events(n: int = 50):
    """Return recent audit events."""
    return {"events": get_recent_events(n)}


@app.get("/audit/summary")
async def audit_summary():
    """Return aggregated threat statistics."""
    return get_threat_summary()


@app.get("/audit/rate-limits")
async def rate_limit_stats(app_id: str = "app_a_content"):
    """Return rate limit usage per app."""
    return limiter.get_stats(app_id)


async def _route_to_app(body: PromptRequest) -> str:
    """
    Route prompt to the appropriate application service.
    In Docker Compose this hits the actual service; standalone uses direct import.
    """
    import httpx
    import os

    # Service URLs (Docker Compose names, fallback to localhost for local dev)
    service_urls = {
        "app_a_content": os.getenv("APP_A_URL", "http://localhost:8001"),
        "app_b_finance": os.getenv("APP_B_URL", "http://localhost:8002"),
        "app_c_support": os.getenv("APP_C_URL", "http://localhost:8003"),
    }

    url = service_urls.get(body.app_id)
    if not url:
        raise ValueError(f"Unknown app_id: {body.app_id}")

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{url}/query",
            json={"prompt": body.prompt, "system_prompt": body.system_prompt},
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


def _rank(level: ThreatLevel) -> int:
    return {
        ThreatLevel.CLEAN: 0,
        ThreatLevel.LOW: 1,
        ThreatLevel.MEDIUM: 2,
        ThreatLevel.HIGH: 3,
        ThreatLevel.CRITICAL: 4,
    }[level]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
