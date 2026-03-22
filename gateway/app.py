"""
FastAPI Gateway with Prompt Injection Detection & Audit Logging

Phase 1 Implementation:
- Routes requests to 3 microservices (content moderation, finance, support)
- Detects basic prompt injection patterns (keyword + regex matching)
- Logs all requests/responses to structured JSON audit trail
- Health check endpoint for monitoring
- Ready for extension with semantic analysis in Phase 2
"""

import json
import logging
import re
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel, Field

# Phase 2: Semantic detection imports
from gateway.llm_client import get_llm_client
from gateway.detectors import SemanticInjectionDetector

# ============================================================================
# Configuration
# ============================================================================

GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8000
LOG_LEVEL = "INFO"
AUDIT_LOG_FILE = "audit.log"

# Service endpoints
SERVICES = {
    "content-moderation": "http://localhost:8001",
    "finance-analysis": "http://localhost:8002",
    "support-chatbot": "http://localhost:8003",
}

# Injection detection patterns (Phase 1: keyword-based, regex-based)
INJECTION_KEYWORDS = [
    "ignore instructions",
    "forget your role",
    "system prompt",
    "developer mode",
    "bypass security",
    "admin access",
    "delete all",
    "execute command",
    "sql injection",
    "xss payload",
]

INJECTION_PATTERNS = [
    r"(?i)(<!--.*?-->)",  # HTML comments
    r"(?i)(eval\s*\()",  # eval() calls
    r"(?i)(exec\s*\()",  # exec() calls
    r"(?i)(\$\{.*?\})",  # Template injection
    r"(?i)({{.*?}})",  # Jinja2-style
    r"(?i)(%[0-9a-fx]+)",  # Format string
]

# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging():
    """Configure structured JSON logging for audit trail."""
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(message)s",
    )
    return logging.getLogger(__name__)


logger = setup_logging()


def log_audit_event(event: Dict[str, Any]) -> None:
    """
    Log audit event as structured JSON.
    
    Args:
        event: Dictionary with timestamp, service, request, response, injection_detected, etc.
    """
    event["timestamp"] = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    
    # Write to audit log file (append mode)
    log_path = Path(AUDIT_LOG_FILE)
    with open(log_path, "a") as f:
        f.write(json.dumps(event) + "\n")
    
    # Also log to console
    logger.info(json.dumps(event))


# ============================================================================
# Prompt Injection Detector
# ============================================================================

class InjectionDetector:
    """Detects prompt injection attempts using keyword and pattern matching."""
    
    def __init__(
        self,
        keywords: list[str] = INJECTION_KEYWORDS,
        patterns: list[str] = INJECTION_PATTERNS,
    ):
        """
        Initialize detector with keyword and regex patterns.
        
        Args:
            keywords: List of suspicious keywords
            patterns: List of regex patterns for suspicious content
        """
        self.keywords = keywords
        self.patterns = [re.compile(p) for p in patterns]
    
    def detect(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for injection indicators.
        
        Args:
            text: Input text to analyze
            
        Returns:
            Dict with:
                - is_injection: bool (True if suspicious)
                - risk_level: str ("low", "medium", "high")
                - detected_keywords: list
                - detected_patterns: list
                - confidence: float (0.0 - 1.0)
        """
        text_lower = text.lower()
        detected_keywords = []
        detected_patterns = []
        
        # Check keywords
        for keyword in self.keywords:
            if keyword in text_lower:
                detected_keywords.append(keyword)
        
        # Check patterns
        for pattern in self.patterns:
            matches = pattern.findall(text)
            if matches:
                detected_patterns.extend(matches)
        
        # Calculate risk
        total_indicators = len(detected_keywords) + len(detected_patterns)
        confidence = min(0.1 * total_indicators, 1.0)
        
        if total_indicators >= 3:
            risk_level = "high"
        elif total_indicators >= 2:
            risk_level = "medium"
        elif total_indicators >= 1:
            risk_level = "low"
        else:
            risk_level = "none"
        
        is_injection = total_indicators > 0
        
        return {
            "is_injection": is_injection,
            "risk_level": risk_level,
            "detected_keywords": detected_keywords,
            "detected_patterns": detected_patterns,
            "confidence": confidence,
        }


# ============================================================================
# Data Models
# ============================================================================

class TextRequest(BaseModel):
    """Generic request model for text-based services."""
    text: Optional[str] = None
    query: Optional[str] = None
    message: Optional[str] = None
    input: Optional[str] = None
    
    class Config:
        extra = "allow"


class ScanRequest(BaseModel):
    """Request model for vulnerability scanning."""
    input: str = Field(..., description="Input to scan for vulnerabilities")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    timestamp: str = Field(..., description="Check timestamp")
    services: Dict[str, str] = Field(..., description="Status of each service")


class AuditEntry(BaseModel):
    """Audit log entry."""
    timestamp: str
    service: str
    method: str
    path: str
    injection_detected: bool
    risk_level: str
    request_body: Dict[str, Any]
    response_status: int
    response_time_ms: float


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="AI Runtime Security Gateway",
    description="Central gateway with prompt injection detection & audit logging",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9000", "http://localhost:8501", "http://0.0.0.0:9000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Phase 1: Keep pattern-based detector as fallback
pattern_injection_detector = InjectionDetector()

# Phase 2: Initialize semantic detector (uses real LLMs)
semantic_injection_detector = None  # Lazy-loaded on first request

async def get_semantic_detector() -> SemanticInjectionDetector:
    """Get or initialize semantic detector (lazy load)."""
    global semantic_injection_detector
    if semantic_injection_detector is None:
        try:
            llm_client = get_llm_client()
            semantic_injection_detector = SemanticInjectionDetector(llm_client=llm_client)
            logger.info(f"Initialized semantic detector with LLM provider: {llm_client.provider}")
        except Exception as e:
            logger.warning(f"Failed to initialize semantic detector: {e}. Falling back to pattern detection.")
            semantic_injection_detector = None
    return semantic_injection_detector


async def detect_injection(text: str, service_context: str = "") -> Dict[str, Any]:
    """
    Detect injection using semantic detector (with pattern-based fallback).
    
    Try semantic detection first (real LLM analysis).
    Fall back to pattern detection if semantic fails.
    
    Args:
        text: Text to analyze
        service_context: Service context for semantic analysis
        
    Returns:
        Detection result with: is_injection, risk_level, confidence, detector, etc.
    """
    # Try semantic detection first (Phase 2)
    semantic_detector = await get_semantic_detector()
    if semantic_detector is not None:
        try:
            result = await semantic_detector.detect(text, service_context=service_context)
            return {
                "is_injection": result.is_injection,
                "risk_level": result.risk_level,
                "confidence": result.confidence,
                "reasoning": result.reasoning,
                "similar_attacks": result.similar_attacks,
                "detector": result.detector_type,
                "llm_provider": result.llm_provider,
                "llm_model": result.llm_model,
                "latency_ms": result.latency_ms,
            }
        except Exception as e:
            logger.warning(f"Semantic detection failed, falling back to pattern: {e}")
    
    # Fallback to pattern-based detection (Phase 1)
    detection = pattern_injection_detector.detect(text)
    return {
        "is_injection": detection["is_injection"],
        "risk_level": detection["risk_level"],
        "confidence": detection["confidence"],
        "detected_keywords": detection["detected_keywords"],
        "detected_patterns": detection["detected_patterns"],
        "detector": "pattern-based",
        "latency_ms": 0,
    }


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Middleware to audit all requests/responses."""
    import time
    
    start_time = time.time()
    
    # Capture request body if available
    body = {}
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.json()
        except Exception:
            body = {}
    
    # Get response
    response = await call_next(request)
    
    elapsed_ms = (time.time() - start_time) * 1000
    
    # Determine if injection detected (from body content)
    injection_detected = False
    risk_level = "none"
    detector_used = "none"
    
    # Check all text-like fields in request body
    for key, value in body.items():
        if isinstance(value, str) and value.strip():
            detection = await detect_injection(value)
            if detection["is_injection"]:
                injection_detected = True
                risk_level = detection["risk_level"]
                detector_used = detection.get("detector", "unknown")
                break
    
    # Log audit event
    audit_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": request.url.path.split("/")[2] if len(request.url.path.split("/")) > 2 else "unknown",
        "method": request.method,
        "path": request.url.path,
        "injection_detected": injection_detected,
        "risk_level": risk_level,
        "detector": detector_used,
        "request_body": body,
        "response_status": response.status_code,
        "response_time_ms": round(elapsed_ms, 2),
    }
    
    log_audit_event(audit_event)
    
    return response


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Verifies gateway and downstream services are operational.
    """
    service_status = {}
    
    # Check each service
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, url in SERVICES.items():
            try:
                response = await client.get(f"{url}/health")
                service_status[name] = "healthy" if response.status_code == 200 else "unhealthy"
            except Exception as e:
                service_status[name] = f"unreachable ({str(e)[:20]})"
    
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
        services=service_status,
    )


@app.post("/v1/content-moderation")
async def content_moderation(request: TextRequest):
    """
    Route to content moderation service.
    
    Detects injection in request using semantic + pattern detection, forwards if safe.
    """
    text = request.text or ""
    
    # Detect injection (Phase 2: semantic + Phase 1: pattern fallback)
    detection = await detect_injection(text, service_context="content-moderation")
    
    if detection["is_injection"] and detection["risk_level"] == "high":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Potential prompt injection detected",
                "detection": detection,
            }
        )
    
    # Forward to service
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{SERVICES['content-moderation']}/analyze",
                json=request.model_dump(),
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unavailable: {str(e)}")


@app.post("/v1/finance-analysis")
async def finance_analysis(request: TextRequest):
    """
    Route to finance analysis service.
    
    Detects injection in request using semantic + pattern detection, forwards if safe.
    """
    query = request.query or ""
    
    # Detect injection (Phase 2: semantic + Phase 1: pattern fallback)
    detection = await detect_injection(query, service_context="finance-analysis")
    
    if detection["is_injection"] and detection["risk_level"] == "high":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Potential prompt injection detected",
                "detection": detection,
            }
        )
    
    # Forward to service
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{SERVICES['finance-analysis']}/analyze",
                json=request.model_dump(),
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unavailable: {str(e)}")


@app.post("/v1/support-chatbot")
async def support_chatbot(request: TextRequest):
    """
    Route to support chatbot service.
    
    Detects injection in request using semantic + pattern detection, forwards if safe.
    """
    message = request.message or ""
    
    # Detect injection (Phase 2: semantic + Phase 1: pattern fallback)
    detection = await detect_injection(message, service_context="support-chatbot")
    
    if detection["is_injection"] and detection["risk_level"] == "high":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Potential prompt injection detected",
                "detection": detection,
            }
        )
    
    # Forward to service
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{SERVICES['support-chatbot']}/chat",
                json=request.model_dump(),
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unavailable: {str(e)}")


@app.post("/scan")
async def scan_vulnerability(request: ScanRequest):
    """
    Scan input for vulnerabilities using semantic + pattern detection.
    
    Returns detection results without blocking.
    """
    detection = await detect_injection(request.input, service_context="scan")
    
    return {
        "input": request.input,
        "detection": detection,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/metrics")
async def get_metrics():
    """Threat metrics aggregated from audit log."""
    from gateway.middleware.audit import get_threat_summary
    return get_threat_summary()


@app.get("/audit/recent")
async def get_recent_audit(n: int = 50):
    """Return last N audit events from log."""
    from gateway.middleware.audit import get_recent_events
    return {"events": get_recent_events(n)}


@app.get("/")
async def root():
    """Root endpoint with API documentation."""
    return {
        "service": "AI Runtime Security Gateway",
        "version": "1.0.0",
        "endpoints": {
            "/health": "Health check",
            "/v1/content-moderation": "POST - Content moderation analysis",
            "/v1/finance-analysis": "POST - Finance analysis",
            "/v1/support-chatbot": "POST - Support chatbot",
            "/scan": "POST - Vulnerability scan",
        },
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    
    # Create audit log file if it doesn't exist
    Path(AUDIT_LOG_FILE).touch()
    
    uvicorn.run(
        app,
        host=GATEWAY_HOST,
        port=GATEWAY_PORT,
        log_level=LOG_LEVEL.lower(),
    )
