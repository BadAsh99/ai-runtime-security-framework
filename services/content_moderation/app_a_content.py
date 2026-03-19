"""
Content Moderation Microservice (App A)

Analyzes content for policy violations, toxicity, and inappropriate material.
Uses shared LLM client for consistent behavior across services.

Phase 1: Mock LLM responses + keyword-based moderation rules.
Phase 2: Integrate with real LLM API + ML-based content classification.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import sys
import os

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))

from shared_llm_client import LLMClientFactory, LLMModel


# ============================================================================
# Configuration
# ============================================================================

SERVICE_NAME = "content-moderation"
SERVICE_PORT = 8001
LOG_LEVEL = "INFO"

# Content moderation rules (Phase 1: keyword-based)
PROHIBITED_KEYWORDS = [
    "explicit",
    "violent",
    "hateful",
    "spam",
    "harassment",
]

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================

class ContentAnalysisRequest(BaseModel):
    """Request for content analysis."""
    text: str = Field(..., description="Text content to analyze")
    categories: list[str] = Field(
        default=["toxicity", "violence", "hate_speech", "spam"],
        description="Categories to check"
    )


class ContentAnalysisResponse(BaseModel):
    """Response from content analysis."""
    text: str
    is_flagged: bool
    risk_level: str  # "none", "low", "medium", "high"
    violations: list[str]
    llm_analysis: str
    confidence: float
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response."""
    service: str
    status: str
    llm_model: str
    request_count: int


# ============================================================================
# Content Analyzer
# ============================================================================

class ContentAnalyzer:
    """Analyzes content for policy violations."""
    
    def __init__(self):
        """Initialize analyzer with LLM client."""
        self.llm_client = LLMClientFactory.get_client(LLMModel.MOCK_GPT4)
        self.request_count = 0
    
    async def analyze(
        self,
        text: str,
        categories: list[str],
    ) -> Dict[str, Any]:
        """
        Analyze content for violations.
        
        Args:
            text: Content to analyze
            categories: Categories to check
            
        Returns:
            Analysis result with violations and risk level
        """
        self.request_count += 1
        
        logger.info(f"Analyzing content: {text[:50]}...")
        
        violations = []
        risk_scores = {}
        
        # Phase 1: Keyword-based detection
        text_lower = text.lower()
        for keyword in PROHIBITED_KEYWORDS:
            if keyword in text_lower:
                violations.append(keyword)
        
        # Phase 1: LLM classification (mock)
        llm_response = await self.llm_client.complete(
            prompt=f"Analyze content: {text}\n\nIdentify violations in categories: {', '.join(categories)}",
            system_message="You are a content moderation expert. Identify policy violations.",
        )
        
        # Determine risk level
        if len(violations) >= 2:
            risk_level = "high"
            confidence = 0.95
        elif len(violations) == 1:
            risk_level = "medium"
            confidence = 0.75
        else:
            risk_level = "low"
            confidence = 0.3
        
        is_flagged = risk_level in ["medium", "high"]
        
        return {
            "text": text,
            "is_flagged": is_flagged,
            "risk_level": risk_level,
            "violations": violations,
            "llm_analysis": llm_response.content,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
        }


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="Content Moderation Service",
    description="Analyzes content for policy violations and toxic material",
    version="1.0.0",
)

analyzer = ContentAnalyzer()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    llm_stats = analyzer.llm_client.get_stats()
    return HealthResponse(
        service=SERVICE_NAME,
        status="healthy",
        llm_model=llm_stats["model"],
        request_count=analyzer.request_count,
    )


@app.post("/analyze", response_model=ContentAnalysisResponse)
async def analyze_content(request: ContentAnalysisRequest) -> ContentAnalysisResponse:
    """
    Analyze content for policy violations.
    
    Args:
        request: ContentAnalysisRequest with text and categories
        
    Returns:
        ContentAnalysisResponse with violations and risk assessment
    """
    try:
        result = await analyzer.analyze(request.text, request.categories)
        
        logger.info(f"Analysis complete: risk_level={result['risk_level']}, violations={result['violations']}")
        
        return ContentAnalysisResponse(**result)
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": SERVICE_NAME,
        "version": "1.0.0",
        "endpoints": {
            "/health": "Health check",
            "/analyze": "POST - Analyze content",
        },
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting {SERVICE_NAME} on port {SERVICE_PORT}")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=SERVICE_PORT,
        log_level=LOG_LEVEL.lower(),
    )
