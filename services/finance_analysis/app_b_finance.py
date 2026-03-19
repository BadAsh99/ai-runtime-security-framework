"""
Finance Analysis Microservice (App B)

Performs financial analysis, earnings interpretation, market insights.
Uses shared LLM client for consistent behavior across services.

Phase 1: Mock LLM responses with keyword-based financial metrics extraction.
Phase 2: Integrate with real LLM API + financial data APIs (Alpha Vantage, IEX Cloud).
"""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional
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

SERVICE_NAME = "finance-analysis"
SERVICE_PORT = 8002
LOG_LEVEL = "INFO"

# Financial keywords for enhanced extraction
FINANCIAL_KEYWORDS = {
    "metrics": ["revenue", "earnings", "profit", "margin", "eps", "pe ratio"],
    "sentiment": ["growth", "decline", "bullish", "bearish", "outperform", "underperform"],
    "sectors": ["tech", "healthcare", "finance", "energy", "retail"],
}

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

class FinanceAnalysisRequest(BaseModel):
    """Request for finance analysis."""
    query: str = Field(..., description="Financial question or context")
    ticker: Optional[str] = Field(default=None, description="Stock ticker symbol")
    period: Optional[str] = Field(default="Q4", description="Period (Q1-Q4, annual)")


class FinancialMetrics(BaseModel):
    """Financial metrics extracted from analysis."""
    metric_name: str
    value: Optional[float] = None
    unit: str
    confidence: float


class FinanceAnalysisResponse(BaseModel):
    """Response from finance analysis."""
    query: str
    analysis: str
    sentiment: str  # "bullish", "bearish", "neutral"
    metrics: list[FinancialMetrics]
    risk_level: str  # "low", "medium", "high"
    recommendation: str
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response."""
    service: str
    status: str
    llm_model: str
    request_count: int


# ============================================================================
# Finance Analyzer
# ============================================================================

class FinanceAnalyzer:
    """Analyzes financial queries and data."""
    
    def __init__(self):
        """Initialize analyzer with LLM client."""
        self.llm_client = LLMClientFactory.get_client(LLMModel.MOCK_GPT4)
        self.request_count = 0
    
    def _extract_metrics(self, text: str) -> list[FinancialMetrics]:
        """
        Extract financial metrics from text.
        
        Phase 1: Regex-based extraction of numbers and keywords.
        Phase 2: NER + semantic analysis.
        """
        metrics = []
        
        # Simple regex patterns for common financial metrics
        patterns = {
            "revenue": r"revenue[:\s]+\$?([\d.]+)",
            "growth": r"growth[:\s]+(\d+\.?\d*)%",
            "margin": r"margin[:\s]+(\d+\.?\d*)%",
            "eps": r"eps[:\s]+\$?([\d.]+)",
        }
        
        for metric_name, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    value = float(match.group(1))
                    metrics.append(FinancialMetrics(
                        metric_name=metric_name,
                        value=value,
                        unit="%" if "%" in metric_name else "$",
                        confidence=0.8,
                    ))
                except (ValueError, IndexError):
                    pass
        
        return metrics
    
    def _extract_sentiment(self, text: str) -> str:
        """
        Extract sentiment from text.
        
        Phase 1: Keyword-based sentiment detection.
        Phase 2: Sentiment analysis model.
        """
        text_lower = text.lower()
        bullish_score = 0
        bearish_score = 0
        
        bullish_terms = ["growth", "strong", "bullish", "outperform", "buy", "positive"]
        bearish_terms = ["decline", "weak", "bearish", "underperform", "sell", "negative"]
        
        for term in bullish_terms:
            bullish_score += text_lower.count(term)
        
        for term in bearish_terms:
            bearish_score += text_lower.count(term)
        
        if bullish_score > bearish_score:
            return "bullish"
        elif bearish_score > bullish_score:
            return "bearish"
        else:
            return "neutral"
    
    async def analyze(
        self,
        query: str,
        ticker: Optional[str] = None,
        period: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze financial query.
        
        Args:
            query: Financial question
            ticker: Stock ticker (optional)
            period: Period (optional)
            
        Returns:
            Analysis result with sentiment and metrics
        """
        self.request_count += 1
        
        logger.info(f"Analyzing finance query: {query[:50]}...")
        
        # Get LLM analysis
        prompt = f"Provide financial analysis: {query}"
        if ticker:
            prompt += f" (ticker: {ticker})"
        if period:
            prompt += f" (period: {period})"
        
        llm_response = await self.llm_client.complete(
            prompt=prompt,
            system_message="You are a financial analyst. Provide detailed analysis with metrics and recommendations.",
        )
        
        analysis_text = llm_response.content
        
        # Extract metrics and sentiment
        metrics = self._extract_metrics(analysis_text)
        sentiment = self._extract_sentiment(analysis_text)
        
        # Determine risk level
        if sentiment == "bearish":
            risk_level = "high"
        elif sentiment == "bullish":
            risk_level = "low"
        else:
            risk_level = "medium"
        
        # Generate recommendation
        if sentiment == "bullish":
            recommendation = "Consider increasing position"
        elif sentiment == "bearish":
            recommendation = "Consider reducing position or wait for improvement"
        else:
            recommendation = "Monitor for further signals"
        
        return {
            "query": query,
            "analysis": analysis_text,
            "sentiment": sentiment,
            "metrics": metrics,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "timestamp": datetime.utcnow().isoformat(),
        }


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="Finance Analysis Service",
    description="Analyzes financial queries and market data",
    version="1.0.0",
)

analyzer = FinanceAnalyzer()


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


@app.post("/analyze", response_model=FinanceAnalysisResponse)
async def analyze_finance(request: FinanceAnalysisRequest) -> FinanceAnalysisResponse:
    """
    Analyze financial query.
    
    Args:
        request: FinanceAnalysisRequest with query and optional ticker/period
        
    Returns:
        FinanceAnalysisResponse with analysis, sentiment, and metrics
    """
    try:
        result = await analyzer.analyze(request.query, request.ticker, request.period)
        
        logger.info(f"Analysis complete: sentiment={result['sentiment']}, metrics_found={len(result['metrics'])}")
        
        return FinanceAnalysisResponse(**result)
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
            "/analyze": "POST - Analyze financial query",
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
