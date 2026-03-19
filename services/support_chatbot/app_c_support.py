"""
Support Chatbot Microservice (App C)

Provides customer support responses for common issues and questions.
Uses shared LLM client for consistent behavior across services.

Phase 1: Mock LLM responses with pattern-based routing to FAQ categories.
Phase 2: Integrate with real LLM API + vector search on support docs.
"""

import json
import logging
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

SERVICE_NAME = "support-chatbot"
SERVICE_PORT = 8003
LOG_LEVEL = "INFO"

# FAQ categories for routing (Phase 1: keyword-based)
FAQ_CATEGORIES = {
    "account": {
        "keywords": ["password", "login", "account", "reset", "username"],
        "description": "Account and authentication issues"
    },
    "billing": {
        "keywords": ["payment", "invoice", "billing", "charge", "refund"],
        "description": "Billing and payment questions"
    },
    "technical": {
        "keywords": ["error", "bug", "crash", "not working", "slow"],
        "description": "Technical issues and troubleshooting"
    },
    "general": {
        "keywords": ["help", "how", "what", "where", "when"],
        "description": "General information and guidance"
    },
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

class SupportMessage(BaseModel):
    """Support request message."""
    message: str = Field(..., description="Customer message")
    customer_id: Optional[str] = Field(default=None, description="Customer identifier")
    priority: Optional[str] = Field(default="normal", description="Priority level")


class SupportResponse(BaseModel):
    """Response from support chatbot."""
    message: str
    category: str
    response: str
    solution_confidence: float
    escalation_needed: bool
    follow_up_questions: list[str]
    timestamp: str


class HealthResponse(BaseModel):
    """Health check response."""
    service: str
    status: str
    llm_model: str
    request_count: int


# ============================================================================
# Support Chatbot
# ============================================================================

class SupportChatbot:
    """Handles customer support interactions."""
    
    def __init__(self):
        """Initialize chatbot with LLM client."""
        self.llm_client = LLMClientFactory.get_client(LLMModel.MOCK_GPT4)
        self.request_count = 0
    
    def _categorize_message(self, message: str) -> str:
        """
        Categorize message into FAQ category.
        
        Args:
            message: Customer message
            
        Returns:
            Category name
        """
        message_lower = message.lower()
        
        # Count matches for each category
        category_scores = {}
        for category, info in FAQ_CATEGORIES.items():
            score = sum(1 for keyword in info["keywords"] if keyword in message_lower)
            category_scores[category] = score
        
        # Return highest scoring category (default to general)
        best_category = max(category_scores, key=category_scores.get)
        return best_category if category_scores[best_category] > 0 else "general"
    
    async def handle_message(
        self,
        message: str,
        customer_id: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Handle support message from customer.
        
        Args:
            message: Customer message
            customer_id: Customer identifier (optional)
            priority: Priority level (optional)
            
        Returns:
            Support response with category and solution
        """
        self.request_count += 1
        
        logger.info(f"Processing support message: {message[:50]}...")
        
        # Categorize the message
        category = self._categorize_message(message)
        category_info = FAQ_CATEGORIES[category]
        
        # Get LLM response
        prompt = f"Customer: {message}\n\nCategory: {category_info['description']}\n\nProvide helpful, accurate support response."
        
        llm_response = await self.llm_client.complete(
            prompt=prompt,
            system_message="You are a helpful customer support agent. Provide clear, concise solutions.",
        )
        
        response_text = llm_response.content
        
        # Determine if escalation needed (Phase 1: simple heuristic)
        escalation_needed = (
            "urgent" in message.lower() or
            priority in ["high", "critical"] or
            any(word in message.lower() for word in ["help", "broken", "crash"])
        )
        
        # Calculate confidence (Phase 1: simple heuristic)
        solution_confidence = 0.8 if category != "general" else 0.6
        
        # Generate follow-up questions
        follow_ups = []
        if not escalation_needed:
            follow_ups.append("Did this resolve your issue?")
            follow_ups.append("Do you need additional help?")
        
        return {
            "message": message,
            "category": category,
            "response": response_text,
            "solution_confidence": solution_confidence,
            "escalation_needed": escalation_needed,
            "follow_up_questions": follow_ups,
            "timestamp": datetime.utcnow().isoformat(),
        }


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="Support Chatbot Service",
    description="Handles customer support inquiries and provides assistance",
    version="1.0.0",
)

chatbot = SupportChatbot()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    llm_stats = chatbot.llm_client.get_stats()
    return HealthResponse(
        service=SERVICE_NAME,
        status="healthy",
        llm_model=llm_stats["model"],
        request_count=chatbot.request_count,
    )


@app.post("/chat", response_model=SupportResponse)
async def chat(request: SupportMessage) -> SupportResponse:
    """
    Handle support chat message.
    
    Args:
        request: SupportMessage with customer message
        
    Returns:
        SupportResponse with categorized response and solution
    """
    try:
        result = await chatbot.handle_message(
            request.message,
            request.customer_id,
            request.priority,
        )
        
        logger.info(f"Response complete: category={result['category']}, escalation_needed={result['escalation_needed']}")
        
        return SupportResponse(**result)
    except Exception as e:
        logger.error(f"Chat processing failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": SERVICE_NAME,
        "version": "1.0.0",
        "endpoints": {
            "/health": "Health check",
            "/chat": "POST - Chat with support bot",
        },
        "faq_categories": list(FAQ_CATEGORIES.keys()),
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
