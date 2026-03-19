"""
Shared LLM API Wrapper (Mock)

Phase 1: Mock implementation using hardcoded responses based on context.
Phase 2: Integrate with real LLM (OpenAI, Anthropic, local Ollama).

All microservices use this client to ensure consistent LLM behavior & logging.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional
from enum import Enum


logger = logging.getLogger(__name__)


class LLMModel(str, Enum):
    """Available LLM models (Phase 1: mock only)."""
    MOCK_GPT4 = "mock-gpt-4"
    MOCK_CLAUDE = "mock-claude-3"
    MOCK_LLAMA = "mock-llama-2"


class LLMResponse:
    """Structured LLM response."""
    
    def __init__(
        self,
        content: str,
        model: str,
        tokens_used: int = 0,
        stop_reason: str = "stop",
        latency_ms: float = 0.0,
    ):
        self.content = content
        self.model = model
        self.tokens_used = tokens_used
        self.stop_reason = stop_reason
        self.latency_ms = latency_ms
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "stop_reason": self.stop_reason,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
        }
    
    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.to_dict())


class MockLLMClient:
    """Mock LLM client for Phase 1 development."""
    
    def __init__(self, model: LLMModel = LLMModel.MOCK_GPT4):
        """
        Initialize mock LLM client.
        
        Args:
            model: Model to use (currently all return mock responses)
        """
        self.model = model
        self.request_count = 0
        
        logger.info(f"Initialized MockLLMClient with model: {model.value}")
    
    async def complete(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 200,
        system_message: Optional[str] = None,
    ) -> LLMResponse:
        """
        Generate completion from prompt.
        
        Phase 1: Returns deterministic mock responses based on prompt content.
        Phase 2: Replace with real API calls.
        
        Args:
            prompt: Input prompt
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            system_message: System prompt/context
            
        Returns:
            LLMResponse with completion
        """
        self.request_count += 1
        
        logger.info(f"Complete request #{self.request_count}: {prompt[:50]}...")
        
        # Mock responses based on context
        prompt_lower = prompt.lower()
        
        if "content" in prompt_lower or "moderation" in prompt_lower:
            response = "Content appears clean and appropriate for general audiences."
        elif "finance" in prompt_lower or "earnings" in prompt_lower or "stock" in prompt_lower:
            response = "Q4 earnings analysis: Revenue growth 15% YoY, margin expansion +2.3%, strong guidance."
        elif "support" in prompt_lower or "help" in prompt_lower or "reset" in prompt_lower:
            response = "To reset your password: 1) Go to login page, 2) Click 'Forgot Password', 3) Check email for reset link, 4) Follow instructions."
        else:
            response = f"Mock response to: {prompt[:50]}..."
        
        return LLMResponse(
            content=response,
            model=self.model.value,
            tokens_used=len(prompt.split()) + len(response.split()),
            stop_reason="stop",
            latency_ms=50.0,  # Mock latency
        )
    
    async def classify(
        self,
        text: str,
        categories: list[str],
        system_message: Optional[str] = None,
    ) -> Dict[str, float]:
        """
        Classify text into categories.
        
        Args:
            text: Text to classify
            categories: List of category labels
            system_message: System prompt
            
        Returns:
            Dict mapping category to confidence score (0.0-1.0)
        """
        logger.info(f"Classify request: {text[:50]}... into {categories}")
        
        # Mock classification
        text_lower = text.lower()
        scores = {}
        
        if categories:
            # Distribute scores based on text keywords
            for i, cat in enumerate(categories):
                base_score = 0.3
                if cat.lower() in text_lower:
                    base_score = 0.9
                scores[cat] = base_score + (0.1 * (i % 2))
                scores[cat] = min(scores[cat], 1.0)
        
        return scores
    
    async def summarize(
        self,
        text: str,
        max_length: int = 100,
        system_message: Optional[str] = None,
    ) -> str:
        """
        Summarize text.
        
        Args:
            text: Text to summarize
            max_length: Maximum summary length
            system_message: System prompt
            
        Returns:
            Summary string
        """
        logger.info(f"Summarize request: {len(text)} chars -> {max_length} max")
        
        # Mock: truncate with ellipsis
        if len(text) > max_length:
            return text[:max_length].rsplit(" ", 1)[0] + "..."
        return text
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            "model": self.model.value,
            "request_count": self.request_count,
            "status": "operational",
        }


class LLMClientFactory:
    """Factory for creating LLM clients (single instance pattern)."""
    
    _instance: Optional[MockLLMClient] = None
    
    @classmethod
    def get_client(cls, model: LLMModel = LLMModel.MOCK_GPT4) -> MockLLMClient:
        """
        Get or create LLM client (singleton).
        
        Args:
            model: Model to use
            
        Returns:
            MockLLMClient instance
        """
        if cls._instance is None:
            cls._instance = MockLLMClient(model)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None
