"""
Shared LLM Client — unified interface for Anthropic and OpenAI APIs.
All 3 apps use this so the gateway can inspect every LLM call.
"""

import os
import time
from dataclasses import dataclass

import requests
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
DEFAULT_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")  # anthropic | openai
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
REQUEST_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "30"))


@dataclass
class LLMResponse:
    content: str
    provider: str
    model: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    error: str | None = None


def call_llm(
    system_prompt: str,
    user_message: str,
    provider: str | None = None,
    max_tokens: int = 512,
) -> LLMResponse:
    """
    Call the configured LLM provider.
    Returns LLMResponse with content, metadata, and latency.
    """
    provider = provider or DEFAULT_PROVIDER
    start = time.time()

    try:
        if provider == "anthropic":
            return _call_anthropic(system_prompt, user_message, max_tokens, start)
        elif provider == "openai":
            return _call_openai(system_prompt, user_message, max_tokens, start)
        else:
            raise ValueError(f"Unknown provider: {provider}")
    except Exception as e:
        latency = (time.time() - start) * 1000
        return LLMResponse(
            content="",
            provider=provider,
            model="unknown",
            latency_ms=latency,
            input_tokens=0,
            output_tokens=0,
            error=str(e),
        )


def _call_anthropic(system_prompt: str, user_message: str, max_tokens: int, start: float) -> LLMResponse:
    if not ANTHROPIC_API_KEY:
        raise ValueError("ANTHROPIC_API_KEY not set")

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    latency = (time.time() - start) * 1000

    return LLMResponse(
        content=data["content"][0]["text"],
        provider="anthropic",
        model=data.get("model", ANTHROPIC_MODEL),
        latency_ms=latency,
        input_tokens=data.get("usage", {}).get("input_tokens", 0),
        output_tokens=data.get("usage", {}).get("output_tokens", 0),
    )


def _call_openai(system_prompt: str, user_message: str, max_tokens: int, start: float) -> LLMResponse:
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY not set")

    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": OPENAI_MODEL,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    latency = (time.time() - start) * 1000

    return LLMResponse(
        content=data["choices"][0]["message"]["content"],
        provider="openai",
        model=data.get("model", OPENAI_MODEL),
        latency_ms=latency,
        input_tokens=data.get("usage", {}).get("prompt_tokens", 0),
        output_tokens=data.get("usage", {}).get("completion_tokens", 0),
    )
