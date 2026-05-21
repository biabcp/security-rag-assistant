"""LLM provider adapters for answer generation."""
from __future__ import annotations

import os
import re
from typing import Any

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?above",
    r"you\s+are\s+now",
    r"system\s*:\s*",
    r"forget\s+(everything|all|your\s+instructions)",
    r"pretend\s+you\s+are",
    r"act\s+as\s+(if\s+you\s+are|a)",
    r"do\s+not\s+follow\s+(your|the)\s+(rules|instructions)",
    r"\[system\]",
    r"\<\|system\|\>",
]


def detect_prompt_injection(query: str) -> bool:
    """Check query for common prompt injection patterns."""
    lower = query.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lower):
            return True
    return False


class LLMProvider:
    """Base class for LLM providers."""

    def generate(self, system_prompt: str, user_message: str) -> str:
        raise NotImplementedError


class RuleBasedProvider(LLMProvider):
    """Placeholder that returns None, signaling rule-based fallback."""

    def generate(self, system_prompt: str, user_message: str) -> str:
        return ""


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def generate(self, system_prompt: str, user_message: str) -> str:
        if not self.api_key:
            return ""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                temperature=0.2,
                max_tokens=1024,
            )
            return response.choices[0].message.content or ""
        except Exception:
            return ""


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def generate(self, system_prompt: str, user_message: str) -> str:
        try:
            import httpx
            response = httpx.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "stream": False,
                },
                timeout=120.0,
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return str(data.get("message", {}).get("content", ""))
        except Exception:
            return ""


def get_llm_provider(name: str = "rule", **kwargs: Any) -> LLMProvider:
    """Factory function to get an LLM provider by name."""
    if name == "rule":
        return RuleBasedProvider()
    elif name == "openai":
        return OpenAIProvider(**kwargs)
    elif name == "ollama":
        return OllamaProvider(**kwargs)
    else:
        raise ValueError(f"Unknown LLM provider: {name}. Use 'rule', 'openai', or 'ollama'.")
