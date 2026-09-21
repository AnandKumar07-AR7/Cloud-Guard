"""
CloudGuard — AI Providers Package (Phase 8)
"""
from typing import Optional

from core.providers.ai.base import AIProvider, AIProviderError, AIProviderRawResponse, AIToolRequest
from core.providers.ai.demo import DemoAIProvider
from core.providers.ai.anthropic import AnthropicAIProvider
from config.settings import settings


def get_ai_provider(
    provider_name: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> AIProvider:
    """
    Factory resolving the active AI provider.
    Strictly validates provider name. Never falls back silently.
    """
    name = (provider_name or settings.ai_provider).strip().lower()

    if name == "demo":
        return DemoAIProvider()

    elif name == "anthropic":
        key = api_key or settings.anthropic_api_key
        mdl = model or settings.anthropic_model
        return AnthropicAIProvider(api_key=key, model=mdl)

    else:
        raise ValueError(
            f"Invalid AI provider '{name}'. Only 'demo' and 'anthropic' are allowed."
        )


__all__ = [
    "AIProvider",
    "AIProviderError",
    "AIProviderRawResponse",
    "AIToolRequest",
    "DemoAIProvider",
    "AnthropicAIProvider",
    "get_ai_provider",
]
