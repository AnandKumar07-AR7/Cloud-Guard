"""
CloudGuard — Anthropic AI Provider (Phase 8)

Integrates with Anthropic Claude API using explicit tool calling and structured output.
Enforces client timeouts, strips sensitive headers/keys from exceptions,
and fails safely with explicit error categories.
NEVER silently falls back to Demo mode.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.providers.ai.base import (
    AIProvider,
    AIProviderError,
    AIProviderRawResponse,
    AIToolRequest,
)
from core.utils.logging import get_logger

log = get_logger(__name__)


class AnthropicAIProvider(AIProvider):
    """
    Real AI Provider using Anthropic Claude API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        timeout_seconds: float = 15.0,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("ANTHROPIC_API_KEY is not configured or empty.")

        self._api_key = api_key.strip()
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._client = None

        try:
            import anthropic
            self._client = anthropic.Anthropic(
                api_key=self._api_key,
                timeout=self._timeout_seconds,
                max_retries=1,
            )
        except ImportError:
            raise AIProviderError(
                "Anthropic SDK is not installed.",
                error_category="provider_error",
            )
        except Exception as exc:
            raise AIProviderError(
                f"Failed to initialize Anthropic client: {type(exc).__name__}",
                error_category="provider_error",
            )

    @property
    def provider_type(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    def generate_response(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> AIProviderRawResponse:
        """
        Calls Anthropic API.
        Never executes tools directly.
        Returns declarative tool requests or parsed recommendation.
        """
        if self._client is None:
            raise AIProviderError("Anthropic client is not initialized.", error_category="provider_error")

        # Format tools for Anthropic
        anthropic_tools = []
        for t in available_tools:
            anthropic_tools.append({
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            })

        # Format messages for Anthropic
        formatted_messages = []
        for msg in messages:
            role = msg.get("role")
            if role in ("user", "assistant"):
                formatted_messages.append({"role": role, "content": msg.get("content", "")})
            elif role == "tool":
                # Convert tool role to user block with tool_result
                tool_use_id = msg.get("tool_call_id", f"tool_call_{msg.get('name')}")
                formatted_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps(msg.get("content")) if not isinstance(msg.get("content"), str) else msg.get("content"),
                        }
                    ],
                })

        try:
            kwargs: Dict[str, Any] = {
                "model": self._model,
                "max_tokens": 2048,
                "system": system_prompt,
                "messages": formatted_messages,
            }
            if anthropic_tools:
                kwargs["tools"] = anthropic_tools

            response = self._client.messages.create(**kwargs)

            tool_requests: List[AIToolRequest] = []
            text_blocks: List[str] = []

            for block in response.content:
                if block.type == "tool_use":
                    tool_requests.append(
                        AIToolRequest(
                            tool_name=block.name,
                            arguments=block.input if isinstance(block.input, dict) else {},
                        )
                    )
                elif block.type == "text":
                    text_blocks.append(block.text)

            raw_text = "\n".join(text_blocks)

            # If tool requests were made, return them
            if tool_requests:
                return AIProviderRawResponse(tool_requests=tool_requests, raw_text=raw_text)

            # Otherwise, try to extract recommendation from text block
            recommendation = None
            if raw_text:
                try:
                    # Look for JSON markdown block or direct JSON
                    cleaned_text = raw_text.strip()
                    if "```json" in cleaned_text:
                        json_part = cleaned_text.split("```json", 1)[1].split("```", 1)[0].strip()
                        recommendation = json.loads(json_part)
                    elif cleaned_text.startswith("{") and cleaned_text.endswith("}"):
                        recommendation = json.loads(cleaned_text)
                except Exception:
                    # Recommendation remains None; validator will catch missing/malformed payload
                    pass

            return AIProviderRawResponse(
                tool_requests=[],
                recommendation=recommendation,
                raw_text=raw_text,
            )

        except Exception as exc:
            import anthropic
            log.warning("anthropic_call_failed", error=type(exc).__name__)

            if isinstance(exc, anthropic.APITimeoutError):
                raise AIProviderError(
                    "Anthropic API request timed out.",
                    error_category="provider_timeout",
                )
            elif isinstance(exc, anthropic.AuthenticationError):
                raise AIProviderError(
                    "Anthropic API authentication failed. Check credentials.",
                    error_category="provider_error",
                )
            else:
                raise AIProviderError(
                    f"Anthropic API error: {type(exc).__name__}",
                    error_category="provider_error",
                )
