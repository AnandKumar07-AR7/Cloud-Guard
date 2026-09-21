"""
CloudGuard — AI Provider Base Abstraction (Phase 8)

Strictly separates AI reasoning from infrastructure execution.
AI providers only produce declarative tool requests or structured analysis/recommendations.
AI providers NEVER receive direct access to Python functions, shell commands, database connections,
AWS SDK clients, HTTP clients, or executable handles.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AIToolRequest:
    """A declarative request from the AI provider to execute a tool."""
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIProviderRawResponse:
    """Raw structured output emitted by an AI provider."""
    tool_requests: List[AIToolRequest] = field(default_factory=list)
    recommendation: Optional[Dict[str, Any]] = None
    raw_text: Optional[str] = None


class AIProviderError(Exception):
    """Base exception for AI provider failures."""
    def __init__(self, message: str, error_category: str = "provider_error"):
        super().__init__(message)
        self.error_category = error_category


class AIProvider(ABC):
    """
    Abstract AI Provider.
    Must never execute tools or mutate cloud/database state.
    """

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Returns 'demo' or 'anthropic'."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Returns the specific model identifier."""
        pass

    @abstractmethod
    def generate_response(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> AIProviderRawResponse:
        """
        Produce declarative tool requests or structured recommendation.
        Never executes any tool directly.
        """
        pass
