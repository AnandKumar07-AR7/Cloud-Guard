"""
CloudGuard / AegisByte — Unit Tests for GeminiAIProvider
"""
import pytest
import httpx
from unittest.mock import MagicMock, patch

from core.providers.ai.gemini import GeminiAIProvider
from core.providers.ai.base import AIProviderError, AIProviderRawResponse


def test_gemini_provider_requires_api_key():
    with pytest.raises(ValueError, match="GEMINI_API_KEY is not configured"):
        GeminiAIProvider(api_key="")

    with pytest.raises(ValueError, match="GEMINI_API_KEY is not configured"):
        GeminiAIProvider(api_key=None)


def test_gemini_provider_initialization():
    provider = GeminiAIProvider(api_key="test-key-123", model="gemini-3.8-flash")
    assert provider.provider_type == "gemini"
    assert provider.model_name == "gemini-3.8-flash"


def test_gemini_provider_successful_response():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": 'Security Analysis:\n{"recommendation": {"strategy": "S3-001-BLOCK-PUBLIC-ACCESS", "parameters": {}}}'
                        }
                    ]
                }
            }
        ]
    }

    provider = GeminiAIProvider(api_key="test-key-123")
    with patch("httpx.Client.post", return_value=mock_response):
        res = provider.generate_response(
            system_prompt="You are a security auditor.",
            messages=[{"role": "user", "content": "Analyze bucket findings."}],
            available_tools=[],
        )

    assert isinstance(res, AIProviderRawResponse)
    assert "Security Analysis" in res.raw_text
    assert res.recommendation is not None
    assert res.recommendation.get("strategy") == "S3-001-BLOCK-PUBLIC-ACCESS"


def test_gemini_provider_bad_request_raises_ai_provider_error():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": {"message": "Invalid argument format"}}

    provider = GeminiAIProvider(api_key="test-key-123")
    with patch("httpx.Client.post", return_value=mock_response):
        with pytest.raises(AIProviderError) as exc_info:
            provider.generate_response(
                system_prompt="audit",
                messages=[{"role": "user", "content": "test"}],
                available_tools=[],
            )
        assert exc_info.value.error_category == "validation_error"


def test_gemini_provider_unauthorized_raises_ai_provider_error():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 401

    provider = GeminiAIProvider(api_key="test-key-123")
    with patch("httpx.Client.post", return_value=mock_response):
        with pytest.raises(AIProviderError) as exc_info:
            provider.generate_response(
                system_prompt="audit",
                messages=[{"role": "user", "content": "test"}],
                available_tools=[],
            )
        assert exc_info.value.error_category == "authentication_error"


def test_gemini_provider_rate_limit_raises_ai_provider_error():
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 429

    provider = GeminiAIProvider(api_key="test-key-123")
    with patch("httpx.Client.post", return_value=mock_response):
        with pytest.raises(AIProviderError) as exc_info:
            provider.generate_response(
                system_prompt="audit",
                messages=[{"role": "user", "content": "test"}],
                available_tools=[],
            )
        assert exc_info.value.error_category == "rate_limit"


def test_gemini_provider_timeout_raises_timeout_error():
    provider = GeminiAIProvider(api_key="test-key-123")
    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Read timeout")):
        with pytest.raises(AIProviderError) as exc_info:
            provider.generate_response(
                system_prompt="audit",
                messages=[{"role": "user", "content": "test"}],
                available_tools=[],
            )
        assert exc_info.value.error_category == "timeout"
