"""
CloudGuard — AI Schemas (Phase 8)

Pydantic validation schemas for AI output, requests, and API responses.
Strictly forbids extra fields to prevent injection or schema tampering.
Uses 'recommendation_rationale' for user-facing explanation (no hidden chain-of-thought).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AIRecommendationOutputSchema(BaseModel):
    """
    Validated structured AI recommendation output schema.
    Must strictly conform to this structure or be rejected.
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    analysis_summary: str = Field(..., min_length=10, max_length=2048)
    risk_summary: str = Field(..., min_length=10, max_length=2048)
    recommendation_rationale: str = Field(..., min_length=10, max_length=2048)
    expected_impact: str = Field(..., min_length=5, max_length=1024)
    recommended_strategy_id: Optional[str] = Field(default=None, max_length=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    requires_approval: bool = Field(default=True)


class AIAnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    finding_id: str = Field(..., min_length=1, max_length=128, description="UUID of the finding to analyze")


class AIAgentRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    finding_id: str
    initiating_user_id: str
    provider_type: str
    model_name: str
    status: str
    tool_call_count: int
    duration_ms: Optional[int] = None
    error_category: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class AIRecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    recommendation_id: str
    run_id: str
    finding_id: str
    recommended_strategy_id: Optional[str] = None
    analysis_summary: str
    risk_summary: str
    recommendation_rationale: str
    expected_impact: str
    confidence: float
    requires_approval: bool
    created_at: datetime


class AIToolEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    run_id: str
    tool_name: str
    status: str
    input_summary: Dict[str, Any]
    output_summary: Dict[str, Any]
    error_category: Optional[str] = None
    duration_ms: Optional[int] = None
    created_at: datetime
