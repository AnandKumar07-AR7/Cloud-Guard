"""
CloudGuard — Read-Only AI Tool Schemas (Phase 8)

Defines strict Pydantic input schemas for all allowlisted tools.
All schemas enforce extra='forbid' to prevent parameter injection.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolInputBase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class GetFindingInput(ToolInputBase):
    finding_id: str = Field(..., min_length=1, max_length=128, description="UUID of the finding")


class GetFindingHistoryInput(ToolInputBase):
    canonical_id: str = Field(..., min_length=1, max_length=64, description="Deterministic canonical ID of the finding")


class GetResourceDetailsInput(ToolInputBase):
    resource_id: str = Field(..., min_length=1, max_length=255, description="Cloud resource ARN or unique identifier")


class GetRuleDetailsInput(ToolInputBase):
    rule_id: str = Field(..., min_length=1, max_length=100, description="Security rule ID (e.g. S3-001)")


class GetAllowedRemediationStrategiesInput(ToolInputBase):
    rule_id: str = Field(..., min_length=1, max_length=100, description="Security rule ID to check strategies for")


class GetRemediationStatusInput(ToolInputBase):
    finding_id: str = Field(..., min_length=1, max_length=128, description="UUID of the finding to check remediation status for")
