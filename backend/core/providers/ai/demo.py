"""
CloudGuard — Demo AI Provider (Phase 8)

Produces deterministic, predictable AI analysis and tool requests without
requiring external API keys or network connectivity.
Strictly identifies itself as provider_type = 'demo'.
Never fabricates external model execution.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.providers.ai.base import AIProvider, AIProviderRawResponse, AIToolRequest


class DemoAIProvider(AIProvider):
    """
    Deterministic Demo AI Provider.
    Operates via multi-step server-controlled tool orchestration in demo mode.
    """

    @property
    def provider_type(self) -> str:
        return "demo"

    @property
    def model_name(self) -> str:
        return "demo-deterministic-v1"

    def generate_response(
        self,
        system_prompt: str,
        messages: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> AIProviderRawResponse:
        """
        Generates deterministic tool requests or final recommendation based on context.
        """
        tool_results: Dict[str, Any] = {}
        target_finding_id: Optional[str] = None
        target_rule_id: Optional[str] = None

        # Inspect messages for initial finding_id and any previous tool results
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str) and "target_finding_id:" in content:
                for line in content.splitlines():
                    if line.startswith("target_finding_id:"):
                        target_finding_id = line.split(":", 1)[1].strip()

            if msg.get("role") == "tool":
                t_name = msg.get("name")
                t_content = msg.get("content")
                if t_name and t_content:
                    try:
                        tool_results[t_name] = json.loads(t_content) if isinstance(t_content, str) else t_content
                    except Exception:
                        tool_results[t_name] = t_content

        # Step 1: If finding details not gathered yet, request get_finding
        if "get_finding" not in tool_results and target_finding_id:
            return AIProviderRawResponse(
                tool_requests=[AIToolRequest(tool_name="get_finding", arguments={"finding_id": target_finding_id})]
            )

        finding_data = tool_results.get("get_finding", {})
        if isinstance(finding_data, dict):
            target_rule_id = finding_data.get("rule_id")

        # Step 2: If rule details not gathered yet, request get_rule_details
        if "get_rule_details" not in tool_results and target_rule_id:
            return AIProviderRawResponse(
                tool_requests=[AIToolRequest(tool_name="get_rule_details", arguments={"rule_id": target_rule_id})]
            )

        # Step 3: Produce deterministic final recommendation
        rule_id = target_rule_id or "UNKNOWN"
        severity = finding_data.get("severity", "MEDIUM") if isinstance(finding_data, dict) else "MEDIUM"
        resource_id = finding_data.get("resource_id", "unknown-resource") if isinstance(finding_data, dict) else "unknown-resource"
        title = finding_data.get("title", f"Finding {rule_id}") if isinstance(finding_data, dict) else f"Finding {rule_id}"

        # Determine strategy from Phase 7 deterministic allowlist
        recommended_strategy_id: Optional[str] = None
        if rule_id in ("S3-001", "s3-public-access-block-disabled"):
            recommended_strategy_id = "S3-001"
        elif rule_id in ("SG-001", "ec2-sg-open-ssh"):
            recommended_strategy_id = "SG-001"

        analysis = (
            f"Security analysis for finding on resource '{resource_id}'. "
            f"The resource violates policy {rule_id} ({title}) with severity {severity}. "
            f"Configuration posture indicates non-compliance with secure baseline standards."
        )

        risk = (
            f"Identified risk level is {severity}. Failure to remediate policy violation {rule_id} "
            f"on {resource_id} may lead to unauthorized network exposure or data exfiltration."
        )

        rationale = (
            f"Applying allowlisted remediation strategy '{recommended_strategy_id or 'NONE'}' "
            f"deterministically mitigates the misconfiguration on '{resource_id}' "
            f"while preserving resource operational integrity."
        )

        impact = f"Enforces compliant configuration for {resource_id}. Low operational risk."

        recommendation = {
            "analysis_summary": analysis,
            "risk_summary": risk,
            "recommendation_rationale": rationale,
            "expected_impact": impact,
            "recommended_strategy_id": recommended_strategy_id,
            "confidence": 0.95,
            "requires_approval": True,
        }

        return AIProviderRawResponse(recommendation=recommendation)
