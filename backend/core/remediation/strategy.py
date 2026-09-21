"""
CloudGuard — Remediation Strategy Registry

Deterministically maps a rule_id to a set of RemediationActions.
All strategies are explicitly allowlisted — no dynamic dispatch.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.remediation.models import RemediationAction
from core.remediation.state import RemediationSafety


@dataclass
class RemediationStrategyContext:
    """
    Minimal context passed to a strategy for action generation.
    Avoids coupling strategy to the full Pydantic Finding model.
    """
    rule_id: str
    resource_id: str
    resource_type: str
    service: str
    account_id: str
    region: str
    provider_name: str


class RemediationStrategy:
    """
    Deterministically generates RemediationActions for a specific rule.
    """
    def __init__(
        self,
        rule_id: str,
        action_type: str,
        safety: RemediationSafety,
        description_template: str,
    ):
        self.rule_id = rule_id
        self.action_type = action_type
        self.safety = safety
        self.description_template = description_template

    def generate_actions(self, ctx: RemediationStrategyContext) -> List[RemediationAction]:
        """Generate deterministic actions based on context."""
        parameters = self._build_parameters(ctx)
        description = self.description_template.format(**parameters)

        return [
            RemediationAction(
                action_type=self.action_type,
                provider=ctx.provider_name,
                service=ctx.service,
                resource_identifier=ctx.resource_id,
                description=description,
                safety=self.safety,
                parameters=parameters,
            )
        ]

    def _build_parameters(self, ctx: RemediationStrategyContext) -> Dict:
        """Extract needed parameters from context."""
        if self.rule_id in ("s3-public-access-block-disabled", "S3-001"):
            # resource_id is typically arn:aws:s3:::bucket-name or bucket-name
            bucket_name = ctx.resource_id.split(":::")[-1]
            if "/" in bucket_name:
                bucket_name = bucket_name.split("/")[0]
            return {"bucket_name": bucket_name}

        elif self.rule_id in ("ec2-sg-open-ssh", "SG-001"):
            # resource_id might be sg-xxx or arn:aws:ec2:...:security-group/sg-xxx
            group_id = ctx.resource_id.split("/")[-1]
            return {"group_id": group_id}

        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Explicit Strategy Allowlist
# Only rules in this dict can be remediated. No implicit fallbacks.
# ─────────────────────────────────────────────────────────────────────────────
STRATEGIES: Dict[str, RemediationStrategy] = {
    "S3-001": RemediationStrategy(
        rule_id="S3-001",
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        safety=RemediationSafety.MEDIUM_RISK,
        description_template="Enable AWS S3 Public Access Block on bucket '{bucket_name}'.",
    ),
    "s3-public-access-block-disabled": RemediationStrategy(
        rule_id="s3-public-access-block-disabled",
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        safety=RemediationSafety.MEDIUM_RISK,
        description_template="Enable AWS S3 Public Access Block on bucket '{bucket_name}'.",
    ),
    "SG-001": RemediationStrategy(
        rule_id="SG-001",
        action_type="DISABLE_SECURITY_GROUP_INGRESS",
        safety=RemediationSafety.MEDIUM_RISK,
        description_template="Remove open 0.0.0.0/0 SSH ingress rule from Security Group '{group_id}'.",
    ),
    "ec2-sg-open-ssh": RemediationStrategy(
        rule_id="ec2-sg-open-ssh",
        action_type="DISABLE_SECURITY_GROUP_INGRESS",
        safety=RemediationSafety.MEDIUM_RISK,
        description_template="Remove open 0.0.0.0/0 SSH ingress rule from Security Group '{group_id}'.",
    ),
}


def get_strategy(rule_id: str) -> Optional[RemediationStrategy]:
    """
    Retrieve the explicitly allowlisted strategy for a rule.
    Returns None if the rule has no supported remediation.
    """
    return STRATEGIES.get(rule_id)
