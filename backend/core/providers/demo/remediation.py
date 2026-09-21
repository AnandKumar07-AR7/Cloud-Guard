"""
CloudGuard — Demo Remediation Provider
"""
from typing import Dict, Any

from core.providers.remediation import RemediationProvider
from core.remediation.models import RemediationAction, RemediationExecutionResult, RemediationVerificationResult

# Internal state tracker for the demo provider to simulate remediations across the execution and verification phases
DEMO_STATE: Dict[str, Any] = {
    "s3_blocks": set(),
    "sg_blocks": set()
}

class DemoRemediationProvider(RemediationProvider):
    """
    Simulates actual remediation against the global demo state.
    Does NOT use AWS credentials.
    """

    @property
    def provider_name(self) -> str:
        return "demo"

    def validate_action(self, action: RemediationAction) -> bool:
        if action.provider != "demo":
            raise ValueError(f"Provider mismatch: expected demo, got {action.provider}")
        
        from core.remediation.state import RemediationSafety
        if action.safety == RemediationSafety.DESTRUCTIVE:
            raise ValueError("DESTRUCTIVE remediation actions are strictly blocked.")

        # Explicit allowlist
        if action.action_type not in ["ENABLE_S3_PUBLIC_ACCESS_BLOCK", "DISABLE_SECURITY_GROUP_INGRESS"]:
            raise ValueError(f"Unsupported action type: {action.action_type}")
            
        # Parameter validation & strict allowlisting
        if action.action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
            allowed_params = {"bucket_name"}
            extra = set(action.parameters.keys()) - allowed_params
            if extra:
                raise ValueError(f"Unknown parameters for ENABLE_S3_PUBLIC_ACCESS_BLOCK: {extra}")
            bucket_name = action.parameters.get("bucket_name")
            if not isinstance(bucket_name, str) or not bucket_name.strip() or len(bucket_name) > 63:
                raise ValueError("Invalid 'bucket_name' parameter: must be a non-empty string <= 63 chars")
        elif action.action_type == "DISABLE_SECURITY_GROUP_INGRESS":
            allowed_params = {"group_id"}
            extra = set(action.parameters.keys()) - allowed_params
            if extra:
                raise ValueError(f"Unknown parameters for DISABLE_SECURITY_GROUP_INGRESS: {extra}")
            group_id = action.parameters.get("group_id")
            if not isinstance(group_id, str) or not group_id.strip():
                raise ValueError("Invalid 'group_id' parameter: must be a non-empty string")
            
        return True

    def execute_action(self, action: RemediationAction) -> RemediationExecutionResult:
        """
        Actually modifies the in-memory DEMO_STATE.
        """
        try:
            self.validate_action(action)
        except ValueError as e:
            return RemediationExecutionResult(
                action_id=action.action_id,
                success=False,
                error_message=str(e)
            )

        try:
            if action.action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
                bucket_name = action.parameters["bucket_name"]
                DEMO_STATE["s3_blocks"].add(bucket_name)
                    
            elif action.action_type == "DISABLE_SECURITY_GROUP_INGRESS":
                group_id = action.parameters["group_id"]
                DEMO_STATE["sg_blocks"].add(group_id)

            return RemediationExecutionResult(
                action_id=action.action_id,
                success=True,
                safe_details={"modified_resource": action.resource_identifier}
            )
        except Exception as e:
            return RemediationExecutionResult(
                action_id=action.action_id,
                success=False,
                error_message=str(e)
            )

    def verify_action(self, action: RemediationAction) -> RemediationVerificationResult:
        """
        Independently verify state after modification.
        """
        if action.action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
            bucket_name = action.parameters.get("bucket_name")
            if bucket_name in DEMO_STATE["s3_blocks"]:
                return RemediationVerificationResult(
                    remediation_id="",
                    is_fixed=True,
                    details="Public Access Block is fully enabled."
                )
            else:
                return RemediationVerificationResult(
                    remediation_id="",
                    is_fixed=False,
                    details="Public Access Block is missing or incomplete."
                )
            
        elif action.action_type == "DISABLE_SECURITY_GROUP_INGRESS":
            group_id = action.parameters.get("group_id")
            if group_id in DEMO_STATE["sg_blocks"]:
                return RemediationVerificationResult(
                    remediation_id="",
                    is_fixed=True,
                    details="Security Group no longer allows 0.0.0.0/0."
                )
            else:
                return RemediationVerificationResult(
                    remediation_id="",
                    is_fixed=False,
                    details="Security Group still allows 0.0.0.0/0."
                )

        return RemediationVerificationResult(
            remediation_id="",
            is_fixed=False,
            details="Unsupported action type for verification."
        )
