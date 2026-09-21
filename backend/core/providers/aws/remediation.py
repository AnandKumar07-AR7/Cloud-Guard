"""
CloudGuard — AWS Remediation Provider
"""
import logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.providers.remediation import RemediationProvider
from core.remediation.models import RemediationAction, RemediationExecutionResult, RemediationVerificationResult

logger = logging.getLogger(__name__)

class AWSRemediationProvider(RemediationProvider):
    """
    Real AWS Remediation Provider.
    Executes actual changes using boto3.
    """
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region_name: str = "us-east-1"):
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name
        )

    @property
    def provider_name(self) -> str:
        return "aws"

    def validate_action(self, action: RemediationAction) -> bool:
        if action.provider != "aws":
            raise ValueError(f"Provider mismatch: expected aws, got {action.provider}")
        
        from core.remediation.state import RemediationSafety
        if action.safety == RemediationSafety.DESTRUCTIVE:
            raise ValueError("DESTRUCTIVE remediation actions are strictly blocked.")

        # Explicit allowlist
        if action.action_type not in ["ENABLE_S3_PUBLIC_ACCESS_BLOCK"]:
            raise ValueError(f"Unsupported AWS action type: {action.action_type}")
            
        if action.action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
            allowed_params = {"bucket_name"}
            extra = set(action.parameters.keys()) - allowed_params
            if extra:
                raise ValueError(f"Unknown parameters for ENABLE_S3_PUBLIC_ACCESS_BLOCK: {extra}")
            bucket_name = action.parameters.get("bucket_name")
            if not isinstance(bucket_name, str) or not bucket_name.strip() or len(bucket_name) > 63:
                raise ValueError("Invalid 'bucket_name' parameter: must be a non-empty string <= 63 chars")
            
        return True

    def execute_action(self, action: RemediationAction) -> RemediationExecutionResult:
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
                s3 = self.session.client('s3')
                bucket_name = action.parameters["bucket_name"]
                
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                
                return RemediationExecutionResult(
                    action_id=action.action_id,
                    success=True,
                    safe_details={"modified_bucket": bucket_name}
                )
            
            # This point should be unreachable due to validation, but safeguard:
            raise ValueError(f"Unimplemented execution for {action.action_type}")

        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS Execution failed: {e}")
            return RemediationExecutionResult(
                action_id=action.action_id,
                success=False,
                error_message="AWS API execution failed. Check logs."
            )
        except Exception as e:
            logger.error(f"Unexpected Execution error: {e}")
            return RemediationExecutionResult(
                action_id=action.action_id,
                success=False,
                error_message="Unexpected execution failure."
            )

    def verify_action(self, action: RemediationAction) -> RemediationVerificationResult:
        """
        Independently verify state after modification by querying AWS API.
        """
        if action.action_type == "ENABLE_S3_PUBLIC_ACCESS_BLOCK":
            s3 = self.session.client('s3')
            bucket_name = action.parameters.get("bucket_name")
            
            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response.get('PublicAccessBlockConfiguration', {})
                if all(config.get(k) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]):
                    return RemediationVerificationResult(
                        remediation_id="",
                        is_fixed=True,
                        details="Public Access Block is verified as fully enabled."
                    )
                else:
                    return RemediationVerificationResult(
                        remediation_id="",
                        is_fixed=False,
                        details="Public Access Block is missing or incomplete."
                    )
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    return RemediationVerificationResult(
                        remediation_id="",
                        is_fixed=False,
                        details="Public Access Block configuration does not exist."
                    )
                return RemediationVerificationResult(
                    remediation_id="",
                    is_fixed=False,
                    details=f"Verification failed due to AWS error: {error_code}"
                )

        return RemediationVerificationResult(
            remediation_id="",
            is_fixed=False,
            details="Unsupported action type for AWS verification."
        )
