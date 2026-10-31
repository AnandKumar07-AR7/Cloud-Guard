"""
CloudGuard — Connected Cloud Accounts API Routes (Cross-Account AWS Connector)

Allows customers to onboard and manage AWS accounts via IAM Cross-Account Role ARN
and ExternalId (confused deputy mitigation).
"""
from __future__ import annotations

import secrets
import json
from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import get_db
from config.settings import settings
from auth.dependencies import get_current_user
from auth.models import UserDBModel
from core.db_models import ConnectedAccountDBModel
from core.utils.logging import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/v1/accounts", tags=["Cloud Accounts"])

# CloudGuard SaaS host account ID
HOST_ACCOUNT_ID = "371700247056"


# ── Schemas ───────────────────────────────────────────────────────────────────

class GenerateExternalIdResponse(BaseModel):
    external_id: str
    host_account_id: str
    trust_policy: dict
    permissions_policy: dict
    cloudformation_template: str
    quick_launch_url: str


class ConnectAccountRequest(BaseModel):
    account_id: str = Field(min_length=12, max_length=12, description="12-digit AWS Account ID")
    account_name: str = Field(min_length=1, max_length=100, description="Display name for this AWS account")
    role_arn: str = Field(min_length=20, max_length=255, description="IAM Role ARN in customer account")
    external_id: str = Field(min_length=6, max_length=128, description="External ID provided by CloudGuard")
    region: str = Field(default="us-east-1", max_length=30)


class ConnectedAccountResponse(BaseModel):
    account_id: str
    account_name: str
    role_arn: str
    external_id: str
    region: str
    status: str
    last_verified_at: str
    created_at: str
    is_primary: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_trust_policy(external_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{HOST_ACCOUNT_ID}:root"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                }
            }
        ]
    }


def _generate_permissions_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudGuardSecurityAudit",
                "Effect": "Allow",
                "Action": [
                    "ec2:Describe*",
                    "iam:Get*",
                    "iam:List*",
                    "s3:Get*",
                    "s3:List*",
                    "lambda:Get*",
                    "lambda:List*",
                    "rds:Describe*",
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:GetTrailStatus"
                ],
                "Resource": "*"
            },
            {
                "Sid": "CloudGuardSafeRemediation",
                "Effect": "Allow",
                "Action": [
                    "s3:PutBucketPublicAccessBlock",
                    "s3:PutEncryptionConfiguration",
                    "s3:PutBucketVersioning",
                    "ec2:RevokeSecurityGroupIngress"
                ],
                "Resource": "*"
            }
        ]
    }


def _generate_cfn_template(external_id: str) -> str:
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: 'CloudGuard Security Audit & Auto-Remediation Cross-Account IAM Role'
Parameters:
  ExternalId:
    Type: String
    Default: '{external_id}'
    Description: 'Cryptographic External ID issued by CloudGuard'
Resources:
  CloudGuardRole:
    Type: 'AWS::IAM::Role'
    Properties:
      RoleName: 'CloudGuardAuditAndRemediationRole'
      Description: 'Allows CloudGuard security scanner and governed auto-remediation'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::{HOST_ACCOUNT_ID}:root'
            Action: 'sts:AssumeRole'
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/SecurityAudit'
      Policies:
        - PolicyName: 'CloudGuardRemediationPolicy'
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - 's3:PutBucketPublicAccessBlock'
                  - 's3:PutEncryptionConfiguration'
                  - 's3:PutBucketVersioning'
                  - 'ec2:RevokeSecurityGroupIngress'
                Resource: '*'
Outputs:
  RoleArn:
    Description: 'ARN of the created CloudGuard IAM Role'
    Value: !GetAtt CloudGuardRole.Arn
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[ConnectedAccountResponse])
def list_connected_accounts(
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(get_current_user),
) -> List[ConnectedAccountResponse]:
    """List all connected AWS cloud accounts for the current tenant."""
    results: List[ConnectedAccountResponse] = []

    # Primary account (dynamically bound to the logged-in user's specified AWS account)
    active_acc = getattr(user, "aws_account_id", None) or HOST_ACCOUNT_ID
    results.append(
        ConnectedAccountResponse(
            account_id=active_acc,
            account_name=f"Primary AWS Enclave ({active_acc})",
            role_arn=f"arn:aws:iam::{active_acc}:role/CloudGuardSecurityRole",
            external_id="enclave-primary",
            region=settings.aws_default_region or "us-east-1",
            status="CONNECTED",
            last_verified_at=datetime.now(timezone.utc).isoformat(),
            created_at="2026-09-01T00:00:00Z",
            is_primary=True,
        )
    )

    db_accounts = list(db.scalars(select(ConnectedAccountDBModel)).all())
    for acc in db_accounts:
        if acc.account_id == active_acc:
            continue
        results.append(
            ConnectedAccountResponse(
                account_id=acc.account_id,
                account_name=acc.account_name,
                role_arn=acc.role_arn,
                external_id=acc.external_id,
                region=acc.region,
                status=acc.status,
                last_verified_at=acc.last_verified_at.isoformat() if acc.last_verified_at else datetime.now(timezone.utc).isoformat(),
                created_at=acc.created_at.isoformat() if acc.created_at else datetime.now(timezone.utc).isoformat(),
                is_primary=False,
            )
        )

    return results


@router.post("/generate-external-id", response_model=GenerateExternalIdResponse)
def generate_external_id(
    user: UserDBModel = Depends(get_current_user),
) -> GenerateExternalIdResponse:
    """Generate a unique ExternalId and copyable trust/permission policies for AWS IAM onboarding."""
    ext_id = f"cg-ext-{secrets.token_hex(16)}"
    trust = _generate_trust_policy(ext_id)
    perms = _generate_permissions_policy()
    cfn = _generate_cfn_template(ext_id)
    quick_launch = (
        f"https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review"
        f"?stackName=CloudGuard-Connector&param_ExternalId={ext_id}"
    )

    return GenerateExternalIdResponse(
        external_id=ext_id,
        host_account_id=HOST_ACCOUNT_ID,
        trust_policy=trust,
        permissions_policy=perms,
        cloudformation_template=cfn,
        quick_launch_url=quick_launch,
    )


@router.post("/connect", response_model=ConnectedAccountResponse, status_code=201)
def connect_aws_account(
    req: ConnectAccountRequest,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(get_current_user),
) -> ConnectedAccountResponse:
    """
    Connect an AWS account via Cross-Account STS AssumeRole.
    Verifies that CloudGuard can assume the specified role with the external ID.
    """
    if not req.account_id.isdigit() or len(req.account_id) != 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AWS Account ID must be exactly 12 digits.",
        )

    # Validate Cross-Account AssumeRole via AWS STS
    verification_success = False
    verification_error = None

    try:
        sts_client = boto3.client(
            "sts",
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=req.region,
        )
        assumed = sts_client.assume_role(
            RoleArn=req.role_arn,
            RoleSessionName="CloudGuardConnectorVerification",
            ExternalId=req.external_id,
            DurationSeconds=900,
        )
        creds = assumed.get("Credentials", {})
        if creds.get("AccessKeyId"):
            verification_success = True
            log.info("cross_account_verification_success", account_id=req.account_id, role_arn=req.role_arn)
    except (ClientError, BotoCoreError) as exc:
        verification_error = str(exc)
        log.warning("cross_account_sts_verification_failed", error=verification_error)
    except Exception as exc:
        verification_error = str(exc)
        log.warning("cross_account_general_verification_error", error=verification_error)

    # In demo mode or if local testing role, allow connection with status indicator
    account_status = "CONNECTED" if verification_success else "PENDING_VERIFICATION"
    if settings.cloudguard_mode.value == "demo" or req.role_arn.startswith("arn:aws:iam::123456789012"):
        account_status = "CONNECTED"

    # Persist or update in database
    existing = db.scalar(
        select(ConnectedAccountDBModel).where(ConnectedAccountDBModel.account_id == req.account_id)
    )
    now = datetime.now(timezone.utc)

    if existing:
        existing.account_name = req.account_name
        existing.role_arn = req.role_arn
        existing.external_id = req.external_id
        existing.region = req.region
        existing.status = account_status
        existing.last_verified_at = now
        existing.owner_email = user.email
    else:
        new_acc = ConnectedAccountDBModel(
            account_id=req.account_id,
            account_name=req.account_name,
            role_arn=req.role_arn,
            external_id=req.external_id,
            region=req.region,
            status=account_status,
            last_verified_at=now,
            created_at=now,
            owner_email=user.email,
        )
        db.add(new_acc)

    db.commit()

    return ConnectedAccountResponse(
        account_id=req.account_id,
        account_name=req.account_name,
        role_arn=req.role_arn,
        external_id=req.external_id,
        region=req.region,
        status=account_status,
        last_verified_at=now.isoformat(),
        created_at=now.isoformat(),
        is_primary=False,
    )


@router.delete("/{account_id}", status_code=204)
def disconnect_aws_account(
    account_id: str,
    db: Session = Depends(get_db),
    user: UserDBModel = Depends(get_current_user),
):
    """Disconnect and remove a connected AWS account."""
    if account_id == HOST_ACCOUNT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disconnect primary host account.",
        )

    acc = db.scalar(
        select(ConnectedAccountDBModel).where(ConnectedAccountDBModel.account_id == account_id)
    )
    if not acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connected account not found.",
        )

    db.delete(acc)
    db.commit()
    return None

