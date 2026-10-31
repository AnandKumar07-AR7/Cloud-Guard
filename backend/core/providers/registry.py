"""
CloudGuard — Multi-Cloud Provider Registry & Roadmap Metadata

Defines the pluggable provider interface and capability matrix for:
  - AWS (Production Live Engine: boto3, STS AssumeRole, parallel discovery, full remediation)
  - Demo (Offline Governance Simulator: synthetic scenarios, full verification state machine)
  - GCP (Extensibility Adapter: Cloud Storage, IAM, Compute Engine)
  - Azure (Extensibility Adapter: Blob Storage, RBAC, Virtual Machines)
"""
from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderCapability(BaseModel):
    provider_id: str
    display_name: str
    status: str = Field(description="'active', 'supported', or 'planned'")
    services_supported: List[str]
    remediation_supported: bool
    sts_role_assumption: bool
    description: str


PROVIDER_REGISTRY: Dict[str, ProviderCapability] = {
    "aws": ProviderCapability(
        provider_id="aws",
        display_name="Amazon Web Services",
        status="active",
        services_supported=["s3", "iam", "ec2", "lambda", "security_group", "rds", "vpc", "cloudtrail"],
        remediation_supported=True,
        sts_role_assumption=True,
        description="Production AWS provider featuring parallel collectors, STS AssumeRole, and real-time boto3 remediation.",
    ),
    "demo": ProviderCapability(
        provider_id="demo",
        display_name="CloudGuard Synthetic Simulator",
        status="active",
        services_supported=["s3", "iam", "ec2", "lambda", "security_group", "rds", "vpc", "cloudtrail"],
        remediation_supported=True,
        sts_role_assumption=False,
        description="Deterministic local simulator with multi-scenario attack injection and end-to-end audit verification.",
    ),
    "gcp": ProviderCapability(
        provider_id="gcp",
        display_name="Google Cloud Platform",
        status="planned",
        services_supported=["gcs", "iam", "compute", "cloud_functions"],
        remediation_supported=False,
        sts_role_assumption=False,
        description="Roadmap Phase 2 multi-cloud adapter implementing the CloudProvider base class for GCP Cloud Asset Inventory.",
    ),
    "azure": ProviderCapability(
        provider_id="azure",
        display_name="Microsoft Azure",
        status="planned",
        services_supported=["blob_storage", "aad", "vm", "network_security_group"],
        remediation_supported=False,
        sts_role_assumption=False,
        description="Roadmap Phase 2 multi-cloud adapter implementing the CloudProvider base class for Azure Resource Graph.",
    ),
}


def get_supported_providers() -> List[ProviderCapability]:
    """Return all registered providers and their capability matrices."""
    return list(PROVIDER_REGISTRY.values())


def get_provider_capability(provider_id: str) -> Optional[ProviderCapability]:
    """Retrieve capability info for a given cloud provider."""
    return PROVIDER_REGISTRY.get(provider_id.lower())
