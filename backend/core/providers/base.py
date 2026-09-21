"""
CloudGuard — Cloud Provider Abstraction

Defines the normalized CloudResource model and the CloudProvider abstract base.

The same CloudResource schema is used whether data comes from:
  - Real AWS (via AWSProvider)
  - Demo mode (via DemoProvider)

This ensures all security rules and risk calculations work identically
regardless of the data source.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ==============================================================================
# Resource Model
# ==============================================================================

class ResourceType(str, Enum):
    """Supported cloud resource types."""
    S3_BUCKET = "s3_bucket"
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    SECURITY_GROUP = "security_group"
    LAMBDA_FUNCTION = "lambda_function"
    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    VPC = "vpc"
    CLOUDTRAIL = "cloudtrail"


class CloudResource(BaseModel):
    """
    Normalized representation of a cloud resource.

    This is the canonical unit of data passed between:
      Collectors → Security Engine → Risk Engine → AI Service → UI

    The 'config' field contains service-specific configuration details.
    All security rules operate on CloudResource objects only.
    """

    resource_id: str = Field(description="Unique resource identifier within the provider.")
    resource_type: ResourceType = Field(description="Type of cloud resource.")
    provider: str = Field(description="Cloud provider: 'aws' or 'demo'.")
    service: str = Field(description="AWS service: 's3', 'iam', 'ec2', etc.")
    account_id: str = Field(description="Cloud account / subscription ID.")
    region: str = Field(description="Geographic region of the resource.")
    name: Optional[str] = Field(default=None, description="Human-readable resource name.")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags.")
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Service-specific configuration. Keys are service-defined.",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this resource was collected.",
    )

    @property
    def display_name(self) -> str:
        """Best human-readable name for this resource."""
        return self.name or self.resource_id

    def get_config(self, key: str, default: Any = None) -> Any:
        """Safely retrieve a configuration value."""
        return self.config.get(key, default)


# ==============================================================================
# Provider Abstraction
# ==============================================================================

class DiscoveryResult(BaseModel):
    """Result returned by a provider's discover() method."""

    provider: str
    account_id: str
    regions: List[str]
    resources: List[CloudResource]
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def had_errors(self) -> bool:
        return len(self.errors) > 0

    def resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        return [r for r in self.resources if r.resource_type == resource_type]


class CloudProvider(ABC):
    """
    Abstract base for cloud providers.

    Implementations:
      - AWSProvider   — Real AWS via boto3
      - DemoProvider  — Deterministic mock data (no credentials needed)
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier: 'aws', 'demo', 'azure', etc."""
        ...

    @property
    @abstractmethod
    def account_id(self) -> str:
        """The cloud account / subscription ID."""
        ...

    @abstractmethod
    def validate_connection(self) -> bool:
        """
        Verify connectivity to the cloud provider.
        Returns True if connection is successful.
        Raises an exception with a descriptive error on failure.
        """
        ...

    @abstractmethod
    def discover(self, regions: Optional[List[str]] = None) -> DiscoveryResult:
        """
        Discover all supported resources.

        Args:
            regions: Optional list of regions to scan.
                     None means use the provider's default.

        Returns:
            DiscoveryResult with all discovered CloudResource objects.
        """
        ...
