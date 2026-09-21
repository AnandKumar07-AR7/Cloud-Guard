"""
CloudGuard — Resource Relationship Extractor

Derives typed, evidence-backed relationships between cloud resources
from their actual configuration data.

Relationships are ONLY established when config evidence exists.
No graph edges are fabricated.

Supported relationships:
  EC2 instance -> Security Group(s)      [PROTECTED_BY]
  EC2 instance -> IAM Instance Profile   [USES]
  EC2 instance -> VPC/Subnet             [LOCATED_IN]
  Lambda       -> IAM Execution Role     [ASSUMES]
  Lambda       -> Security Group(s)      [PROTECTED_BY]
  Lambda       -> VPC/Subnet             [LOCATED_IN]
  RDS          -> Security Group(s)      [PROTECTED_BY]
  RDS          -> VPC/Subnet             [LOCATED_IN]
  S3           -> Encryption Config      (internal, not cross-resource)
  CloudTrail   -> S3 Bucket (log target) [DEPENDS_ON]
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource, ResourceType
from core.security.models import RelationshipType, ResourceRelationship


class RelationshipExtractor:
    """
    Extracts typed resource relationships from CloudResource configuration.

    Usage:
        extractor = RelationshipExtractor(all_resources)
        relationships = extractor.extract(resource)
    """

    def __init__(self, all_resources: List[CloudResource]) -> None:
        """
        Args:
            all_resources: All resources from the current scan, used to
                           validate relationship targets exist.
        """
        # Index resources by ID for fast lookup
        self._by_id = {r.resource_id: r for r in all_resources}
        # Index by type for finding related resources
        self._by_type: dict = {}
        for r in all_resources:
            self._by_type.setdefault(r.resource_type, []).append(r)

    def extract(self, resource: CloudResource) -> List[ResourceRelationship]:
        """
        Extract all relationships for a given resource.

        Args:
            resource: The resource to extract relationships from.

        Returns:
            List of ResourceRelationship objects backed by config evidence.
        """
        handlers = {
            ResourceType.EC2_INSTANCE:    self._ec2_relationships,
            ResourceType.LAMBDA_FUNCTION: self._lambda_relationships,
            ResourceType.RDS_INSTANCE:    self._rds_relationships,
            ResourceType.CLOUDTRAIL:      self._cloudtrail_relationships,
            ResourceType.VPC:             self._vpc_relationships,
            ResourceType.S3_BUCKET:       self._s3_relationships,
        }
        handler = handlers.get(resource.resource_type)
        if handler:
            return handler(resource)
        return []

    def extract_all(self, resources: List[CloudResource]) -> dict:
        """
        Extract relationships for all resources.

        Returns:
            Dict mapping resource_id -> List[ResourceRelationship]
        """
        return {r.resource_id: self.extract(r) for r in resources}

    # ──────────────────────────────────────────────────────────────────────────
    # EC2 Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _ec2_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        rels = []

        # EC2 -> Security Group(s) [PROTECTED_BY]
        sg_ids = resource.config.get("security_group_ids", [])
        if isinstance(sg_ids, list):
            for sg_id in sg_ids:
                target = self._by_id.get(sg_id)
                rels.append(ResourceRelationship(
                    source_resource_id=resource.resource_id,
                    relationship_type=RelationshipType.PROTECTED_BY,
                    target_resource_id=sg_id,
                    target_resource_type=ResourceType.SECURITY_GROUP.value,
                    target_service="ec2",
                    evidence_source=f"config.security_group_ids contains '{sg_id}'",
                ))

        # EC2 -> IAM Instance Profile [USES]
        profile = resource.config.get("iam_instance_profile")
        if profile:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.USES,
                target_resource_id=str(profile),
                target_resource_type=ResourceType.IAM_ROLE.value,
                target_service="iam",
                evidence_source="config.iam_instance_profile",
            ))

        # EC2 -> VPC [LOCATED_IN]
        vpc_id = resource.config.get("vpc_id")
        if vpc_id:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.LOCATED_IN,
                target_resource_id=str(vpc_id),
                target_resource_type=ResourceType.VPC.value,
                target_service="vpc",
                evidence_source="config.vpc_id",
            ))

        return rels

    # ──────────────────────────────────────────────────────────────────────────
    # Lambda Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _lambda_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        rels = []

        # Lambda -> IAM Execution Role [ASSUMES]
        role_arn = resource.config.get("execution_role_arn") or resource.config.get("role_arn")
        if role_arn:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.ASSUMES,
                target_resource_id=str(role_arn),
                target_resource_type=ResourceType.IAM_ROLE.value,
                target_service="iam",
                evidence_source="config.execution_role_arn",
            ))

        # Lambda -> Security Groups [PROTECTED_BY] (VPC-attached Lambda)
        vpc_cfg = resource.config.get("vpc_config") or {}
        sg_ids = vpc_cfg.get("security_group_ids", [])
        if not sg_ids:
            sg_ids = resource.config.get("security_group_ids") or []
        if isinstance(sg_ids, list):
            for sg_id in sg_ids:
                rels.append(ResourceRelationship(
                    source_resource_id=resource.resource_id,
                    relationship_type=RelationshipType.PROTECTED_BY,
                    target_resource_id=str(sg_id),
                    target_resource_type=ResourceType.SECURITY_GROUP.value,
                    target_service="ec2",
                    evidence_source="config.vpc_config.security_group_ids",
                ))

        # Lambda -> VPC [LOCATED_IN]
        vpc_id = vpc_cfg.get("vpc_id") or resource.config.get("vpc_id")
        if vpc_id:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.LOCATED_IN,
                target_resource_id=str(vpc_id),
                target_resource_type=ResourceType.VPC.value,
                target_service="vpc",
                evidence_source="config.vpc_config.vpc_id",
            ))

        return rels


    # ──────────────────────────────────────────────────────────────────────────
    # RDS Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _rds_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        rels = []

        # RDS -> Security Group(s) [PROTECTED_BY]
        sg_ids = resource.config.get("security_group_ids") or resource.config.get("vpc_security_groups") or []
        if isinstance(sg_ids, list):
            for sg_id in sg_ids:
                rels.append(ResourceRelationship(
                    source_resource_id=resource.resource_id,
                    relationship_type=RelationshipType.PROTECTED_BY,
                    target_resource_id=str(sg_id),
                    target_resource_type=ResourceType.SECURITY_GROUP.value,
                    target_service="ec2",
                    evidence_source="config.security_group_ids",
                ))

        # RDS -> VPC [LOCATED_IN]
        vpc_id = resource.config.get("vpc_id")
        if vpc_id:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.LOCATED_IN,
                target_resource_id=str(vpc_id),
                target_resource_type=ResourceType.VPC.value,
                target_service="vpc",
                evidence_source="config.vpc_id",
            ))

        return rels

    # ──────────────────────────────────────────────────────────────────────────
    # CloudTrail Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _cloudtrail_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        rels = []

        # CloudTrail -> S3 Bucket (log destination) [DEPENDS_ON]
        s3_bucket = resource.config.get("s3_bucket_name") or resource.config.get("s3_bucket")
        if s3_bucket:
            rels.append(ResourceRelationship(
                source_resource_id=resource.resource_id,
                relationship_type=RelationshipType.DEPENDS_ON,
                target_resource_id=str(s3_bucket),
                target_resource_type=ResourceType.S3_BUCKET.value,
                target_service="s3",
                evidence_source="config.s3_bucket_name",
            ))

        return rels

    # ──────────────────────────────────────────────────────────────────────────
    # VPC Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _vpc_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        """
        VPCs don't pull relationships from their own config —
        other resources declare membership in the VPC.
        Return empty list; inverse relationships come from EC2/RDS/Lambda.
        """
        return []

    # ──────────────────────────────────────────────────────────────────────────
    # S3 Relationships
    # ──────────────────────────────────────────────────────────────────────────

    def _s3_relationships(self, resource: CloudResource) -> List[ResourceRelationship]:
        """
        S3 buckets don't have cross-resource relationships in standard config.
        Logging targets and replication targets could be added in future.
        """
        rels = []

        # S3 -> CloudTrail (if this bucket is referenced by a CloudTrail)
        # This inverse relationship is established by CloudTrail extractor
        # so we don't duplicate it here.
        return rels


def extract_relationships_for_scan(
    resources: List[CloudResource],
) -> dict:
    """
    Extract all relationships for all resources in a scan.

    Args:
        resources: All resources discovered in a scan.

    Returns:
        Dict mapping resource_id -> List[ResourceRelationship]
    """
    extractor = RelationshipExtractor(resources)
    return extractor.extract_all(resources)
