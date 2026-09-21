"""
CloudGuard Phase 4 Tests — Resource Relationships

Tests for:
  - RelationshipExtractor
  - EC2 to Security Group, IAM Instance Profile, VPC
  - Lambda to IAM Role, Security Group, VPC
  - RDS to Security Group, VPC
  - CloudTrail to S3 Bucket
  - Safe handling of None/missing config keys
  - No fabricated relationship edges
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.models import RelationshipType
from core.security.relationships import RelationshipExtractor, extract_relationships_for_scan


def _resource(
    resource_id: str,
    resource_type: ResourceType,
    service: str,
    config: dict,
) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=resource_type,
        provider="demo",
        service=service,
        account_id="123456789012",
        region="us-east-1",
        name=resource_id,
        config=config,
    )


class TestRelationshipExtractor:
    def test_ec2_to_security_group_and_iam_and_vpc(self):
        ec2 = _resource(
            "i-12345",
            ResourceType.EC2_INSTANCE,
            "ec2",
            {
                "security_group_ids": ["sg-web-001", "sg-ssh-002"],
                "iam_instance_profile": "arn:aws:iam::123456789012:instance-profile/web-profile",
                "vpc_id": "vpc-main-001",
            },
        )
        extractor = RelationshipExtractor([ec2])
        rels = extractor.extract(ec2)
        assert len(rels) == 4

        types = [r.relationship_type for r in rels]
        assert types.count(RelationshipType.PROTECTED_BY) == 2
        assert types.count(RelationshipType.USES) == 1
        assert types.count(RelationshipType.LOCATED_IN) == 1

        targets = {r.target_resource_id for r in rels}
        assert "sg-web-001" in targets
        assert "sg-ssh-002" in targets
        assert "arn:aws:iam::123456789012:instance-profile/web-profile" in targets
        assert "vpc-main-001" in targets

    def test_lambda_to_iam_and_vpc(self):
        fn = _resource(
            "arn:aws:lambda:us-east-1:123456789012:function:my-fn",
            ResourceType.LAMBDA_FUNCTION,
            "lambda",
            {
                "execution_role_arn": "arn:aws:iam::123456789012:role/lambda-role",
                "vpc_config": {
                    "vpc_id": "vpc-001",
                    "security_group_ids": ["sg-lambda-001"],
                },
            },
        )
        extractor = RelationshipExtractor([fn])
        rels = extractor.extract(fn)
        assert len(rels) == 3

        role_rel = next(r for r in rels if r.relationship_type == RelationshipType.ASSUMES)
        assert role_rel.target_resource_id == "arn:aws:iam::123456789012:role/lambda-role"
        assert role_rel.target_service == "iam"

        sg_rel = next(r for r in rels if r.relationship_type == RelationshipType.PROTECTED_BY)
        assert sg_rel.target_resource_id == "sg-lambda-001"

        vpc_rel = next(r for r in rels if r.relationship_type == RelationshipType.LOCATED_IN)
        assert vpc_rel.target_resource_id == "vpc-001"

    def test_lambda_with_none_vpc_config_does_not_error(self):
        fn = _resource(
            "arn:aws:lambda:us-east-1:123456789012:function:clean-fn",
            ResourceType.LAMBDA_FUNCTION,
            "lambda",
            {
                "execution_role_arn": "arn:aws:iam::123456789012:role/clean-role",
                "vpc_config": None,
            },
        )
        extractor = RelationshipExtractor([fn])
        rels = extractor.extract(fn)
        assert len(rels) == 1
        assert rels[0].relationship_type == RelationshipType.ASSUMES

    def test_rds_to_security_group_and_vpc(self):
        rds = _resource(
            "db-prod-01",
            ResourceType.RDS_INSTANCE,
            "rds",
            {
                "security_group_ids": ["sg-db-001"],
                "vpc_id": "vpc-main-001",
            },
        )
        extractor = RelationshipExtractor([rds])
        rels = extractor.extract(rds)
        assert len(rels) == 2
        assert rels[0].relationship_type == RelationshipType.PROTECTED_BY
        assert rels[0].target_resource_id == "sg-db-001"
        assert rels[1].relationship_type == RelationshipType.LOCATED_IN
        assert rels[1].target_resource_id == "vpc-main-001"

    def test_cloudtrail_to_s3_bucket(self):
        trail = _resource(
            "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail",
            ResourceType.CLOUDTRAIL,
            "cloudtrail",
            {"s3_bucket_name": "acme-audit-logs"},
        )
        extractor = RelationshipExtractor([trail])
        rels = extractor.extract(trail)
        assert len(rels) == 1
        assert rels[0].relationship_type == RelationshipType.DEPENDS_ON
        assert rels[0].target_resource_id == "acme-audit-logs"
        assert rels[0].target_service == "s3"

    def test_empty_config_produces_no_relationships(self):
        ec2 = _resource("i-empty", ResourceType.EC2_INSTANCE, "ec2", {})
        extractor = RelationshipExtractor([ec2])
        assert extractor.extract(ec2) == []

    def test_extract_all_helper(self):
        ec2 = _resource("i-1", ResourceType.EC2_INSTANCE, "ec2", {"security_group_ids": ["sg-1"]})
        rds = _resource("db-1", ResourceType.RDS_INSTANCE, "rds", {"security_group_ids": ["sg-2"]})
        res_map = extract_relationships_for_scan([ec2, rds])
        assert "i-1" in res_map
        assert "db-1" in res_map
        assert len(res_map["i-1"]) == 1
        assert len(res_map["db-1"]) == 1
