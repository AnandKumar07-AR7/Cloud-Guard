"""
CloudGuard — Default Demo Scenario

Mixed secure + vulnerable infrastructure representing a realistic enterprise
AWS environment. Contains resources from every supported service with a
deliberate mix of misconfigurations and correctly-configured resources.

Expected findings (via actual rule engine):
  - S3: public access block missing, public ACL, missing encryption, no versioning
  - IAM: wildcard actions, overly broad resources, admin policies
  - SG: SSH/RDP/MySQL exposed to internet
  - Lambda: secrets in env vars, deprecated runtime, public resource policy
"""
from __future__ import annotations

from typing import List

from core.providers.base import CloudResource
from core.providers.demo.fixtures.cloudtrail_fixtures import get_cloudtrail_fixtures
from core.providers.demo.fixtures.ec2_fixtures import get_ec2_fixtures
from core.providers.demo.fixtures.iam_fixtures import get_iam_fixtures
from core.providers.demo.fixtures.lambda_fixtures import get_lambda_fixtures
from core.providers.demo.fixtures.rds_fixtures import get_rds_fixtures
from core.providers.demo.fixtures.s3_fixtures import get_s3_fixtures
from core.providers.demo.fixtures.sg_fixtures import get_sg_fixtures
from core.providers.demo.fixtures.vpc_fixtures import get_vpc_fixtures
from core.providers.demo.scenarios.base import DemoScenario


class DefaultScenario(DemoScenario):
    """
    Default demo scenario — mixed environment.

    This is the scenario used when no explicit scenario is requested.
    It models 'Acme Corp', a fictional company whose AWS environment
    reflects common real-world misconfiguration patterns.
    """

    @property
    def name(self) -> str:
        return "default"

    @property
    def description(self) -> str:
        return (
            "Mixed secure and vulnerable infrastructure representing a typical "
            "enterprise AWS environment. Contains a realistic combination of "
            "misconfigurations and correctly-configured resources."
        )

    def get_resources(self) -> List[CloudResource]:
        resources: List[CloudResource] = []
        resources.extend(get_s3_fixtures())
        resources.extend(get_iam_fixtures())
        resources.extend(get_sg_fixtures())
        resources.extend(get_lambda_fixtures())
        resources.extend(get_ec2_fixtures())
        resources.extend(get_rds_fixtures())
        resources.extend(get_vpc_fixtures())
        resources.extend(get_cloudtrail_fixtures())
        return resources
