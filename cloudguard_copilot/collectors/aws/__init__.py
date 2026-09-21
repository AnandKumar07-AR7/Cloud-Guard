"""
AWS resource collectors.
"""

from cloudguard_copilot.collectors.aws.s3_collector import S3Collector
from cloudguard_copilot.collectors.aws.iam_collector import IAMCollector
from cloudguard_copilot.collectors.aws.sg_collector import SecurityGroupCollector
from cloudguard_copilot.collectors.aws.lambda_collector import LambdaCollector

__all__ = ["S3Collector", "IAMCollector", "SecurityGroupCollector", "LambdaCollector"]
