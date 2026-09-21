"""
Detectors for identifying security misconfigurations.
"""

from cloudguard_copilot.detectors.s3_detector import detect_s3_misconfigurations
from cloudguard_copilot.detectors.iam_detector import detect_iam_misconfigurations
from cloudguard_copilot.detectors.sg_detector import detect_sg_misconfigurations
from cloudguard_copilot.detectors.lambda_detector import detect_lambda_misconfigurations

__all__ = [
    "detect_s3_misconfigurations",
    "detect_iam_misconfigurations",
    "detect_sg_misconfigurations",
    "detect_lambda_misconfigurations"
]
