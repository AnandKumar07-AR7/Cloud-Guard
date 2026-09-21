"""
CloudGuard — Remediation Provider Abstraction
"""
from abc import ABC, abstractmethod
from typing import Dict, Any

from core.remediation.models import RemediationAction, RemediationExecutionResult, RemediationVerificationResult

class RemediationProvider(ABC):
    """
    Abstract base for remediation execution.
    Strictly separates infrastructure modification from discovery (CloudProvider).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier: 'aws', 'demo'."""
        ...

    @abstractmethod
    def validate_action(self, action: RemediationAction) -> bool:
        """
        Validate that the action type is supported and its parameters are correct.
        Throws a ValueError or specific exception on invalid action.
        """
        ...

    @abstractmethod
    def execute_action(self, action: RemediationAction) -> RemediationExecutionResult:
        """
        Execute the remediation action against the provider.
        Returns the execution result indicating API success or failure.
        """
        ...

    @abstractmethod
    def verify_action(self, action: RemediationAction) -> RemediationVerificationResult:
        """
        Independently verify that the resource state was successfully changed
        and the vulnerability is no longer present.
        """
        ...
