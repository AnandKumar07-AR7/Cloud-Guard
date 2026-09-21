"""
Base collector class for all cloud resource collectors.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """
    Abstract base class for all resource collectors.

    Collectors are responsible for fetching raw resource configurations
    from cloud providers and normalizing them into a standard schema.
    """

    def __init__(self, session: Any = None):
        """
        Initialize the collector.

        Args:
            session: Cloud provider session/client (e.g., boto3.Session)
        """
        self.session = session

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect and normalize resources.

        Returns:
            List of normalized resource dictionaries with schema:
            {
                "resource_id": str,
                "resource_type": str,
                "config": dict
            }
        """
        pass

    def _normalize_resource(
        self,
        resource_id: str,
        resource_type: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a normalized resource dictionary.

        Args:
            resource_id: Unique identifier for the resource
            resource_type: Type of resource (e.g., "s3_bucket", "iam_role")
            config: Raw configuration dictionary

        Returns:
            Normalized resource dictionary
        """
        return {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "config": config
        }

    def _handle_error(self, error: Exception, resource_type: str) -> None:
        """
        Handle collection errors gracefully.

        Args:
            error: The exception that occurred
            resource_type: Type of resource being collected
        """
        logger.error(f"Error collecting {resource_type}: {str(error)}")
