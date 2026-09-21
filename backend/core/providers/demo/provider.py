"""
CloudGuard — Demo Cloud Provider

Returns deterministic CloudResource objects representing a fictional
'Acme Corp' AWS environment. No AWS credentials required.

The DemoProvider supports multiple scenarios:
  default  → Realistic mix of secure + vulnerable resources (16 resources)
  healthy  → All correctly configured resources (no/minimal findings)
  critical → Maximum-severity misconfigurations

All resources from every scenario pass through the identical
SecurityRuleEngine → RiskEngine → AIService pipeline used by AWSProvider.
There is no short-circuit for demo mode at any layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from core.providers.base import CloudProvider, CloudResource, DiscoveryResult
from core.providers.demo.scenarios.base import DemoScenario
from core.providers.demo.scenarios.default import DefaultScenario
from core.providers.demo.scenarios.healthy import HealthyScenario
from core.providers.demo.scenarios.critical import CriticalScenario
from core.utils.logging import get_logger

log = get_logger(__name__)

_DEMO_ACCOUNT_ID = "123456789012"
_DEMO_REGIONS = ["us-east-1", "us-west-2"]

# Registry of available scenarios
_SCENARIOS: dict[str, type[DemoScenario]] = {
    "default": DefaultScenario,
    "healthy": HealthyScenario,
    "critical": CriticalScenario,
}


class DemoProvider(CloudProvider):
    """
    Cloud provider that returns deterministic fixture data.

    Properties:
      - No AWS credentials required.
      - Same data returned on every call (deterministic).
      - Scenario-based: pass scenario= to select a different environment.
      - Resources pass through the real security + risk pipeline.
    """

    def __init__(self, scenario: str = "default") -> None:
        if scenario not in _SCENARIOS:
            import warnings
            warnings.warn(
                f"Unknown demo scenario '{scenario}'. Available: {list(_SCENARIOS.keys())}. Falling back to 'default'.",
                UserWarning,
                stacklevel=2,
            )
            scenario = "default"
        self._scenario_name = scenario
        self._scenario: DemoScenario = _SCENARIOS[scenario]()

    @property
    def provider_name(self) -> str:
        return "demo"

    @property
    def account_id(self) -> str:
        return _DEMO_ACCOUNT_ID

    @property
    def scenario_name(self) -> str:
        return self._scenario_name

    @classmethod
    def available_scenarios(cls) -> List[str]:
        """Return names of all available demo scenarios."""
        return list(_SCENARIOS.keys())

    def validate_connection(self) -> bool:
        """Demo always has a valid 'connection'."""
        log.info("demo_provider_connected", account_id=self.account_id, scenario=self._scenario_name)
        return True

    def discover(self, regions: Optional[List[str]] = None) -> DiscoveryResult:
        """Return all resources from the selected scenario."""
        log.info(
            "demo_discovery_started",
            account_id=self.account_id,
            scenario=self._scenario_name,
        )

        resources: List[CloudResource] = []
        errors = []

        try:
            resources = self._scenario.get_resources()
        except Exception as exc:
            log.error("demo_scenario_load_error", scenario=self._scenario_name, error=str(exc))
            errors.append({"service": "scenario", "error": str(exc)})

        log.info(
            "demo_discovery_completed",
            scenario=self._scenario_name,
            resource_count=len(resources),
            error_count=len(errors),
        )

        return DiscoveryResult(
            provider=self.provider_name,
            account_id=self.account_id,
            regions=regions or _DEMO_REGIONS,
            resources=resources,
            errors=errors,
            completed_at=datetime.now(timezone.utc),
        )
