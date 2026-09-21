"""
CloudGuard — Demo Scenario Base

A DemoScenario is a named collection of CloudResource fixtures.
Each scenario represents a distinct fictional AWS environment state.

Architecture:
  - Scenarios are stateless fixture containers
  - All resources pass through the real security rule + risk engine
  - No scenario invents findings — findings emerge from actual resource config
  - Scenarios are designed to produce predictable finding sets for demos

Available scenarios:
  default  → Mixed secure + vulnerable (realistic enterprise env)
  healthy  → All resources correctly configured, minimal findings
  critical → Multiple critical misconfigurations for dramatic demo
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from core.providers.base import CloudResource


class DemoScenario(ABC):
    """Base class for all demo scenarios."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scenario identifier."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable scenario description."""
        ...

    @abstractmethod
    def get_resources(self) -> List[CloudResource]:
        """
        Return the full list of CloudResource fixtures for this scenario.
        Resources must not be generated randomly — they must be deterministic.
        """
        ...
