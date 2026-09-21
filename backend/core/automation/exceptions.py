"""
CloudGuard — Automation Domain Exceptions (Phase 9)
"""
from typing import Optional


class AutomationError(Exception):
    """Base exception for all automation domain errors."""
    def __init__(self, message: str, code: str = "AUTOMATION_ERROR", details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class KillSwitchActiveError(AutomationError):
    def __init__(self, message: str = "Emergency automation kill switch is ACTIVE. Automation is halted."):
        super().__init__(message=message, code="KILL_SWITCH_ACTIVE")


class DestructiveActionBlockedError(AutomationError):
    def __init__(self, message: str = "Destructive remediation actions are strictly prohibited from automation."):
        super().__init__(message=message, code="DESTRUCTIVE_ACTION_BLOCKED")


class AutomationBlockedError(AutomationError):
    def __init__(self, message: str, code: str = "AUTOMATION_BLOCKED"):
        super().__init__(message=message, code=code)


class PolicyNotFoundError(AutomationError):
    def __init__(self, policy_id: str):
        super().__init__(message=f"Automation policy '{policy_id}' not found.", code="POLICY_NOT_FOUND")


class PolicyConflictError(AutomationError):
    def __init__(self, message: str):
        super().__init__(message=message, code="POLICY_CONFLICT")


class InvalidAutomationTransitionError(AutomationError):
    def __init__(self, from_state: str, to_state: str):
        super().__init__(
            message=f"Invalid automation state transition from '{from_state}' to '{to_state}'.",
            code="INVALID_AUTOMATION_TRANSITION",
        )
