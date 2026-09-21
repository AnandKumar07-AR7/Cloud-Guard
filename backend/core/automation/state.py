"""
CloudGuard — Automation Lifecycle State Machine (Phase 9)
"""
from enum import Enum
from typing import Set


class AutomationState(str, Enum):
    NOT_EVALUATED           = "NOT_EVALUATED"
    EVALUATING              = "EVALUATING"
    ELIGIBLE                = "ELIGIBLE"
    NOT_ELIGIBLE            = "NOT_ELIGIBLE"
    BLOCKED_BY_KILL_SWITCH  = "BLOCKED_BY_KILL_SWITCH"
    BLOCKED_BY_SAFETY       = "BLOCKED_BY_SAFETY"
    AWAITING_HUMAN_ACTION   = "AWAITING_HUMAN_ACTION"
    PROGRESSING             = "PROGRESSING"
    PROGRESSION_COMPLETED   = "PROGRESSION_COMPLETED"
    PROGRESSION_FAILED      = "PROGRESSION_FAILED"


VALID_AUTOMATION_TRANSITIONS = {
    AutomationState.NOT_EVALUATED: {
        AutomationState.EVALUATING,
        AutomationState.BLOCKED_BY_KILL_SWITCH,
    },
    AutomationState.EVALUATING: {
        AutomationState.ELIGIBLE,
        AutomationState.NOT_ELIGIBLE,
        AutomationState.BLOCKED_BY_KILL_SWITCH,
        AutomationState.BLOCKED_BY_SAFETY,
        AutomationState.AWAITING_HUMAN_ACTION,
    },
    AutomationState.ELIGIBLE: {
        AutomationState.PROGRESSING,
        AutomationState.EVALUATING,
        AutomationState.BLOCKED_BY_KILL_SWITCH,
    },
    AutomationState.NOT_ELIGIBLE: {
        AutomationState.EVALUATING,
    },
    AutomationState.BLOCKED_BY_KILL_SWITCH: {
        AutomationState.EVALUATING,
    },
    AutomationState.BLOCKED_BY_SAFETY: {
        AutomationState.EVALUATING,
    },
    AutomationState.AWAITING_HUMAN_ACTION: {
        AutomationState.EVALUATING,
        AutomationState.PROGRESSING,
    },
    AutomationState.PROGRESSING: {
        AutomationState.PROGRESSION_COMPLETED,
        AutomationState.PROGRESSION_FAILED,
    },
    # Terminal outcomes for an execution attempt (can be re-evaluated if plan is updated)
    AutomationState.PROGRESSION_COMPLETED: {
        AutomationState.EVALUATING,
    },
    AutomationState.PROGRESSION_FAILED: {
        AutomationState.EVALUATING,
    },
}


def is_valid_automation_transition(current_state: AutomationState, next_state: AutomationState) -> bool:
    """Returns True if transition is explicitly allowed."""
    return next_state in VALID_AUTOMATION_TRANSITIONS.get(current_state, set())
