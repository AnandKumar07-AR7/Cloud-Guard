"""
CloudGuard — Remediation State Machine
"""
from enum import Enum

class RemediationState(str, Enum):
    """
    Strict lifecycle states for a remediation plan.
    Transitions must be enforced server-side.
    """
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFYING = "VERIFYING"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFIED_UNFIXED = "VERIFIED_UNFIXED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    CANCELLED = "CANCELLED"

# Define valid transitions FROM a state to a list of allowed states
VALID_TRANSITIONS = {
    RemediationState.DRAFT: {
        RemediationState.VALIDATED,
        RemediationState.PENDING_APPROVAL,
        RemediationState.CANCELLED
    },
    RemediationState.VALIDATED: {
        RemediationState.PENDING_APPROVAL,
        RemediationState.DRAFT,
        RemediationState.CANCELLED
    },
    RemediationState.PENDING_APPROVAL: {
        RemediationState.APPROVED,
        RemediationState.REJECTED,
        RemediationState.CANCELLED
    },
    RemediationState.APPROVED: {
        RemediationState.EXECUTING,
        RemediationState.CANCELLED
    },
    RemediationState.EXECUTING: {
        RemediationState.EXECUTED,
        RemediationState.EXECUTION_FAILED
    },
    RemediationState.EXECUTED: {
        RemediationState.VERIFYING
    },
    RemediationState.VERIFYING: {
        RemediationState.VERIFIED_FIXED,
        RemediationState.VERIFICATION_FAILED,
        RemediationState.VERIFIED_UNFIXED
    },
    # Terminal states have no valid outbound transitions
    RemediationState.REJECTED: set(),
    RemediationState.CANCELLED: set(),
    RemediationState.VERIFIED_FIXED: set(),
    RemediationState.VERIFICATION_FAILED: set(),
    RemediationState.VERIFIED_UNFIXED: set(),
    RemediationState.EXECUTION_FAILED: set(),
}

def is_valid_transition(current_state: RemediationState, next_state: RemediationState) -> bool:
    """Check if a transition is explicitly allowed."""
    return next_state in VALID_TRANSITIONS.get(current_state, set())

class RemediationSafety(str, Enum):
    """
    Safety classification for remediation actions.
    """
    READ_ONLY = "READ_ONLY"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    DESTRUCTIVE = "DESTRUCTIVE"
