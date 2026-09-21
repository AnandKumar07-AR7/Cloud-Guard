"""
CloudGuard — SQLAlchemy Database Models

Defines the relational schema for PostgreSQL persistence.
Uses JSON columns for flexible structured data (config, evidence, etc).
"""
from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator, VARCHAR
import json

from core.database import Base


# We use a custom JSON type decorator for SQLite compatibility in tests.
class JSONEncodedDict(TypeDecorator):
    """Enables JSON storage safely across SQLite and PostgreSQL."""
    impl = VARCHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(String())

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if isinstance(value, dict) or isinstance(value, list):
                return value
            return json.loads(value)
        return value


class ScanDBModel(Base):
    __tablename__ = "scans"

    scan_id = Column(String(36), primary_key=True)
    correlation_id = Column(String(36), nullable=False)
    provider = Column(String(50), nullable=False, index=True)
    account_id = Column(String(100), nullable=False)
    mode = Column(String(20), nullable=False)
    scenario = Column(String(50), nullable=True)
    
    regions = Column(JSONEncodedDict, nullable=False, default=list)
    status = Column(String(50), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    resource_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    
    # Aggregates from risk summary
    posture_score = Column(Float, nullable=True)
    risk_level = Column(String(50), nullable=True)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Full JSON dumps for complex payloads that don't need independent querying
    risk_summary = Column(JSONEncodedDict, nullable=True)
    errors = Column(JSONEncodedDict, nullable=False, default=list)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    findings = relationship("FindingDBModel", back_populates="scan", cascade="all, delete-orphan")
    resources = relationship("ResourceSnapshotDBModel", back_populates="scan", cascade="all, delete-orphan")


class ResourceDBModel(Base):
    """
    Persistent identity for a cloud resource across scans.
    Identity is strictly provider + account + ARN.
    """
    __tablename__ = "resources"

    resource_id = Column(String(255), primary_key=True) # Typically the ARN or unique identifier
    provider = Column(String(50), nullable=False)
    account_id = Column(String(100), nullable=False)
    region = Column(String(50), nullable=False)
    service = Column(String(50), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    
    name = Column(String(255), nullable=True)
    tags = Column(JSONEncodedDict, nullable=False, default=dict)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    snapshots = relationship("ResourceSnapshotDBModel", back_populates="resource", cascade="all, delete-orphan")
    findings = relationship("FindingDBModel", back_populates="resource")


class ResourceSnapshotDBModel(Base):
    """
    Point-in-time configuration snapshot of a resource during a specific scan.
    """
    __tablename__ = "resource_snapshots"

    snapshot_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    resource_id = Column(String(255), ForeignKey("resources.resource_id"), nullable=False, index=True)
    
    configuration = Column(JSONEncodedDict, nullable=False, default=dict)
    observed_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    scan = relationship("ScanDBModel", back_populates="resources")
    resource = relationship("ResourceDBModel", back_populates="snapshots")


class FindingDBModel(Base):
    __tablename__ = "findings"

    finding_id = Column(String(36), primary_key=True)
    canonical_id = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    resource_id = Column(String(255), ForeignKey("resources.resource_id"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=False, index=True)
    rule_version = Column(String(20), nullable=True)
    
    resource_type = Column(String(100), nullable=False, index=True)
    service = Column(String(50), nullable=False, index=True)
    account_id = Column(String(50), nullable=False, index=True)
    region = Column(String(50), nullable=False, index=True)
    
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    category = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, index=True)
    internet_exposed = Column(Boolean, nullable=False, default=False, index=True)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # Rich context
    evidence = Column(JSONEncodedDict, nullable=False, default=dict)
    security_context = Column(JSONEncodedDict, nullable=True)
    risk_context = Column(JSONEncodedDict, nullable=True)
    remediation_context = Column(JSONEncodedDict, nullable=True)
    compliance_context = Column(JSONEncodedDict, nullable=True)
    
    first_detected_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_detected_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    scan = relationship("ScanDBModel", back_populates="findings")
    resource = relationship("ResourceDBModel", back_populates="findings")
    ai_analysis = relationship("AIAnalysisDBModel", back_populates="finding", uselist=False, cascade="all, delete-orphan")


class RelationshipDBModel(Base):
    __tablename__ = "resource_relationships"

    relationship_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    
    source_resource_id = Column(String(255), nullable=False, index=True)
    target_resource_id = Column(String(255), nullable=False, index=True)
    target_resource_type = Column(String(100), nullable=False, server_default="unknown")
    target_service = Column(String(50), nullable=False, server_default="unknown")
    relationship_type = Column(String(50), nullable=False)
    
    evidence = Column(JSONEncodedDict, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


ResourceRelationshipDBModel = RelationshipDBModel


class AIAnalysisDBModel(Base):
    __tablename__ = "ai_analyses"

    ai_analysis_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=False, unique=True)
    
    ai_source = Column(String(50), nullable=False) # 'claude' or 'template'
    executive_summary = Column(Text, nullable=False)
    technical_analysis = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    attack_relevance = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    confidence = Column(String(20), nullable=False)
    limitations = Column(Text, nullable=True)
    
    observed_facts = Column(JSONEncodedDict, nullable=False, default=list)
    ai_inferences = Column(JSONEncodedDict, nullable=False, default=list)
    
    generated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    finding = relationship("FindingDBModel", back_populates="ai_analysis")

# ==============================================================================
# Phase 7: Remediation Engine Models
# ==============================================================================

class RemediationPlanDBModel(Base):
    __tablename__ = "remediation_plans"

    remediation_id = Column(String(36), primary_key=True)
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False)
    resource_id = Column(String(255), ForeignKey("resources.resource_id"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=False)
    
    state = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    validation_result = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    
    created_by = Column(String(36), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    approved_by = Column(String(36), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    
    execution_started_at = Column(DateTime(timezone=True), nullable=True)
    execution_completed_at = Column(DateTime(timezone=True), nullable=True)

    actions = relationship("RemediationActionDBModel", back_populates="plan", cascade="all, delete-orphan")
    executions = relationship("RemediationExecutionDBModel", back_populates="plan", cascade="all, delete-orphan")
    audit_events = relationship("RemediationAuditEventDBModel", back_populates="plan", cascade="all, delete-orphan")


class RemediationActionDBModel(Base):
    __tablename__ = "remediation_actions"

    action_id = Column(String(36), primary_key=True)
    remediation_id = Column(String(36), ForeignKey("remediation_plans.remediation_id"), nullable=False, index=True)
    
    action_type = Column(String(100), nullable=False)
    provider = Column(String(50), nullable=False)
    service = Column(String(50), nullable=False)
    resource_identifier = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    safety = Column(String(50), nullable=False)
    
    parameters = Column(JSONEncodedDict, nullable=False, default=dict)

    plan = relationship("RemediationPlanDBModel", back_populates="actions")


class RemediationExecutionDBModel(Base):
    __tablename__ = "remediation_executions"

    execution_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remediation_id = Column(String(36), ForeignKey("remediation_plans.remediation_id"), nullable=False, index=True)
    
    status = Column(String(50), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    attempt_number = Column(Integer, nullable=False, default=1)
    
    error_message = Column(Text, nullable=True)
    safe_details = Column(JSONEncodedDict, nullable=False, default=dict)

    plan = relationship("RemediationPlanDBModel", back_populates="executions")


class RemediationAuditEventDBModel(Base):
    __tablename__ = "remediation_audit_events"

    event_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remediation_id = Column(String(36), ForeignKey("remediation_plans.remediation_id"), nullable=False, index=True)
    execution_id = Column(String(36), ForeignKey("remediation_executions.execution_id"), nullable=True, index=True)
    
    event_type = Column(String(100), nullable=False)
    actor_user_id = Column(String(36), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    
    previous_state = Column(String(50), nullable=True)
    new_state = Column(String(50), nullable=True)
    request_id = Column(String(64), nullable=True, index=True)
    
    safe_details = Column(JSONEncodedDict, nullable=False, default=dict)

    sequence_number = Column(Integer, nullable=False, default=1)
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False)

    plan = relationship("RemediationPlanDBModel", back_populates="audit_events")


# ==============================================================================
# Phase 8: AI Agent Orchestration Models
# ==============================================================================

class AIAgentRunDBModel(Base):
    """
    Persistent record of an AI analysis run for a security finding.
    Tracks provider, model, execution status, tool call count, duration, and error category.
    Never stores raw prompts, raw LLM token streams, or credentials.
    """
    __tablename__ = "ai_runs"

    run_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=False, index=True)
    initiating_user_id = Column(String(36), ForeignKey("users.user_id"), nullable=False, index=True)
    
    provider_type = Column(String(50), nullable=False)  # 'demo' | 'anthropic'
    model_name = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, index=True)  # PENDING, RUNNING, COMPLETED, FAILED, TIMED_OUT, CANCELLED
    
    tool_call_count = Column(Integer, nullable=False, default=0)
    duration_ms = Column(Integer, nullable=True)
    error_category = Column(String(100), nullable=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    finding = relationship("FindingDBModel")
    recommendations = relationship("AIRecommendationDBModel", back_populates="run", cascade="all, delete-orphan")
    tool_events = relationship("AIToolEventDBModel", back_populates="run", cascade="all, delete-orphan")


class AIRecommendationDBModel(Base):
    """
    Immutable validated AI recommendation.
    Append-only: no update or delete endpoints exist.
    Uses 'recommendation_rationale' for user-facing explanation (no hidden chain-of-thought).
    Confidence is informational only and cannot trigger execution or bypass controls.
    """
    __tablename__ = "ai_recommendations"

    recommendation_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), ForeignKey("ai_runs.run_id"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=False, index=True)
    
    recommended_strategy_id = Column(String(100), nullable=True)
    analysis_summary = Column(Text, nullable=False)
    risk_summary = Column(Text, nullable=False)
    recommendation_rationale = Column(Text, nullable=False)
    expected_impact = Column(Text, nullable=False)
    
    confidence = Column(Float, nullable=False)  # Informational only
    requires_approval = Column(Boolean, nullable=False, default=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    run = relationship("AIAgentRunDBModel", back_populates="recommendations")
    finding = relationship("FindingDBModel")


class AIToolEventDBModel(Base):
    """
    Audit log of server-controlled tool execution requested by AI.
    Contains sanitized inputs and outputs only. Never stores secrets or raw tokens.
    """
    __tablename__ = "ai_tool_events"

    event_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), ForeignKey("ai_runs.run_id"), nullable=False, index=True)
    
    tool_name = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, index=True)  # SUCCESS, FAILED, BLOCKED
    
    input_summary = Column(JSONEncodedDict, nullable=False, default=dict)
    output_summary = Column(JSONEncodedDict, nullable=False, default=dict)
    error_category = Column(String(100), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    run = relationship("AIAgentRunDBModel", back_populates="tool_events")


# ==============================================================================
# Phase 9: Policy-Governed Automation Orchestration Models
# ==============================================================================

class AutomationPolicyDBModel(Base):
    """
    Persistent declarative automation policy governing remediation workflow progression.
    Fully deterministic criteria: providers, services, resource types, rules, strategies, actions, safety levels.
    """
    __tablename__ = "automation_policies"

    policy_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    enabled = Column(Boolean, nullable=False, default=False, index=True)
    priority = Column(Integer, nullable=False, default=50, index=True)
    version = Column(Integer, nullable=False, default=1)

    allowed_providers = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_services = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_resource_types = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_rule_ids = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_strategies = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_action_types = Column(JSONEncodedDict, nullable=False, default=list)
    allowed_safety_levels = Column(JSONEncodedDict, nullable=False, default=list)

    min_severity = Column(String(20), nullable=True)
    max_severity = Column(String(20), nullable=True)

    auto_progress_validation = Column(Boolean, nullable=False, default=True)
    auto_progress_approval = Column(Boolean, nullable=False, default=False)
    auto_progress_execution = Column(Boolean, nullable=False, default=False)
    require_human_approval = Column(Boolean, nullable=False, default=True)

    created_by = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    updated_by = Column(String(36), ForeignKey("users.user_id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    creator = relationship("UserDBModel", foreign_keys=[created_by])
    updater = relationship("UserDBModel", foreign_keys=[updated_by])
    decisions = relationship("AutomationDecisionDBModel", back_populates="policy")


class AutomationDecisionDBModel(Base):
    """
    Immutable snapshot of an automation policy evaluation on a remediation plan.
    Records the exact policy version, cryptographic hash of policy rules, decision outcome, and explanation.
    """
    __tablename__ = "automation_decisions"

    decision_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remediation_id = Column(String(36), ForeignKey("remediation_plans.remediation_id"), nullable=False, index=True)
    policy_id = Column(String(36), ForeignKey("automation_policies.policy_id"), nullable=True, index=True)
    policy_version = Column(Integer, nullable=True)
    policy_hash = Column(String(64), nullable=True)

    decision = Column(String(50), nullable=False, index=True)  # ELIGIBLE, NOT_ELIGIBLE, BLOCKED_BY_KILL_SWITCH, BLOCKED_BY_SAFETY, REQUIRE_HUMAN_APPROVAL, etc.
    reason = Column(Text, nullable=False)
    evaluated_by = Column(String(36), ForeignKey("users.user_id"), nullable=False, index=True)
    evaluated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    decision_context = Column(JSONEncodedDict, nullable=False, default=dict)

    remediation_plan = relationship("RemediationPlanDBModel")
    policy = relationship("AutomationPolicyDBModel", back_populates="decisions")
    evaluator = relationship("UserDBModel")
    progressions = relationship("AutomationProgressionDBModel", back_populates="decision")


class AutomationProgressionDBModel(Base):
    """
    Audit record of an automated state progression executed on a Phase 7 remediation plan.
    """
    __tablename__ = "automation_progressions"

    progression_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remediation_id = Column(String(36), ForeignKey("remediation_plans.remediation_id"), nullable=False, index=True)
    decision_id = Column(String(36), ForeignKey("automation_decisions.decision_id"), nullable=False, index=True)

    from_state = Column(String(50), nullable=False)
    to_state = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, index=True)  # PROGRESSING, SUCCESS, FAILED
    error_message = Column(Text, nullable=True)

    executed_by = Column(String(36), ForeignKey("users.user_id"), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    remediation_plan = relationship("RemediationPlanDBModel")
    decision = relationship("AutomationDecisionDBModel", back_populates="progressions")
    executor = relationship("UserDBModel")


class AutomationAuditEventDBModel(Base):
    """
    Append-only audit events for automation policy lifecycle and emergency kill-switch toggling.
    Uses SHA-256 hash chaining for tamper-evidence.
    """
    __tablename__ = "automation_audit_events"

    event_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(100), nullable=False, index=True)
    actor_user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True, index=True)
    policy_id = Column(String(36), nullable=True, index=True)
    remediation_id = Column(String(36), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    safe_details = Column(JSONEncodedDict, nullable=False, default=dict)
    sequence_number = Column(Integer, nullable=False, default=1)
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False)

    actor = relationship("UserDBModel")


class AutomationSettingDBModel(Base):
    """
    Persistent system-wide settings for automation orchestration (e.g. global kill-switch).
    """
    __tablename__ = "automation_settings"

    setting_key = Column(String(50), primary_key=True)
    setting_value = Column(JSONEncodedDict, nullable=False, default=dict)
    updated_by = Column(String(36), ForeignKey("users.user_id"), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    updater = relationship("UserDBModel")


# ── Phase 10: Model Context Protocol (MCP) Control Plane Models ──────────────

class MCPServerDBModel(Base):
    """
    Persistent registry for CloudGuard Model Context Protocol (MCP) servers.
    Tracks lifecycle, status, health, latency metrics, and permission scopes.
    """
    __tablename__ = "mcp_servers"

    server_id = Column(String(50), primary_key=True)
    server_name = Column(String(100), nullable=False, unique=True, index=True)
    version = Column(String(20), nullable=False, default="1.0.0")
    server_type = Column(String(50), nullable=False)  # discovery, security, remediation
    status = Column(String(20), nullable=False, default="HEALTHY")  # HEALTHY, DEGRADED, UNAVAILABLE, DISABLED
    permission_scope = Column(JSONEncodedDict, nullable=False, default=list)
    enabled = Column(Boolean, nullable=False, default=True)

    request_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)
    avg_latency_ms = Column(Float, nullable=False, default=0.0)

    last_health_check = Column(DateTime(timezone=True), nullable=True)
    last_request_at = Column(DateTime(timezone=True), nullable=True)
    last_error_at = Column(DateTime(timezone=True), nullable=True)
    last_error_code = Column(String(50), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    tools = relationship("MCPToolDBModel", back_populates="server", cascade="all, delete-orphan")


class MCPToolDBModel(Base):
    """
    Persistent registry for tools exposed by CloudGuard MCP servers.
    Explicitly tracks operation class (READ/WRITE/DESTRUCTIVE) and required RBAC permission.
    """
    __tablename__ = "mcp_tools"

    tool_id = Column(String(100), primary_key=True)  # e.g., "cloudguard-discovery-mcp:list_resources"
    server_id = Column(String(50), ForeignKey("mcp_servers.server_id"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    operation_class = Column(String(20), nullable=False)  # READ, WRITE, DESTRUCTIVE
    input_schema = Column(JSONEncodedDict, nullable=False, default=dict)
    output_schema = Column(JSONEncodedDict, nullable=False, default=dict)
    required_permission = Column(String(100), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    version = Column(String(20), nullable=False, default="1.0.0")

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    server = relationship("MCPServerDBModel", back_populates="tools")


class MCPAuditEventDBModel(Base):
    """
    Append-only audit events for all MCP tool invocations and control operations.
    Enforces SHA-256 hash chaining and secret sanitization.
    """
    __tablename__ = "mcp_audit_events"

    event_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(36), nullable=False, index=True)
    correlation_id = Column(String(36), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.user_id"), nullable=True, index=True)
    server_id = Column(String(50), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False, index=True)
    operation_class = Column(String(20), nullable=False)
    authorized = Column(Boolean, nullable=False, default=True)
    status = Column(String(20), nullable=False, index=True)  # SUCCESS, FAILED, BLOCKED
    latency_ms = Column(Integer, nullable=False, default=0)
    error_code = Column(String(50), nullable=True)

    safe_details = Column(JSONEncodedDict, nullable=False, default=dict)
    sequence_number = Column(Integer, nullable=False, default=1)
    previous_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    user = relationship("UserDBModel")



