"""phase9_automation_orchestration

Revision ID: b9c0d1e2f3a4
Revises: a8b1c2d3e4f5
Create Date: 2026-09-07 15:00:00.000000

"""
import datetime
import json
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import core.db_models

# revision identifiers, used by Alembic.
revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, Sequence[str], None] = 'a8b1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create automation_policies ──────────────────────────────────────────
    op.create_table(
        'automation_policies',
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('allowed_providers', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_services', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_resource_types', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_rule_ids', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_strategies', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_action_types', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('allowed_safety_levels', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('min_severity', sa.String(length=20), nullable=True),
        sa.Column('max_severity', sa.String(length=20), nullable=True),
        sa.Column('auto_progress_validation', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('auto_progress_approval', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('auto_progress_execution', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('require_human_approval', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('updated_by', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.user_id']),
        sa.ForeignKeyConstraint(['updated_by'], ['users.user_id']),
        sa.PrimaryKeyConstraint('policy_id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_automation_policies_name'), 'automation_policies', ['name'], unique=True)
    op.create_index(op.f('ix_automation_policies_enabled'), 'automation_policies', ['enabled'], unique=False)
    op.create_index(op.f('ix_automation_policies_priority'), 'automation_policies', ['priority'], unique=False)
    op.create_index(op.f('ix_automation_policies_created_at'), 'automation_policies', ['created_at'], unique=False)

    # ── 2. Create automation_decisions ─────────────────────────────────────────
    op.create_table(
        'automation_decisions',
        sa.Column('decision_id', sa.String(length=36), nullable=False),
        sa.Column('remediation_id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=True),
        sa.Column('policy_version', sa.Integer(), nullable=True),
        sa.Column('policy_hash', sa.String(length=64), nullable=True),
        sa.Column('decision', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('evaluated_by', sa.String(length=36), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('decision_context', core.db_models.JSONEncodedDict(), nullable=False),
        sa.ForeignKeyConstraint(['remediation_id'], ['remediation_plans.remediation_id']),
        sa.ForeignKeyConstraint(['policy_id'], ['automation_policies.policy_id']),
        sa.ForeignKeyConstraint(['evaluated_by'], ['users.user_id']),
        sa.PrimaryKeyConstraint('decision_id')
    )
    op.create_index(op.f('ix_automation_decisions_remediation_id'), 'automation_decisions', ['remediation_id'], unique=False)
    op.create_index(op.f('ix_automation_decisions_policy_id'), 'automation_decisions', ['policy_id'], unique=False)
    op.create_index(op.f('ix_automation_decisions_decision'), 'automation_decisions', ['decision'], unique=False)
    op.create_index(op.f('ix_automation_decisions_evaluated_by'), 'automation_decisions', ['evaluated_by'], unique=False)
    op.create_index(op.f('ix_automation_decisions_evaluated_at'), 'automation_decisions', ['evaluated_at'], unique=False)

    # ── 3. Create automation_progressions ──────────────────────────────────────
    op.create_table(
        'automation_progressions',
        sa.Column('progression_id', sa.String(length=36), nullable=False),
        sa.Column('remediation_id', sa.String(length=36), nullable=False),
        sa.Column('decision_id', sa.String(length=36), nullable=False),
        sa.Column('from_state', sa.String(length=50), nullable=False),
        sa.Column('to_state', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('executed_by', sa.String(length=36), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['remediation_id'], ['remediation_plans.remediation_id']),
        sa.ForeignKeyConstraint(['decision_id'], ['automation_decisions.decision_id']),
        sa.ForeignKeyConstraint(['executed_by'], ['users.user_id']),
        sa.PrimaryKeyConstraint('progression_id')
    )
    op.create_index(op.f('ix_automation_progressions_remediation_id'), 'automation_progressions', ['remediation_id'], unique=False)
    op.create_index(op.f('ix_automation_progressions_decision_id'), 'automation_progressions', ['decision_id'], unique=False)
    op.create_index(op.f('ix_automation_progressions_status'), 'automation_progressions', ['status'], unique=False)
    op.create_index(op.f('ix_automation_progressions_executed_by'), 'automation_progressions', ['executed_by'], unique=False)
    op.create_index(op.f('ix_automation_progressions_started_at'), 'automation_progressions', ['started_at'], unique=False)

    # ── 4. Create automation_audit_events ──────────────────────────────────────
    op.create_table(
        'automation_audit_events',
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('actor_user_id', sa.String(length=36), nullable=True),
        sa.Column('policy_id', sa.String(length=36), nullable=True),
        sa.Column('remediation_id', sa.String(length=36), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('safe_details', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('sequence_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('previous_event_hash', sa.String(length=64), nullable=True),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index(op.f('ix_automation_audit_events_event_type'), 'automation_audit_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_automation_audit_events_actor_user_id'), 'automation_audit_events', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_automation_audit_events_policy_id'), 'automation_audit_events', ['policy_id'], unique=False)
    op.create_index(op.f('ix_automation_audit_events_remediation_id'), 'automation_audit_events', ['remediation_id'], unique=False)
    op.create_index(op.f('ix_automation_audit_events_timestamp'), 'automation_audit_events', ['timestamp'], unique=False)

    # ── 5. Create automation_settings ──────────────────────────────────────────
    op.create_table(
        'automation_settings',
        sa.Column('setting_key', sa.String(length=50), nullable=False),
        sa.Column('setting_value', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('updated_by', sa.String(length=36), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['updated_by'], ['users.user_id']),
        sa.PrimaryKeyConstraint('setting_key')
    )

    # Seed permissions & default kill-switch setting
    _seed_phase9_data()


def _seed_phase9_data() -> None:
    conn = op.get_bind()
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Seed global_kill_switch setting
    settings_table = sa.table(
        'automation_settings',
        sa.column('setting_key'),
        sa.column('setting_value'),
        sa.column('updated_by'),
        sa.column('updated_at')
    )
    op.bulk_insert(settings_table, [{
        'setting_key': 'global_kill_switch',
        'setting_value': json.dumps({'enabled': False}),
        'updated_by': None,
        'updated_at': now,
    }])

    # 2. Seed permissions
    perms_table = sa.table(
        'permissions',
        sa.column('permission_id'),
        sa.column('name'),
        sa.column('description'),
        sa.column('created_at')
    )
    role_perms_table = sa.table(
        'role_permissions',
        sa.column('role_id'),
        sa.column('permission_id')
    )

    new_permissions = {
        "automation.read": "View automation policies, decisions, and status.",
        "automation.evaluate": "Evaluate findings and remediation plans against automation policies.",
        "automation.manage": "Create, update, and manage automation policies.",
        "automation.killswitch": "Emergency control to enable or disable the automation kill switch.",
        "automation.audit.read": "View automation audit trail.",
    }

    # Fetch existing roles
    roles = conn.execute(sa.text("SELECT role_id, name FROM roles")).fetchall()
    role_map = {r[1]: r[0] for r in roles}

    perm_id_map = {}
    for perm_name, perm_desc in new_permissions.items():
        # Check if permission already exists
        existing = conn.execute(
            sa.text("SELECT permission_id FROM permissions WHERE name = :name"),
            {"name": perm_name}
        ).fetchone()

        if existing:
            perm_id = existing[0]
        else:
            perm_id = str(uuid.uuid4())
            op.bulk_insert(perms_table, [{
                "permission_id": perm_id,
                "name": perm_name,
                "description": perm_desc,
                "created_at": now,
            }])
        perm_id_map[perm_name] = perm_id

    # Attach to roles according to ROLE_PERMISSIONS
    role_grants = {
        "ADMIN": ["automation.read", "automation.evaluate", "automation.manage", "automation.killswitch", "automation.audit.read"],
        "SECURITY_ANALYST": ["automation.read", "automation.evaluate", "automation.audit.read"],
        "OPERATOR": ["automation.read", "automation.audit.read"],
        "VIEWER": ["automation.read"],
    }

    for role_name, granted_perms in role_grants.items():
        role_id = role_map.get(role_name)
        if not role_id:
            continue
        for perm_name in granted_perms:
            pid = perm_id_map.get(perm_name)
            if not pid:
                continue
            # Check if mapping already exists
            existing_rp = conn.execute(
                sa.text("SELECT 1 FROM role_permissions WHERE role_id = :rid AND permission_id = :pid"),
                {"rid": role_id, "pid": pid}
            ).fetchone()
            if not existing_rp:
                op.bulk_insert(role_perms_table, [{
                    "role_id": role_id,
                    "permission_id": pid
                }])


def downgrade() -> None:
    op.drop_table('automation_settings')

    op.drop_index(op.f('ix_automation_audit_events_timestamp'), table_name='automation_audit_events')
    op.drop_index(op.f('ix_automation_audit_events_remediation_id'), table_name='automation_audit_events')
    op.drop_index(op.f('ix_automation_audit_events_policy_id'), table_name='automation_audit_events')
    op.drop_index(op.f('ix_automation_audit_events_actor_user_id'), table_name='automation_audit_events')
    op.drop_index(op.f('ix_automation_audit_events_event_type'), table_name='automation_audit_events')
    op.drop_table('automation_audit_events')

    op.drop_index(op.f('ix_automation_progressions_started_at'), table_name='automation_progressions')
    op.drop_index(op.f('ix_automation_progressions_executed_by'), table_name='automation_progressions')
    op.drop_index(op.f('ix_automation_progressions_status'), table_name='automation_progressions')
    op.drop_index(op.f('ix_automation_progressions_decision_id'), table_name='automation_progressions')
    op.drop_index(op.f('ix_automation_progressions_remediation_id'), table_name='automation_progressions')
    op.drop_table('automation_progressions')

    op.drop_index(op.f('ix_automation_decisions_evaluated_at'), table_name='automation_decisions')
    op.drop_index(op.f('ix_automation_decisions_evaluated_by'), table_name='automation_decisions')
    op.drop_index(op.f('ix_automation_decisions_decision'), table_name='automation_decisions')
    op.drop_index(op.f('ix_automation_decisions_policy_id'), table_name='automation_decisions')
    op.drop_index(op.f('ix_automation_decisions_remediation_id'), table_name='automation_decisions')
    op.drop_table('automation_decisions')

    op.drop_index(op.f('ix_automation_policies_created_at'), table_name='automation_policies')
    op.drop_index(op.f('ix_automation_policies_priority'), table_name='automation_policies')
    op.drop_index(op.f('ix_automation_policies_enabled'), table_name='automation_policies')
    op.drop_index(op.f('ix_automation_policies_name'), table_name='automation_policies')
    op.drop_table('automation_policies')
