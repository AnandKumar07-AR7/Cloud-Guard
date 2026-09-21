"""phase10_mcp_control_plane

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-09-15 11:00:00.000000

"""
import datetime
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import core.db_models

# revision identifiers, used by Alembic.
revision: str = 'c0d1e2f3a4b5'
down_revision: Union[str, Sequence[str], None] = 'b9c0d1e2f3a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create mcp_servers table ──────────────────────────────────────────
    op.create_table(
        'mcp_servers',
        sa.Column('server_id', sa.String(length=50), nullable=False),
        sa.Column('server_name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('server_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='HEALTHY'),
        sa.Column('permission_scope', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('request_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('avg_latency_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('last_health_check', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_request_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error_code', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('server_id'),
        sa.UniqueConstraint('server_name')
    )
    op.create_index(op.f('ix_mcp_servers_server_name'), 'mcp_servers', ['server_name'], unique=True)
    op.create_index(op.f('ix_mcp_servers_enabled'), 'mcp_servers', ['enabled'], unique=False)
    op.create_index(op.f('ix_mcp_servers_status'), 'mcp_servers', ['status'], unique=False)

    # ── 2. Create mcp_tools table ────────────────────────────────────────────
    op.create_table(
        'mcp_tools',
        sa.Column('tool_id', sa.String(length=100), nullable=False),
        sa.Column('server_id', sa.String(length=50), nullable=False),
        sa.Column('tool_name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('operation_class', sa.String(length=20), nullable=False),
        sa.Column('input_schema', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('output_schema', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('required_permission', sa.String(length=100), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['server_id'], ['mcp_servers.server_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('tool_id')
    )
    op.create_index(op.f('ix_mcp_tools_server_id'), 'mcp_tools', ['server_id'], unique=False)
    op.create_index(op.f('ix_mcp_tools_tool_name'), 'mcp_tools', ['tool_name'], unique=False)
    op.create_index(op.f('ix_mcp_tools_operation_class'), 'mcp_tools', ['operation_class'], unique=False)

    # ── 3. Create mcp_audit_events table ─────────────────────────────────────
    op.create_table(
        'mcp_audit_events',
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('correlation_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('server_id', sa.String(length=50), nullable=False),
        sa.Column('tool_name', sa.String(length=100), nullable=False),
        sa.Column('operation_class', sa.String(length=20), nullable=False),
        sa.Column('authorized', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('latency_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_code', sa.String(length=50), nullable=True),
        sa.Column('safe_details', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('sequence_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('previous_event_hash', sa.String(length=64), nullable=True),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id']),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index(op.f('ix_mcp_audit_events_request_id'), 'mcp_audit_events', ['request_id'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_correlation_id'), 'mcp_audit_events', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_user_id'), 'mcp_audit_events', ['user_id'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_server_id'), 'mcp_audit_events', ['server_id'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_tool_name'), 'mcp_audit_events', ['tool_name'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_status'), 'mcp_audit_events', ['status'], unique=False)
    op.create_index(op.f('ix_mcp_audit_events_timestamp'), 'mcp_audit_events', ['timestamp'], unique=False)

    # ── 4. Seed new MCP permissions ──────────────────────────────────────────
    conn = op.get_bind()
    mcp_permissions = [
        ("mcp.read", "mcp.read"),
        ("mcp.execute", "mcp.execute"),
        ("mcp.manage", "mcp.manage"),
        ("mcp.audit.read", "mcp.audit.read"),
    ]
    for perm_name, desc in mcp_permissions:
        conn.execute(
            sa.text(
                "INSERT INTO permissions (permission_id, name, description, created_at) "
                "VALUES (:pid, :name, :desc, NOW()) "
                "ON CONFLICT (name) DO NOTHING;"
            ),
            {"pid": str(uuid.uuid4()), "name": perm_name, "desc": desc}
        )

    # Assign MCP permissions to roles in role_permissions
    role_perm_mappings = [
        ("ADMIN", ["mcp.read", "mcp.execute", "mcp.manage", "mcp.audit.read"]),
        ("SECURITY_ANALYST", ["mcp.read", "mcp.execute", "mcp.audit.read"]),
        ("OPERATOR", ["mcp.read", "mcp.audit.read"]),
        ("VIEWER", ["mcp.read"]),
    ]
    for role_name, perms in role_perm_mappings:
        for perm in perms:
            conn.execute(
                sa.text("""
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT r.role_id, p.permission_id
                    FROM roles r, permissions p
                    WHERE r.name = :role_name AND p.name = :perm_name
                    ON CONFLICT DO NOTHING;
                """),
                {"role_name": role_name, "perm_name": perm}
            )


def downgrade() -> None:
    op.drop_table('mcp_audit_events')
    op.drop_table('mcp_tools')
    op.drop_table('mcp_servers')
