"""phase8_ai_orchestration

Revision ID: a8b1c2d3e4f5
Revises: f7a8b9c0d1e2
Create Date: 2026-09-07 13:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import core.db_models

# revision identifiers, used by Alembic.
revision: str = 'a8b1c2d3e4f5'
down_revision: Union[str, Sequence[str], None] = 'f7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create ai_runs ──────────────────────────────────────────────────────
    op.create_table(
        'ai_runs',
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('initiating_user_id', sa.String(length=36), nullable=False),
        sa.Column('provider_type', sa.String(length=50), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('tool_call_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('error_category', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.finding_id'], ),
        sa.ForeignKeyConstraint(['initiating_user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('run_id')
    )
    op.create_index(op.f('ix_ai_runs_finding_id'), 'ai_runs', ['finding_id'], unique=False)
    op.create_index(op.f('ix_ai_runs_initiating_user_id'), 'ai_runs', ['initiating_user_id'], unique=False)
    op.create_index(op.f('ix_ai_runs_status'), 'ai_runs', ['status'], unique=False)
    op.create_index(op.f('ix_ai_runs_created_at'), 'ai_runs', ['created_at'], unique=False)

    # ── 2. Create ai_recommendations ──────────────────────────────────────────
    op.create_table(
        'ai_recommendations',
        sa.Column('recommendation_id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('recommended_strategy_id', sa.String(length=100), nullable=True),
        sa.Column('analysis_summary', sa.Text(), nullable=False),
        sa.Column('risk_summary', sa.Text(), nullable=False),
        sa.Column('recommendation_rationale', sa.Text(), nullable=False),
        sa.Column('expected_impact', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('requires_approval', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['run_id'], ['ai_runs.run_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.finding_id'], ),
        sa.PrimaryKeyConstraint('recommendation_id')
    )
    op.create_index(op.f('ix_ai_recommendations_run_id'), 'ai_recommendations', ['run_id'], unique=False)
    op.create_index(op.f('ix_ai_recommendations_finding_id'), 'ai_recommendations', ['finding_id'], unique=False)
    op.create_index(op.f('ix_ai_recommendations_created_at'), 'ai_recommendations', ['created_at'], unique=False)

    # ── 3. Create ai_tool_events ──────────────────────────────────────────────
    op.create_table(
        'ai_tool_events',
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('tool_name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('input_summary', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('output_summary', core.db_models.JSONEncodedDict(), nullable=False),
        sa.Column('error_category', sa.String(length=100), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['run_id'], ['ai_runs.run_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index(op.f('ix_ai_tool_events_run_id'), 'ai_tool_events', ['run_id'], unique=False)
    op.create_index(op.f('ix_ai_tool_events_status'), 'ai_tool_events', ['status'], unique=False)
    op.create_index(op.f('ix_ai_tool_events_created_at'), 'ai_tool_events', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ai_tool_events_created_at'), table_name='ai_tool_events')
    op.drop_index(op.f('ix_ai_tool_events_status'), table_name='ai_tool_events')
    op.drop_index(op.f('ix_ai_tool_events_run_id'), table_name='ai_tool_events')
    op.drop_table('ai_tool_events')

    op.drop_index(op.f('ix_ai_recommendations_created_at'), table_name='ai_recommendations')
    op.drop_index(op.f('ix_ai_recommendations_finding_id'), table_name='ai_recommendations')
    op.drop_index(op.f('ix_ai_recommendations_run_id'), table_name='ai_recommendations')
    op.drop_table('ai_recommendations')

    op.drop_index(op.f('ix_ai_runs_created_at'), table_name='ai_runs')
    op.drop_index(op.f('ix_ai_runs_status'), table_name='ai_runs')
    op.drop_index(op.f('ix_ai_runs_initiating_user_id'), table_name='ai_runs')
    op.drop_index(op.f('ix_ai_runs_finding_id'), table_name='ai_runs')
    op.drop_table('ai_runs')
