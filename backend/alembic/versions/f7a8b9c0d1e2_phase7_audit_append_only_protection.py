"""phase7_audit_append_only_protection

Revision ID: f7a8b9c0d1e2
Revises: eadcfff5a24b
Create Date: 2026-09-07 11:15:00.000000

"""
from typing import Sequence, Union
import hashlib
import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column, select

# revision identifiers, used by Alembic.
revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, Sequence[str], None] = 'eadcfff5a24b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _format_canonical_ts(ts) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        return ts
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def _compute_event_hash(
    remediation_id: str,
    sequence_number: int,
    event_type: str,
    timestamp_str: str,
    previous_event_hash: Union[str, None],
    actor_user_id: Union[str, None] = None,
    execution_id: Union[str, None] = None,
    previous_state: Union[str, None] = None,
    new_state: Union[str, None] = None,
    request_id: Union[str, None] = None,
    safe_details: Union[dict, None] = None,
) -> str:
    canonical_payload = {
        "actor_user_id": actor_user_id,
        "event_type": event_type,
        "execution_id": execution_id,
        "new_state": new_state,
        "previous_event_hash": previous_event_hash,
        "previous_state": previous_state,
        "remediation_id": remediation_id,
        "request_id": request_id,
        "safe_details": safe_details or {},
        "sequence_number": sequence_number,
        "timestamp": timestamp_str,
    }
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # 1. Add columns (initially nullable for backfill)
    op.add_column('remediation_audit_events', sa.Column('sequence_number', sa.Integer(), nullable=True))
    op.add_column('remediation_audit_events', sa.Column('previous_event_hash', sa.String(length=64), nullable=True))
    op.add_column('remediation_audit_events', sa.Column('event_hash', sa.String(length=64), nullable=True))

    # 2. Backfill existing records deterministically
    audit_table = table(
        'remediation_audit_events',
        column('event_id', sa.String),
        column('remediation_id', sa.String),
        column('execution_id', sa.String),
        column('event_type', sa.String),
        column('actor_user_id', sa.String),
        column('timestamp', sa.DateTime),
        column('previous_state', sa.String),
        column('new_state', sa.String),
        column('request_id', sa.String),
        column('safe_details', sa.JSON),
        column('sequence_number', sa.Integer),
        column('previous_event_hash', sa.String),
        column('event_hash', sa.String),
    )

    connection = op.get_bind()
    rows = connection.execute(
        select(
            audit_table.c.event_id,
            audit_table.c.remediation_id,
            audit_table.c.execution_id,
            audit_table.c.event_type,
            audit_table.c.actor_user_id,
            audit_table.c.timestamp,
            audit_table.c.previous_state,
            audit_table.c.new_state,
            audit_table.c.request_id,
            audit_table.c.safe_details,
        ).order_by(audit_table.c.remediation_id, audit_table.c.timestamp.asc())
    ).fetchall()

    if rows:
        from collections import defaultdict
        grouped = defaultdict(list)
        for r in rows:
            grouped[r.remediation_id].append(r)

        for rem_id, events in grouped.items():
            prev_hash = None
            for idx, ev in enumerate(events, start=1):
                ts_str = _format_canonical_ts(ev.timestamp)
                details = ev.safe_details
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except Exception:
                        details = {}
                h = _compute_event_hash(
                    remediation_id=rem_id,
                    sequence_number=idx,
                    event_type=ev.event_type,
                    timestamp_str=ts_str,
                    previous_event_hash=prev_hash,
                    actor_user_id=ev.actor_user_id,
                    execution_id=ev.execution_id,
                    previous_state=ev.previous_state,
                    new_state=ev.new_state,
                    request_id=ev.request_id,
                    safe_details=details,
                )
                connection.execute(
                    audit_table.update()
                    .where(audit_table.c.event_id == ev.event_id)
                    .values(
                        sequence_number=idx,
                        previous_event_hash=prev_hash,
                        event_hash=h,
                    )
                )
                prev_hash = h

    # 3. Enforce NOT NULL on sequence_number and event_hash
    op.alter_column('remediation_audit_events', 'sequence_number', nullable=False)
    op.alter_column('remediation_audit_events', 'event_hash', nullable=False)

    # 4. Create composite index on (remediation_id, sequence_number)
    op.create_index(
        'ix_remediation_audit_events_seq',
        'remediation_audit_events',
        ['remediation_id', 'sequence_number'],
        unique=True
    )

    # 5. Attach PostgreSQL trigger for database-enforced append-only immutability
    if is_postgres:
        op.execute("""
        CREATE OR REPLACE FUNCTION prevent_remediation_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Remediation audit records are append-only. UPDATE and DELETE operations are prohibited.';
        END;
        $$ LANGUAGE plpgsql;
        """)

        op.execute("""
        DROP TRIGGER IF EXISTS trg_remediation_audit_prevent_update_delete ON remediation_audit_events;
        CREATE TRIGGER trg_remediation_audit_prevent_update_delete
        BEFORE UPDATE OR DELETE ON remediation_audit_events
        FOR EACH ROW
        EXECUTE FUNCTION prevent_remediation_audit_modification();
        """)


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute("DROP TRIGGER IF EXISTS trg_remediation_audit_prevent_update_delete ON remediation_audit_events;")
        op.execute("DROP FUNCTION IF EXISTS prevent_remediation_audit_modification();")

    op.drop_index('ix_remediation_audit_events_seq', table_name='remediation_audit_events')
    op.drop_column('remediation_audit_events', 'event_hash')
    op.drop_column('remediation_audit_events', 'previous_event_hash')
    op.drop_column('remediation_audit_events', 'sequence_number')
