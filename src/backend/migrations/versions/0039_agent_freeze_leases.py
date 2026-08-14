"""agent_freeze_leases — durable database execution fence

Revision ID: 0039_agent_freeze_leases
Revises: 0038_portal_chat_state
Create Date: 2026-08-13
"""

from alembic import op


revision = "0039_agent_freeze_leases"
down_revision = "0038_portal_chat_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE schedule_executions "
        "ADD COLUMN IF NOT EXISTS dispatch_attempt_count INTEGER NOT NULL DEFAULT 0"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_freeze_leases (
            id TEXT PRIMARY KEY,
            agent_name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            claimed_at TEXT,
            claim_expires_at TEXT,
            claimed_by TEXT,
            released_at TEXT,
            released_by TEXT,
            schedule_revision TEXT NOT NULL
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_freeze_one_active "
        "ON agent_freeze_leases(agent_name) WHERE active = 1"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION agent_freeze_schedule_guard_fn() RETURNS trigger AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(NEW.agent_name, 0));
            IF NEW.enabled = 1 AND EXISTS (
                SELECT 1 FROM agent_freeze_leases
                WHERE agent_name = NEW.agent_name AND active = 1
            ) THEN
                RAISE EXCEPTION 'agent freeze lease blocks schedule enable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE OR REPLACE TRIGGER agent_freeze_block_enabled_schedule_insert
        BEFORE INSERT ON agent_schedules
        FOR EACH ROW EXECUTE FUNCTION agent_freeze_schedule_guard_fn()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE TRIGGER agent_freeze_block_schedule_enable
        BEFORE UPDATE OF enabled ON agent_schedules
        FOR EACH ROW EXECUTE FUNCTION agent_freeze_schedule_guard_fn()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION agent_freeze_execution_guard_fn() RETURNS trigger AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended(NEW.agent_name, 0));
            IF COALESCE(NEW.status, '') NOT IN ('success', 'failed', 'cancelled', 'skipped') THEN
                IF TG_OP = 'INSERT' AND EXISTS (
                    SELECT 1 FROM agent_freeze_leases
                    WHERE agent_name = NEW.agent_name AND active = 1
                ) THEN
                    RAISE EXCEPTION 'agent freeze lease blocks execution dispatch';
                ELSIF TG_OP = 'UPDATE'
                   AND (
                        NEW.status IS DISTINCT FROM OLD.status
                        OR NEW.dispatch_attempt_count IS DISTINCT FROM OLD.dispatch_attempt_count
                   )
                   AND EXISTS (
                       SELECT 1 FROM agent_freeze_leases
                       WHERE agent_name = NEW.agent_name AND active = 1
                   ) THEN
                    RAISE EXCEPTION 'agent freeze lease blocks execution dispatch';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE OR REPLACE TRIGGER agent_freeze_block_execution_insert
        BEFORE INSERT ON schedule_executions
        FOR EACH ROW EXECUTE FUNCTION agent_freeze_execution_guard_fn()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE TRIGGER agent_freeze_block_execution_redispatch
        BEFORE UPDATE OF status, dispatch_attempt_count ON schedule_executions
        FOR EACH ROW EXECUTE FUNCTION agent_freeze_execution_guard_fn()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS agent_freeze_block_execution_redispatch ON schedule_executions")
    op.execute("DROP TRIGGER IF EXISTS agent_freeze_block_execution_insert ON schedule_executions")
    op.execute("DROP FUNCTION IF EXISTS agent_freeze_execution_guard_fn()")
    op.execute("DROP TRIGGER IF EXISTS agent_freeze_block_schedule_enable ON agent_schedules")
    op.execute("DROP TRIGGER IF EXISTS agent_freeze_block_enabled_schedule_insert ON agent_schedules")
    op.execute("DROP FUNCTION IF EXISTS agent_freeze_schedule_guard_fn()")
    op.execute("DROP INDEX IF EXISTS idx_agent_freeze_one_active")
    op.execute("DROP TABLE IF EXISTS agent_freeze_leases")
    op.execute("ALTER TABLE schedule_executions DROP COLUMN IF EXISTS dispatch_attempt_count")
