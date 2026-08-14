from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import sqlite3
import threading

import httpx
import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from db.engine import get_engine
from db.tables import agent_ownership, agent_schedules, schedule_executions, users
from services import agent_freeze_service as freeze
from services import task_execution_service as task_service
from services.agent_client import AgentClient, AgentRequestError
from db_harness import db_backend  # noqa: F401 - pytest fixture export


AGENT = "freeze-test-agent"
NOW = "2026-08-13T12:00:00Z"


def _seed_agent(*, enabled_schedules: int = 2) -> None:
    with get_engine().begin() as conn:
        conn.execute(
            insert(users).values(
                id=1,
                username="admin",
                email="admin@example.test",
                password_hash="x",
                role="admin",
                created_at=NOW,
                updated_at=NOW,
            )
        )
        conn.execute(
            insert(agent_ownership).values(
                agent_name=AGENT,
                owner_id=1,
                created_at=NOW,
            )
        )
        for number in range(enabled_schedules):
            conn.execute(
                insert(agent_schedules).values(
                    id=f"schedule-{number}",
                    agent_name=AGENT,
                    name=f"schedule {number}",
                    cron_expression="0 * * * *",
                    message="run",
                    enabled=1,
                    timezone="UTC",
                    owner_id=1,
                    created_at=NOW,
                    updated_at=NOW,
                    next_run_at="2026-08-13T13:00:00Z",
                )
            )


def _execution(execution_id: str, status: str, triggered_by: str = "manual") -> None:
    with get_engine().begin() as conn:
        conn.execute(
            insert(schedule_executions).values(
                id=execution_id,
                schedule_id="__manual__",
                agent_name=AGENT,
                status=status,
                started_at=NOW,
                message="work",
                triggered_by=triggered_by,
            )
        )


def test_create_is_atomic_disable_and_exact_count(db_backend) -> None:  # noqa: F811
    _seed_agent()
    for status in ("running", "queued", "pending_retry", "unknown_future_status"):
        _execution(f"execution-{status}", status)
    for status in freeze.TERMINAL_STATUSES:
        _execution(f"terminal-{status}", status)

    lease = freeze.create_freeze(AGENT, created_by="operator")

    assert lease.nonterminal_count == 4
    assert lease.active is True
    assert lease.schedule_revision == lease.schedule_digest
    with get_engine().connect() as conn:
        rows = conn.execute(
            select(agent_schedules.c.enabled, agent_schedules.c.next_run_at).where(
                agent_schedules.c.agent_name == AGENT
            )
        ).all()
    assert rows == [(0, None), (0, None)]
    with pytest.raises(freeze.AgentFreezeNotDrained) as exc:
        freeze.claim_freeze(AGENT, lease.lease_id, claimed_by=AGENT)
    assert exc.value.nonterminal_count == 4


@pytest.mark.parametrize(
    "triggered_by",
    ["schedule", "manual", "api", "retry", "webhook", "agent", "fan_out", "loop"],
)
def test_active_lease_blocks_every_new_dispatch(  # noqa: F811
    db_backend,  # noqa: F811
    triggered_by: str,
) -> None:
    _seed_agent()
    freeze.create_freeze(AGENT, created_by="operator")

    with pytest.raises(IntegrityError, match="freeze lease blocks execution dispatch"):
        _execution(f"blocked-{triggered_by}", "running", triggered_by)


def test_active_lease_blocks_queued_and_retry_redispatch(db_backend) -> None:  # noqa: F811
    _seed_agent()
    _execution("queued", "queued", "api")
    _execution("retry", "pending_retry", "retry")
    freeze.create_freeze(AGENT, created_by="operator")

    for execution_id in ("queued", "retry"):
        with pytest.raises(IntegrityError, match="freeze lease blocks execution dispatch"):
            with get_engine().begin() as conn:
                conn.execute(
                    update(schedule_executions)
                    .where(schedule_executions.c.id == execution_id)
                    .values(status="running")
                )


def test_every_wire_attempt_is_transactionally_fenced(db_backend) -> None:  # noqa: F811
    _seed_agent()
    _execution("wire-attempt", "running", "api")

    assert freeze.get_active_freeze(AGENT) is None
    from database import db

    assert db.authorize_execution_dispatch("wire-attempt", AGENT) is True
    lease = freeze.create_freeze(AGENT, created_by="operator")
    assert lease.nonterminal_count == 1
    with pytest.raises(freeze.AgentFreezeNotDrained):
        freeze.claim_freeze(AGENT, lease.lease_id, claimed_by=AGENT)
    with pytest.raises(IntegrityError, match="freeze lease blocks execution dispatch"):
        db.authorize_execution_dispatch("wire-attempt", AGENT)


def test_wire_attempt_and_freeze_creation_have_no_zero_count_race(
    db_backend,  # noqa: F811
) -> None:
    _seed_agent()
    _execution("racing-wire", "running", "api")
    barrier = threading.Barrier(2)

    def authorize() -> str:
        from database import db

        barrier.wait()
        try:
            return (
                "authorized"
                if db.authorize_execution_dispatch("racing-wire", AGENT)
                else "missing"
            )
        except IntegrityError:
            return "blocked"

    def create() -> freeze.AgentFreezeSnapshot:
        barrier.wait()
        return freeze.create_freeze(AGENT, created_by="operator")

    with ThreadPoolExecutor(max_workers=2) as pool:
        authorize_future = pool.submit(authorize)
        freeze_future = pool.submit(create)
        dispatch_result = authorize_future.result()
        lease = freeze_future.result()

    assert dispatch_result in {"authorized", "blocked"}
    # If dispatch serialized first it is exactly represented by this running
    # row; if the lease serialized first, the wire authorization was rejected.
    assert lease.nonterminal_count == 1
    with pytest.raises(freeze.AgentFreezeNotDrained):
        freeze.claim_freeze(AGENT, lease.lease_id, claimed_by=AGENT)


def test_schedule_enable_is_blocked_and_freeze_revision_is_immutable(  # noqa: F811
    db_backend,  # noqa: F811
) -> None:
    _seed_agent()
    lease = freeze.create_freeze(AGENT, created_by="operator")

    with pytest.raises(IntegrityError, match="freeze lease blocks schedule enable"):
        with get_engine().begin() as conn:
            conn.execute(
                update(agent_schedules)
                .where(agent_schedules.c.id == "schedule-0")
                .values(enabled=1)
            )

    with get_engine().begin() as conn:
        conn.execute(
            update(agent_schedules)
            .where(agent_schedules.c.id == "schedule-0")
            .values(message="mutated while frozen", updated_at="2026-08-13T12:01:00Z")
        )
    reread = freeze.get_active_freeze(AGENT)
    assert reread is not None
    assert reread.schedule_revision == lease.schedule_revision
    assert reread.schedule_digest == lease.schedule_digest


def test_concurrent_enable_and_dispatch_are_both_rejected(
    db_backend,  # noqa: F811
) -> None:
    _seed_agent()
    freeze.create_freeze(AGENT, created_by="operator")
    barrier = threading.Barrier(2)

    def enable() -> str:
        barrier.wait()
        try:
            with get_engine().begin() as conn:
                conn.execute(
                    update(agent_schedules)
                    .where(agent_schedules.c.id == "schedule-0")
                    .values(enabled=1)
                )
        except IntegrityError:
            return "blocked-enable"
        return "enabled"

    def dispatch() -> str:
        barrier.wait()
        try:
            _execution("concurrent-dispatch", "running", "api")
        except IntegrityError:
            return "blocked-dispatch"
        return "dispatched"

    with ThreadPoolExecutor(max_workers=2) as pool:
        enable_future = pool.submit(enable)
        dispatch_future = pool.submit(dispatch)
        results = {enable_future.result(), dispatch_future.result()}
    assert results == {"blocked-enable", "blocked-dispatch"}


def test_claim_and_second_approval_release_leave_schedules_disabled(
    db_backend, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    _seed_agent()
    lease = freeze.create_freeze(AGENT, created_by="operator-one")
    claimed = freeze.claim_freeze(
        AGENT,
        lease.lease_id,
        claimed_by=AGENT,
        claim_seconds=60,
    )
    assert claimed.nonterminal_count == 0
    assert claimed.claimed_by == AGENT

    with pytest.raises(freeze.AgentFreezeConflict, match="explicit second"):
        freeze.release_freeze(
            AGENT,
            lease.lease_id,
            released_by="operator-two",
            approve_release=False,
        )
    with pytest.raises(freeze.AgentFreezeConflict, match="cannot be released"):
        freeze.release_freeze(
            AGENT,
            lease.lease_id,
            released_by="operator-two",
            approve_release=True,
        )

    expiry = datetime.fromisoformat(claimed.claim_expires_at.replace("Z", "+00:00"))
    monkeypatch.setattr(freeze, "_now", lambda: expiry + timedelta(seconds=1))
    released = freeze.release_freeze(
        AGENT,
        lease.lease_id,
        released_by="operator-two",
        approve_release=True,
    )
    assert released.active is False
    assert freeze.get_active_freeze(AGENT) is None

    with get_engine().connect() as conn:
        enabled = conn.execute(
            select(agent_schedules.c.enabled).where(
                agent_schedules.c.agent_name == AGENT
            )
        ).scalars().all()
    assert enabled == [0, 0]


def test_release_must_be_approved_by_distinct_operator(
    db_backend,  # noqa: F811
) -> None:
    _seed_agent(enabled_schedules=0)
    lease = freeze.create_freeze(AGENT, created_by="operator-one")
    with pytest.raises(freeze.AgentFreezeConflict, match="distinct second"):
        freeze.release_freeze(
            AGENT,
            lease.lease_id,
            released_by="operator-one",
            approve_release=True,
        )


def test_expired_claim_can_be_reclaimed_but_never_auto_releases(
    db_backend, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    _seed_agent(enabled_schedules=0)
    lease = freeze.create_freeze(AGENT, created_by="operator")
    first = freeze.claim_freeze(
        AGENT, lease.lease_id, claimed_by="cutover-a", claim_seconds=60
    )
    expiry = datetime.fromisoformat(first.claim_expires_at.replace("Z", "+00:00"))
    monkeypatch.setattr(freeze, "_now", lambda: expiry + timedelta(seconds=1))

    still_active = freeze.get_active_freeze(AGENT)
    assert still_active is not None and still_active.active
    second = freeze.claim_freeze(
        AGENT, lease.lease_id, claimed_by="cutover-b", claim_seconds=60
    )
    assert second.claimed_by == "cutover-b"


def test_cutover_credential_is_agent_scoped_read_claim_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRINITY_CUTOVER_TOKEN", "scoped-secret")
    monkeypatch.setenv("TRINITY_CUTOVER_AGENT", AGENT)
    assert (
        freeze.authorize_cutover_credential(AGENT, "Bearer scoped-secret")
        == AGENT
    )
    with pytest.raises(freeze.AgentFreezeCredentialError) as wrong_agent:
        freeze.authorize_cutover_credential("different-agent", "Bearer scoped-secret")
    assert wrong_agent.value.status_code == 403
    with pytest.raises(freeze.AgentFreezeCredentialError) as wrong_token:
        freeze.authorize_cutover_credential(AGENT, "Bearer admin-or-agent-token")
    assert wrong_token.value.status_code == 401


def test_sqlite_upgrade_migration_fences_null_status_and_wire_attempt() -> None:
    """The upgrade trigger must be as strict as the fresh-schema trigger."""
    from db.migrations import _migrate_agent_freeze_leases

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE agent_schedules ("
        "id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, enabled INTEGER NOT NULL)"
    )
    cursor.execute(
        "CREATE TABLE schedule_executions ("
        "id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, status TEXT)"
    )
    _migrate_agent_freeze_leases(cursor, conn)
    cursor.execute(
        "INSERT INTO agent_freeze_leases "
        "(id, agent_name, active, created_at, created_by, schedule_revision) "
        "VALUES (?, ?, 1, ?, ?, ?)",
        ("lease", AGENT, NOW, "operator", "revision"),
    )
    conn.commit()

    with pytest.raises(sqlite3.IntegrityError, match="freeze lease blocks execution"):
        cursor.execute(
            "INSERT INTO schedule_executions (id, agent_name, status) VALUES (?, ?, NULL)",
            ("null-status", AGENT),
        )

    cursor.execute(
        "UPDATE agent_freeze_leases SET active = 0 WHERE id = 'lease'"
    )
    cursor.execute(
        "INSERT INTO schedule_executions (id, agent_name, status) VALUES (?, ?, ?)",
        ("running-before-freeze", AGENT, "running"),
    )
    cursor.execute("UPDATE agent_freeze_leases SET active = 1 WHERE id = 'lease'")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="freeze lease blocks execution"):
        cursor.execute(
            "UPDATE schedule_executions SET dispatch_attempt_count = "
            "dispatch_attempt_count + 1 WHERE id = ?",
            ("running-before-freeze",),
        )
    conn.close()


@pytest.mark.asyncio
async def test_pre_wire_authorization_failure_never_opens_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered_http = False

    @asynccontextmanager
    async def _slot(_agent_name: str):
        yield

    @asynccontextmanager
    async def _http(_agent_name: str, *, timeout: float):
        nonlocal entered_http
        entered_http = True
        yield None

    def _refuse(_execution_id: str, _agent_name: str) -> bool:
        raise sqlite3.IntegrityError("agent freeze lease blocks execution dispatch")

    monkeypatch.setattr(task_service, "acquire_agent_call_slot", _slot)
    monkeypatch.setattr(task_service, "agent_httpx_client", _http)
    monkeypatch.setattr(task_service.db, "authorize_execution_dispatch", _refuse)

    with pytest.raises(httpx.HTTPStatusError) as exc:
        await task_service.agent_post_with_retry(
            AGENT,
            "/api/task",
            {"execution_id": "execution", "message": "do not send"},
            max_retries=3,
        )
    assert exc.value.response.status_code == 423
    assert entered_http is False


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/task", "/api/chat"])
async def test_agent_client_post_cannot_bypass_row_owning_services(path: str) -> None:
    with pytest.raises(AgentRequestError, match="direct agent execution"):
        await AgentClient(AGENT).post(path, json={"message": "bypass"})
