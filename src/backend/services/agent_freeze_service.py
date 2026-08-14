"""Durable, agent-scoped execution freeze leases.

The database triggers installed with the lease table are the authority.  This
service provides the operator protocol around that fence; it is not itself the
dispatch boundary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import uuid

from sqlalchemy import and_, func, insert, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from db.engine import get_engine
from db.tables import (
    agent_freeze_leases,
    agent_ownership,
    agent_schedules,
    schedule_executions,
)
from utils.helpers import utc_now_iso


TERMINAL_STATUSES = ("success", "failed", "cancelled", "skipped")
MIN_CLAIM_SECONDS = 60
MAX_CLAIM_SECONDS = 3600


class AgentFreezeError(RuntimeError):
    """Base class for freeze protocol refusals."""


class AgentFreezeNotFound(AgentFreezeError):
    pass


class AgentFreezeConflict(AgentFreezeError):
    pass


class AgentFreezeNotDrained(AgentFreezeError):
    def __init__(self, nonterminal_count: int):
        super().__init__(
            f"agent still has {nonterminal_count} nonterminal execution(s)"
        )
        self.nonterminal_count = nonterminal_count


class AgentFreezeCredentialError(AgentFreezeError):
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AgentFreezeSnapshot:
    lease_id: str
    agent_name: str
    active: bool
    created_at: str
    created_by: str
    claimed_at: str | None
    claim_expires_at: str | None
    claimed_by: str | None
    released_at: str | None
    released_by: str | None
    schedule_revision: str
    schedule_digest: str
    nonterminal_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def authorize_cutover_credential(agent_name: str, authorization: str | None) -> str:
    """Validate the read/claim-only secret scoped to exactly one agent."""
    expected_token = os.getenv("TRINITY_CUTOVER_TOKEN", "")
    expected_agent = os.getenv("TRINITY_CUTOVER_AGENT", "")
    if not expected_token or not expected_agent:
        raise AgentFreezeCredentialError("CUTOVER credential is not configured", 503)
    if agent_name != expected_agent:
        raise AgentFreezeCredentialError("Forbidden", 403)
    prefix = "Bearer "
    supplied = (
        authorization[len(prefix) :]
        if isinstance(authorization, str) and authorization.startswith(prefix)
        else ""
    )
    if not hmac.compare_digest(supplied, expected_token):
        raise AgentFreezeCredentialError("Invalid CUTOVER credential", 401)
    return agent_name


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _schedule_digest(conn, agent_name: str) -> str:
    rows = conn.execute(
        select(
            agent_schedules.c.id,
            agent_schedules.c.name,
            agent_schedules.c.cron_expression,
            agent_schedules.c.message,
            agent_schedules.c.enabled,
            agent_schedules.c.timezone,
            agent_schedules.c.deleted_at,
            agent_schedules.c.updated_at,
        )
        .where(agent_schedules.c.agent_name == agent_name)
        .order_by(agent_schedules.c.id)
    ).mappings()
    canonical = json.dumps(
        [dict(row) for row in rows],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _nonterminal_count(conn, agent_name: str) -> int:
    value = conn.execute(
        select(func.count())
        .select_from(schedule_executions)
        .where(
            and_(
                schedule_executions.c.agent_name == agent_name,
                or_(
                    schedule_executions.c.status.is_(None),
                    schedule_executions.c.status.not_in(TERMINAL_STATUSES),
                ),
            )
        )
    ).scalar_one()
    return int(value)


def _lock_agent(conn, agent_name: str) -> None:
    """Serialize PostgreSQL producers with the matching trigger advisory lock."""
    if conn.dialect.name == "postgresql":
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:agent_name, 0))"),
            {"agent_name": agent_name},
        )


def _snapshot(conn, row) -> AgentFreezeSnapshot:
    data = dict(row)
    digest = str(data.get("schedule_revision") or "")
    if len(digest) != 64:
        raise AgentFreezeConflict("freeze lease has no immutable schedule revision")
    return AgentFreezeSnapshot(
        lease_id=data["id"],
        agent_name=data["agent_name"],
        active=bool(data["active"]),
        created_at=data["created_at"],
        created_by=data["created_by"],
        claimed_at=data["claimed_at"],
        claim_expires_at=data["claim_expires_at"],
        claimed_by=data["claimed_by"],
        released_at=data["released_at"],
        released_by=data["released_by"],
        schedule_revision=digest,
        schedule_digest=digest,
        nonterminal_count=_nonterminal_count(conn, data["agent_name"]),
    )


def get_active_freeze(agent_name: str) -> AgentFreezeSnapshot | None:
    with get_engine().connect() as conn:
        row = conn.execute(
            select(agent_freeze_leases).where(
                and_(
                    agent_freeze_leases.c.agent_name == agent_name,
                    agent_freeze_leases.c.active == 1,
                )
            )
        ).mappings().first()
        return _snapshot(conn, row) if row else None


def is_agent_frozen(agent_name: str) -> bool:
    with get_engine().connect() as conn:
        return conn.execute(
            select(agent_freeze_leases.c.id).where(
                and_(
                    agent_freeze_leases.c.agent_name == agent_name,
                    agent_freeze_leases.c.active == 1,
                )
            )
        ).first() is not None


def create_freeze(agent_name: str, *, created_by: str) -> AgentFreezeSnapshot:
    """Atomically create the lease and disable every live schedule."""
    lease_id = str(uuid.uuid4())
    now = utc_now_iso()
    try:
        with get_engine().begin() as conn:
            _lock_agent(conn, agent_name)
            live_agent = conn.execute(
                select(agent_ownership.c.agent_name).where(
                    and_(
                        agent_ownership.c.agent_name == agent_name,
                        agent_ownership.c.deleted_at.is_(None),
                    )
                )
            ).first()
            if live_agent is None:
                raise AgentFreezeNotFound(f"agent not found: {agent_name}")
            existing = conn.execute(
                select(agent_freeze_leases.c.id).where(
                    and_(
                        agent_freeze_leases.c.agent_name == agent_name,
                        agent_freeze_leases.c.active == 1,
                    )
                )
            ).first()
            if existing is not None:
                raise AgentFreezeConflict("agent already has an active freeze lease")
            conn.execute(
                update(agent_schedules)
                .where(
                    and_(
                        agent_schedules.c.agent_name == agent_name,
                        agent_schedules.c.deleted_at.is_(None),
                    )
                )
                .values(enabled=0, next_run_at=None, updated_at=now)
            )
            schedule_revision = _schedule_digest(conn, agent_name)
            conn.execute(
                insert(agent_freeze_leases).values(
                    id=lease_id,
                    agent_name=agent_name,
                    active=1,
                    created_at=now,
                    created_by=created_by,
                    schedule_revision=schedule_revision,
                )
            )
            row = conn.execute(
                select(agent_freeze_leases).where(
                    agent_freeze_leases.c.id == lease_id
                )
            ).mappings().one()
            return _snapshot(conn, row)
    except IntegrityError as exc:
        raise AgentFreezeConflict("agent already has an active freeze lease") from exc


def claim_freeze(
    agent_name: str,
    lease_id: str,
    *,
    claimed_by: str,
    claim_seconds: int = 900,
) -> AgentFreezeSnapshot:
    if not MIN_CLAIM_SECONDS <= claim_seconds <= MAX_CLAIM_SECONDS:
        raise AgentFreezeConflict(
            f"claim_seconds must be {MIN_CLAIM_SECONDS}..{MAX_CLAIM_SECONDS}"
        )
    now_dt = _now()
    expires = now_dt + timedelta(seconds=claim_seconds)
    now = now_dt.isoformat().replace("+00:00", "Z")
    expires_at = expires.isoformat().replace("+00:00", "Z")
    with get_engine().begin() as conn:
        _lock_agent(conn, agent_name)
        stmt = select(agent_freeze_leases).where(
            and_(
                agent_freeze_leases.c.id == lease_id,
                agent_freeze_leases.c.agent_name == agent_name,
                agent_freeze_leases.c.active == 1,
            )
        )
        if conn.dialect.name != "sqlite":
            stmt = stmt.with_for_update()
        row = conn.execute(stmt).mappings().first()
        if row is None:
            raise AgentFreezeNotFound("active freeze lease not found")
        count = _nonterminal_count(conn, agent_name)
        if count:
            raise AgentFreezeNotDrained(count)
        current_expiry = _parse_utc(row["claim_expires_at"])
        if current_expiry and current_expiry > now_dt and row["claimed_by"] != claimed_by:
            raise AgentFreezeConflict("freeze lease is claimed by another principal")
        conn.execute(
            update(agent_freeze_leases)
            .where(agent_freeze_leases.c.id == lease_id)
            .values(
                claimed_at=now,
                claim_expires_at=expires_at,
                claimed_by=claimed_by,
            )
        )
        claimed = conn.execute(
            select(agent_freeze_leases).where(agent_freeze_leases.c.id == lease_id)
        ).mappings().one()
        return _snapshot(conn, claimed)


def release_freeze(
    agent_name: str,
    lease_id: str,
    *,
    released_by: str,
    approve_release: bool,
) -> AgentFreezeSnapshot:
    if not approve_release:
        raise AgentFreezeConflict("explicit second operator release approval is required")
    now_dt = _now()
    now = now_dt.isoformat().replace("+00:00", "Z")
    with get_engine().begin() as conn:
        _lock_agent(conn, agent_name)
        stmt = select(agent_freeze_leases).where(
            and_(
                agent_freeze_leases.c.id == lease_id,
                agent_freeze_leases.c.agent_name == agent_name,
                agent_freeze_leases.c.active == 1,
            )
        )
        if conn.dialect.name != "sqlite":
            stmt = stmt.with_for_update()
        row = conn.execute(stmt).mappings().first()
        if row is None:
            raise AgentFreezeNotFound("active freeze lease not found")
        if released_by in {row["created_by"], row["claimed_by"]}:
            raise AgentFreezeConflict(
                "freeze release requires a distinct second operator"
            )
        claim_expiry = _parse_utc(row["claim_expires_at"])
        if claim_expiry and claim_expiry > now_dt:
            raise AgentFreezeConflict("claimed freeze lease cannot be released")
        conn.execute(
            update(agent_freeze_leases)
            .where(agent_freeze_leases.c.id == lease_id)
            .values(
                active=0,
                released_at=now,
                released_by=released_by,
            )
        )
        released = conn.execute(
            select(agent_freeze_leases).where(agent_freeze_leases.c.id == lease_id)
        ).mappings().one()
        return _snapshot(conn, released)
