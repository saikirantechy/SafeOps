from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from app.policies.models import (
    ApprovalGrant,
    PolicyEvaluationResult,
    ToolCall,
    ToolExecutionStatus,
    ToolGateResult,
    arguments_fingerprint,
)
from app.sanitize import sanitize_payload

RUN_STATUSES = frozenset({"pending", "running", "completed", "failed", "cancelled"})
TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
APPROVAL_STATUSES = frozenset({"pending", "approved", "rejected", "used"})
FAULTS = frozenset({"none", "tool_failure", "timeout"})
MAX_TASK_LENGTH = 2000
MAX_DECIDED_BY_LENGTH = 100
MAX_DECISION_NOTE_LENGTH = 500
DEFAULT_GRANT_TTL_SECONDS = 300
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PersistenceError(RuntimeError):
    pass


class NotFoundError(PersistenceError):
    pass


class ConflictError(PersistenceError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _encode(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _decode(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _run_from_row(row: sqlite3.Row) -> dict[str, Any]:
    payload = dict(row)
    payload["plan"] = _decode(payload.pop("plan_json", None), [])
    payload["event_count"] = int(payload.get("event_count") or 0)
    return payload


def _event_from_row(row: sqlite3.Row) -> dict[str, Any]:
    payload = dict(row)
    payload["arguments"] = _decode(payload.pop("arguments_json", None), {})
    payload["result"] = _decode(payload.pop("result_json", None), None)
    return payload


def _approval_from_row(row: sqlite3.Row) -> dict[str, Any]:
    payload = dict(row)
    payload["arguments"] = _decode(payload.pop("arguments_json", None), {})
    return payload


def _normalize_plan(plan: Sequence[Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for step in plan:
        if isinstance(step, ToolCall):
            raw: dict[str, Any] = {
                "tool_name": step.tool_name,
                "arguments": step.arguments,
            }
        elif isinstance(step, Mapping):
            tool_name = step.get("tool_name")
            arguments = step.get("arguments", {})
            if not isinstance(tool_name, str) or not tool_name:
                raise ValueError("plan steps require a tool_name")
            if not isinstance(arguments, Mapping):
                raise ValueError("plan step arguments must be an object")
            raw = {"tool_name": tool_name, "arguments": dict(arguments)}
        else:
            raise ValueError("plan steps must be tool calls")
        steps.append(sanitize_payload(raw))
    return steps


def create_run(
    connection: sqlite3.Connection,
    *,
    task: str,
    plan: Sequence[Any] = (),
    provider: str = "demo",
    provider_mode: str = "demo",
    fault: str = "none",
    status: str = "pending",
) -> dict[str, Any]:
    normalized_task = " ".join(str(task).split())
    if not normalized_task:
        raise ValueError("task must not be empty")
    if len(normalized_task) > MAX_TASK_LENGTH:
        raise ValueError(f"task must not exceed {MAX_TASK_LENGTH} characters")
    if status not in RUN_STATUSES:
        raise ValueError("invalid run status")
    if fault not in FAULTS:
        raise ValueError("invalid fault")

    run_id = _new_id("run")
    created_at = _now_iso()
    started_at = created_at if status == "running" else None
    connection.execute(
        """
        INSERT INTO runs (
            id, task, provider, provider_mode, status, error_category,
            plan_json, next_index, fault, created_at, started_at
        )
        VALUES (?, ?, ?, ?, ?, NULL, ?, 0, ?, ?, ?)
        """,
        (
            run_id,
            normalized_task,
            provider,
            provider_mode,
            status,
            _encode(_normalize_plan(plan)),
            fault,
            created_at,
            started_at,
        ),
    )
    connection.commit()
    return get_run(connection, run_id)


def get_run(connection: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT runs.*, (
            SELECT COUNT(*) FROM tool_events WHERE tool_events.run_id = runs.id
        ) AS event_count
        FROM runs
        WHERE runs.id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Run '{run_id}' was not found.")
    return _run_from_row(row)


def list_runs(
    connection: sqlite3.Connection,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 200))
    rows = connection.execute(
        """
        SELECT runs.*, (
            SELECT COUNT(*) FROM tool_events WHERE tool_events.run_id = runs.id
        ) AS event_count
        FROM runs
        ORDER BY runs.created_at DESC, runs.id DESC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()
    return [_run_from_row(row) for row in rows]


def update_run_status(
    connection: sqlite3.Connection,
    run_id: str,
    status: str,
    *,
    error_category: str | None = None,
) -> dict[str, Any]:
    if status not in RUN_STATUSES:
        raise ValueError("invalid run status")
    current = get_run(connection, run_id)
    now = _now()
    started_at = current.get("started_at")
    finished_at = current.get("finished_at")
    duration_ms = current.get("duration_ms")

    if status == "running" and not started_at:
        started_at = now.isoformat()
    if status in TERMINAL_RUN_STATUSES and not finished_at:
        finished_at = now.isoformat()
        started = _parse_timestamp(started_at)
        if started is not None:
            duration_ms = max(0, int((now - started).total_seconds() * 1000))

    connection.execute(
        """
        UPDATE runs
        SET status = ?, error_category = ?, started_at = ?,
            finished_at = ?, duration_ms = ?
        WHERE id = ?
        """,
        (status, error_category, started_at, finished_at, duration_ms, run_id),
    )
    connection.commit()
    return get_run(connection, run_id)


def record_tool_event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    call: ToolCall,
    evaluation: PolicyEvaluationResult,
    outcome: ToolGateResult,
) -> str:
    run = get_run(connection, run_id)
    row = connection.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM tool_events WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    seq = int(row["next_seq"]) if row is not None else 1
    event_id = _new_id("evt")
    created_at = _now_iso()

    result_payload = (
        sanitize_payload(outcome.result.model_dump(mode="json"))
        if outcome.result is not None
        else None
    )
    error_category = outcome.result.error_category if outcome.result else None

    connection.execute(
        """
        INSERT INTO tool_events (
            id, run_id, seq, created_at, tool_name, arguments_json,
            policy_id, policy_name, policy_decision, execution_status,
            error_category, retry_count, duration_ms, result_json, reason
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """,
        (
            event_id,
            run_id,
            seq,
            created_at,
            call.tool_name,
            _encode(sanitize_payload(call.arguments)),
            evaluation.policy_id,
            evaluation.policy_name,
            evaluation.decision.value,
            outcome.status.value,
            error_category,
            outcome.duration_ms,
            _encode(result_payload) if result_payload is not None else None,
            evaluation.reason,
        ),
    )
    if run["status"] == "pending":
        connection.execute(
            """
            UPDATE runs SET status = 'running', started_at = COALESCE(started_at, ?)
            WHERE id = ?
            """,
            (created_at, run_id),
        )
    connection.commit()
    return event_id


def list_tool_events(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    limit: int = 200,
) -> list[dict[str, Any]]:
    get_run(connection, run_id)
    safe_limit = max(1, min(int(limit), 500))
    rows = connection.execute(
        """
        SELECT * FROM tool_events
        WHERE run_id = ?
        ORDER BY seq ASC
        LIMIT ?
        """,
        (run_id, safe_limit),
    ).fetchall()
    return [_event_from_row(row) for row in rows]


def get_trace(connection: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    return {
        "run": get_run(connection, run_id),
        "events": list_tool_events(connection, run_id),
    }


def find_pending_approval(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    tool_name: str,
    arguments_hash: str,
) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT * FROM approvals
        WHERE run_id = ? AND tool_name = ? AND arguments_hash = ? AND status = 'pending'
        ORDER BY requested_at ASC
        LIMIT 1
        """,
        (run_id, tool_name, arguments_hash),
    ).fetchone()
    return _approval_from_row(row) if row is not None else None


def record_approval_request(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    event_id: str,
    call: ToolCall,
    reason: str,
) -> dict[str, Any]:
    get_run(connection, run_id)
    event = connection.execute(
        "SELECT id FROM tool_events WHERE id = ? AND run_id = ?",
        (event_id, run_id),
    ).fetchone()
    if event is None:
        raise NotFoundError(f"Tool event '{event_id}' was not found for this run.")

    fingerprint = arguments_fingerprint(call.tool_name, call.arguments)
    existing = find_pending_approval(
        connection,
        run_id=run_id,
        tool_name=call.tool_name,
        arguments_hash=fingerprint,
    )
    if existing is not None:
        return existing

    approval_id = _new_id("appr")
    connection.execute(
        """
        INSERT INTO approvals (
            id, run_id, event_id, tool_name, arguments_json, arguments_hash,
            reason, status, requested_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            approval_id,
            run_id,
            event_id,
            call.tool_name,
            _encode(sanitize_payload(call.arguments)),
            fingerprint,
            reason,
            _now_iso(),
        ),
    )
    connection.commit()
    return get_approval(connection, approval_id)


def get_approval(connection: sqlite3.Connection, approval_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM approvals WHERE id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Approval '{approval_id}' was not found.")
    return _approval_from_row(row)


def list_approvals(
    connection: sqlite3.Connection,
    *,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if status is not None and status not in APPROVAL_STATUSES:
        raise ValueError("invalid approval status")
    safe_limit = max(1, min(int(limit), 200))
    if status is None:
        rows = connection.execute(
            """
            SELECT * FROM approvals
            ORDER BY requested_at DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT * FROM approvals
            WHERE status = ?
            ORDER BY requested_at DESC, id DESC
            LIMIT ?
            """,
            (status, safe_limit),
        ).fetchall()
    return [_approval_from_row(row) for row in rows]


def decide_approval(
    connection: sqlite3.Connection,
    approval_id: str,
    *,
    approved: bool,
    decided_by: str,
    note: str | None = None,
) -> dict[str, Any]:
    reviewer = " ".join(str(decided_by).split())
    if not reviewer:
        raise ValueError("decided_by must not be empty")
    if len(reviewer) > MAX_DECIDED_BY_LENGTH:
        raise ValueError(
            f"decided_by must not exceed {MAX_DECIDED_BY_LENGTH} characters"
        )
    normalized_note = " ".join(note.split()) if note else None
    if normalized_note and len(normalized_note) > MAX_DECISION_NOTE_LENGTH:
        raise ValueError(
            f"note must not exceed {MAX_DECISION_NOTE_LENGTH} characters"
        )

    current = get_approval(connection, approval_id)
    if current["status"] != "pending":
        raise ConflictError(
            f"Approval '{approval_id}' is already {current['status']}."
        )

    new_status = "approved" if approved else "rejected"
    cursor = connection.execute(
        """
        UPDATE approvals
        SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?
        WHERE id = ? AND status = 'pending'
        """,
        (new_status, _now_iso(), reviewer, normalized_note, approval_id),
    )
    if cursor.rowcount != 1:
        connection.rollback()
        raise ConflictError(f"Approval '{approval_id}' is no longer pending.")
    connection.commit()
    return get_approval(connection, approval_id)


def mark_approval_used(
    connection: sqlite3.Connection,
    approval_id: str,
) -> dict[str, Any]:
    current = get_approval(connection, approval_id)
    if current["status"] == "used":
        return current
    if current["status"] != "approved":
        raise ConflictError(
            f"Approval '{approval_id}' cannot be used while {current['status']}."
        )
    connection.execute(
        "UPDATE approvals SET status = 'used' WHERE id = ? AND status = 'approved'",
        (approval_id,),
    )
    connection.commit()
    return get_approval(connection, approval_id)


def build_approval_grant(
    approval: Mapping[str, Any],
    *,
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
) -> ApprovalGrant:
    if approval.get("status") != "approved":
        raise ConflictError("Only approved requests can be executed.")
    fingerprint = approval.get("arguments_hash")
    if not isinstance(fingerprint, str) or not _HASH_PATTERN.fullmatch(fingerprint):
        raise PersistenceError(
            "Approval is missing a valid argument binding; request a new approval."
        )
    decided_at = _parse_timestamp(approval.get("decided_at"))
    if decided_at is None:
        raise PersistenceError("Approval has no decision time; request a new approval.")
    return ApprovalGrant(
        approval_id=str(approval["id"]),
        tool_name=str(approval["tool_name"]),
        arguments_hash=fingerprint,
        approved_by=str(approval.get("decided_by") or "unknown"),
        expires_at=decided_at + timedelta(seconds=ttl_seconds),
    )


def _group_counts(
    connection: sqlite3.Connection,
    query: str,
    known: Sequence[str],
) -> dict[str, int]:
    counts = {key: 0 for key in known}
    for row in connection.execute(query).fetchall():
        key = row[0]
        if key is not None:
            counts[str(key)] = int(row[1])
    return counts


def compute_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    runs_by_status = _group_counts(
        connection,
        "SELECT status, COUNT(*) FROM runs GROUP BY status",
        tuple(sorted(RUN_STATUSES)),
    )
    decisions = _group_counts(
        connection,
        "SELECT policy_decision, COUNT(*) FROM tool_events GROUP BY policy_decision",
        ("ALLOW", "DENY", "REQUIRE_APPROVAL"),
    )
    executions = _group_counts(
        connection,
        "SELECT execution_status, COUNT(*) FROM tool_events GROUP BY execution_status",
        tuple(sorted(status.value for status in ToolExecutionStatus)),
    )
    approvals_by_status = _group_counts(
        connection,
        "SELECT status, COUNT(*) FROM approvals GROUP BY status",
        tuple(sorted(APPROVAL_STATUSES)),
    )

    totals_row = connection.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM runs) AS total_runs,
            (SELECT COUNT(*) FROM tool_events) AS total_events,
            (SELECT COALESCE(SUM(retry_count), 0) FROM tool_events) AS total_retries,
            (SELECT AVG(duration_ms) FROM tool_events WHERE duration_ms IS NOT NULL)
                AS avg_duration_ms,
            (SELECT MAX(created_at) FROM tool_events) AS last_event_at
        """
    ).fetchone()
    total_runs = int(totals_row["total_runs"] or 0)
    total_events = int(totals_row["total_events"] or 0)
    total_retries = int(totals_row["total_retries"] or 0)
    avg_duration = totals_row["avg_duration_ms"]
    last_event_at = totals_row["last_event_at"]

    attempted = executions.get(ToolExecutionStatus.EXECUTED.value, 0) + executions.get(
        ToolExecutionStatus.FAILED.value, 0
    )
    succeeded = executions.get(ToolExecutionStatus.EXECUTED.value, 0)
    success_rate = round(succeeded / attempted, 4) if attempted else None

    return {
        "total_runs": total_runs,
        "total_events": total_events,
        "runs_by_status": runs_by_status,
        "decisions": decisions,
        "executions": executions,
        "approvals": approvals_by_status,
        "blocked_events": executions.get(ToolExecutionStatus.DENIED.value, 0),
        "total_retries": total_retries,
        "average_duration_ms": (
            round(float(avg_duration), 2) if avg_duration is not None else None
        ),
        "success_rate": success_rate,
        "last_event_at": last_event_at,
    }
