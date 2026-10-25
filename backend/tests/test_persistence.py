from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.config import Settings
from app.database import repository
from app.database.db import connect, initialize_database
from app.policies.models import (
    ApprovalRequirement,
    PolicyDecision,
    PolicyEvaluationResult,
    RiskCategory,
    ToolCall,
    ToolExecutionStatus,
    ToolGateResult,
    ToolResult,
)
from app.sanitize import MAX_TRACE_TEXT, REDACTED, sanitize_payload


@pytest.fixture
def db_settings(tmp_path: Path, workspace: Path) -> Settings:
    return Settings(
        database_path=str(tmp_path / "safeops-persistence.db"),
        environment="test",
        workspace_root=str(workspace),
        seed_demo_records=False,
    )


@pytest.fixture
def connection(db_settings: Settings):
    initialize_database(db_settings)
    connection = connect(db_settings)
    try:
        yield connection
    finally:
        connection.close()


def _evaluation(
    call: ToolCall,
    *,
    workspace: Path,
    decision: PolicyDecision,
    policy_id: str,
    risk_category: RiskCategory,
) -> PolicyEvaluationResult:
    approval_required = decision == PolicyDecision.REQUIRE_APPROVAL
    return PolicyEvaluationResult(
        tool_name=call.tool_name,
        arguments=call.arguments,
        workspace_root=workspace,
        decision=decision,
        policy_id=policy_id,
        policy_name=policy_id.replace("-", " ").title(),
        reason="test policy reason",
        risk_category=risk_category,
        execution_permitted=decision == PolicyDecision.ALLOW,
        approval_required=approval_required,
        approval=(
            ApprovalRequirement(
                required=True,
                reason="test policy reason",
                risk_category=risk_category,
                policy_id=policy_id,
            )
            if approval_required
            else None
        ),
    )


def _record_event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    call: ToolCall,
    workspace: Path,
    decision: PolicyDecision = PolicyDecision.ALLOW,
    status: ToolExecutionStatus = ToolExecutionStatus.EXECUTED,
    policy_id: str = "read-allowed-file",
    risk_category: RiskCategory = RiskCategory.READ,
    result: ToolResult | None = None,
    duration_ms: int = 5,
) -> str:
    evaluation = _evaluation(
        call,
        workspace=workspace,
        decision=decision,
        policy_id=policy_id,
        risk_category=risk_category,
    )
    if result is None and status in {
        ToolExecutionStatus.EXECUTED,
        ToolExecutionStatus.FAILED,
    }:
        result = ToolResult(ok=status == ToolExecutionStatus.EXECUTED, output={"ok": True})
    outcome = ToolGateResult(
        status=status,
        evaluation=evaluation,
        result=result,
        duration_ms=duration_ms if result is not None else None,
    )
    return repository.record_tool_event(
        connection,
        run_id=run_id,
        call=call,
        evaluation=outcome.evaluation,
        outcome=outcome,
    )


def test_create_and_list_runs(connection: sqlite3.Connection, workspace: Path) -> None:
    call = ToolCall(tool_name="read_file", arguments={"path": "app.py"})
    run = repository.create_run(
        connection,
        task="  Inspect   the   demo  ",
        plan=[call],
    )

    assert run["task"] == "Inspect the demo"
    assert run["status"] == "pending"
    assert run["plan"] == [{"tool_name": "read_file", "arguments": {"path": "app.py"}}]
    assert run["event_count"] == 0

    runs = repository.list_runs(connection)
    assert [item["id"] for item in runs] == [run["id"]]
    assert repository.get_run(connection, run["id"])["id"] == run["id"]


def test_record_event_sanitizes_and_advances_run(
    connection: sqlite3.Connection,
    workspace: Path,
) -> None:
    run = repository.create_run(connection, task="Trace sanitization")
    call = ToolCall(
        tool_name="read_file",
        arguments={"path": "app.py", "api_token": "super-secret"},
    )
    long_content = "x" * (MAX_TRACE_TEXT + 500)

    _record_event(
        connection,
        run_id=run["id"],
        call=call,
        workspace=workspace,
        result=ToolResult(
            ok=True,
            output={"path": "app.py", "content": long_content, "access_token": "abc"},
        ),
    )
    _record_event(connection, run_id=run["id"], call=call, workspace=workspace)

    trace = repository.get_trace(connection, run["id"])
    assert trace["run"]["status"] == "running"
    assert trace["run"]["started_at"] is not None
    assert trace["run"]["event_count"] == 2
    assert [event["seq"] for event in trace["events"]] == [1, 2]

    first = trace["events"][0]
    assert first["arguments"]["api_token"] == REDACTED
    assert len(first["result"]["output"]["content"]) > MAX_TRACE_TEXT
    assert "truncated" in first["result"]["output"]["content"]
    assert first["result"]["output"]["access_token"] == REDACTED
    assert first["duration_ms"] == 5


def test_pending_approval_is_deduplicated(
    connection: sqlite3.Connection,
    workspace: Path,
) -> None:
    run = repository.create_run(connection, task="Delete a record")
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-001"},
    )
    event_id = _record_event(
        connection,
        run_id=run["id"],
        call=call,
        workspace=workspace,
        decision=PolicyDecision.REQUIRE_APPROVAL,
        status=ToolExecutionStatus.PENDING_APPROVAL,
        policy_id="delete-simulated-record",
        risk_category=RiskCategory.DESTRUCTIVE,
        result=None,
    )
    first = repository.record_approval_request(
        connection,
        run_id=run["id"],
        event_id=event_id,
        call=call,
        reason="Deletion requires approval.",
    )
    second = repository.record_approval_request(
        connection,
        run_id=run["id"],
        event_id=event_id,
        call=call,
        reason="Deletion requires approval.",
    )

    assert first["id"] == second["id"]
    assert first["status"] == "pending"
    assert first["arguments"] == {"record_id": "rec-001"}
    assert repository.list_approvals(connection, status="pending") == [first]
    assert repository.list_approvals(connection, status="approved") == []


def test_approval_decisions_are_single_use(
    connection: sqlite3.Connection,
    workspace: Path,
) -> None:
    run = repository.create_run(connection, task="Approve a write")
    call = ToolCall(
        tool_name="write_file",
        arguments={"path": "notes.txt", "content": "hello"},
    )
    event_id = _record_event(
        connection,
        run_id=run["id"],
        call=call,
        workspace=workspace,
        decision=PolicyDecision.REQUIRE_APPROVAL,
        status=ToolExecutionStatus.PENDING_APPROVAL,
        policy_id="write-requires-approval",
        risk_category=RiskCategory.WRITE,
        result=None,
    )
    approval = repository.record_approval_request(
        connection,
        run_id=run["id"],
        event_id=event_id,
        call=call,
        reason="Write requires approval.",
    )

    approved = repository.decide_approval(
        connection,
        approval["id"],
        approved=True,
        decided_by="reviewer@example.test",
        note="Looks safe.",
    )
    assert approved["status"] == "approved"
    assert approved["decided_by"] == "reviewer@example.test"

    grant = repository.build_approval_grant(approved)
    assert grant.matches(call)
    assert not grant.is_expired()

    with pytest.raises(repository.ConflictError):
        repository.decide_approval(
            connection,
            approval["id"],
            approved=False,
            decided_by="reviewer@example.test",
        )

    used = repository.mark_approval_used(connection, approval["id"])
    assert used["status"] == "used"
    with pytest.raises(repository.ConflictError):
        repository.build_approval_grant(used)


def test_metrics_are_derived_from_events(
    connection: sqlite3.Connection,
    workspace: Path,
) -> None:
    empty = repository.compute_metrics(connection)
    assert empty["total_runs"] == 0
    assert empty["total_events"] == 0
    assert empty["success_rate"] is None
    assert empty["average_duration_ms"] is None

    run = repository.create_run(connection, task="Mixed outcomes")
    allowed = ToolCall(tool_name="read_file", arguments={"path": "app.py"})
    denied = ToolCall(tool_name="read_file", arguments={"path": ".env"})
    pending = ToolCall(
        tool_name="write_file",
        arguments={"path": "notes.txt", "content": "hello"},
    )

    _record_event(
        connection,
        run_id=run["id"],
        call=allowed,
        workspace=workspace,
        duration_ms=10,
    )
    _record_event(
        connection,
        run_id=run["id"],
        call=denied,
        workspace=workspace,
        decision=PolicyDecision.DENY,
        status=ToolExecutionStatus.DENIED,
        policy_id="read-protected-secret",
        risk_category=RiskCategory.SECRET,
        result=None,
        duration_ms=0,
    )
    pending_event = _record_event(
        connection,
        run_id=run["id"],
        call=pending,
        workspace=workspace,
        decision=PolicyDecision.REQUIRE_APPROVAL,
        status=ToolExecutionStatus.PENDING_APPROVAL,
        policy_id="write-requires-approval",
        risk_category=RiskCategory.WRITE,
        result=None,
    )
    approval = repository.record_approval_request(
        connection,
        run_id=run["id"],
        event_id=pending_event,
        call=pending,
        reason="Write requires approval.",
    )
    repository.decide_approval(
        connection,
        approval["id"],
        approved=False,
        decided_by="reviewer@example.test",
    )
    _record_event(
        connection,
        run_id=run["id"],
        call=allowed,
        workspace=workspace,
        status=ToolExecutionStatus.FAILED,
        result=ToolResult(ok=False, error="boom", error_category="test_failure"),
        duration_ms=30,
    )

    metrics = repository.compute_metrics(connection)
    assert metrics["total_runs"] == 1
    assert metrics["total_events"] == 4
    assert metrics["runs_by_status"]["running"] == 1
    assert metrics["decisions"]["ALLOW"] == 2
    assert metrics["decisions"]["DENY"] == 1
    assert metrics["decisions"]["REQUIRE_APPROVAL"] == 1
    assert metrics["executions"]["executed"] == 1
    assert metrics["executions"]["failed"] == 1
    assert metrics["executions"]["denied"] == 1
    assert metrics["executions"]["pending_approval"] == 1
    assert metrics["approvals"]["rejected"] == 1
    assert metrics["blocked_events"] == 1
    assert metrics["success_rate"] == 0.5
    assert metrics["average_duration_ms"] == 20.0
    assert metrics["last_event_at"] is not None


def test_update_run_status_sets_terminal_fields(
    connection: sqlite3.Connection,
) -> None:
    run = repository.create_run(connection, task="Finish a run", status="running")
    finished = repository.update_run_status(
        connection,
        run["id"],
        "completed",
    )

    assert finished["status"] == "completed"
    assert finished["finished_at"] is not None
    assert finished["duration_ms"] is not None


def test_sanitize_payload_redacts_keys_and_truncates() -> None:
    payload = {
        "token": "abc",
        "nested": {"password": "hunter2", "items": ["ok", {"secret": "shh"}]},
        "content": "y" * (MAX_TRACE_TEXT + 10),
        "bytes": b"abc",
        "count": 3,
    }

    sanitized = sanitize_payload(payload)

    assert sanitized["token"] == REDACTED
    assert sanitized["nested"]["password"] == REDACTED
    assert sanitized["nested"]["items"][1]["secret"] == REDACTED
    assert sanitized["bytes"] == "<3 bytes>"
    assert sanitized["count"] == 3
    assert "truncated" in sanitized["content"]
