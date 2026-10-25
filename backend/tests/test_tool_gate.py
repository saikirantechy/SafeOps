from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.policies.engine import PolicyEngine
from app.policies.models import (
    ApprovalGrant,
    PolicyIds,
    ToolCall,
    ToolExecutionStatus,
    arguments_fingerprint,
)
from app.tools.base import ToolGate
from app.tools.registry import ToolRegistry


def test_allowed_tool_executes(
    gate: ToolGate,
    read_tool: object,
) -> None:
    result = gate.execute(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.status == ToolExecutionStatus.EXECUTED
    assert result.result is not None
    assert result.result.ok is True
    assert result.result.output == "read:app.py"
    assert result.approved_by is None
    assert result.duration_ms is not None
    assert result.duration_ms >= 0
    assert read_tool.calls == 1


def test_denied_tool_never_executes(
    gate: ToolGate,
    read_tool: object,
) -> None:
    result = gate.execute(ToolCall(tool_name="read_file", arguments={"path": ".env"}))

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.READ_PROTECTED_SECRET
    assert result.result is None
    assert read_tool.calls == 0


def test_outside_workspace_never_executes(
    gate: ToolGate,
    read_tool: object,
    tmp_path: Path,
) -> None:
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")

    result = gate.execute(
        ToolCall(tool_name="read_file", arguments={"path": "../outside.txt"})
    )

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.OUTSIDE_WORKSPACE_ACCESS
    assert read_tool.calls == 0


def test_approval_required_tool_does_not_execute_without_grant(
    gate: ToolGate,
    delete_tool: object,
) -> None:
    result = gate.execute(
        ToolCall(
            tool_name="delete_simulated_record",
            arguments={"record_id": "rec-1"},
        )
    )

    assert result.status == ToolExecutionStatus.PENDING_APPROVAL
    assert result.evaluation.approval_required is True
    assert result.result is None
    assert delete_tool.calls == 0


def test_approved_tool_executes_once(
    gate: ToolGate,
    delete_tool: object,
) -> None:
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-1"},
    )
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-1",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.EXECUTED
    assert result.approved_by == "reviewer"
    assert result.result is not None
    assert result.result.output == "deleted:rec-1"
    assert delete_tool.calls == 1


def test_approval_cannot_be_reused(
    gate: ToolGate,
    delete_tool: object,
) -> None:
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-1"},
    )
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-2",
        approved_by="reviewer",
        ttl_seconds=60,
    )
    first = gate.execute(call, approval=grant)
    second = gate.execute(call, approval=grant)

    assert first.status == ToolExecutionStatus.EXECUTED
    assert second.status == ToolExecutionStatus.DENIED
    assert second.evaluation.policy_id == PolicyIds.APPROVAL_REUSED
    assert delete_tool.calls == 1


def test_expired_approval_is_denied(
    gate: ToolGate,
    delete_tool: object,
) -> None:
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-1"},
    )
    now = datetime.now(timezone.utc)
    grant = ApprovalGrant(
        approval_id="approval-expired",
        tool_name=call.tool_name,
        arguments_hash=arguments_fingerprint(call.tool_name, call.arguments),
        approved_by="reviewer",
        expires_at=now - timedelta(minutes=1),
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.APPROVAL_EXPIRED
    assert delete_tool.calls == 0


def test_approval_for_different_arguments_is_denied(
    gate: ToolGate,
    delete_tool: object,
) -> None:
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-1"},
    )
    other_call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-2"},
    )
    grant = ApprovalGrant.issue(
        other_call,
        approval_id="approval-mismatch",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.APPROVAL_MISMATCH
    assert delete_tool.calls == 0


def test_approval_cannot_override_explicit_deny(
    gate: ToolGate,
    git_push_tool: object,
) -> None:
    call = ToolCall(tool_name="git_push", arguments={})
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-denied-action",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.UNAPPROVED_GIT_PUSH
    assert git_push_tool.calls == 0


def test_approval_cannot_write_outside_workspace(
    gate: ToolGate,
    write_tool: object,
) -> None:
    call = ToolCall(
        tool_name="write_file",
        arguments={"path": "../outside.txt", "content": "outside\n"},
    )
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-outside-write",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.OUTSIDE_WORKSPACE_ACCESS
    assert write_tool.calls == 0


def test_approved_write_executes(
    gate: ToolGate,
    write_tool: object,
) -> None:
    call = ToolCall(
        tool_name="write_file",
        arguments={"path": "app.py", "content": "print('updated')\n"},
    )
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-write",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.EXECUTED
    assert result.approved_by == "reviewer"
    assert result.result is not None
    assert result.result.output == "wrote:app.py"
    assert write_tool.calls == 1


def test_approved_tool_failure_preserves_approval_context(
    workspace: Path,
    failing_delete_tool: object,
) -> None:
    registry = ToolRegistry((failing_delete_tool,))
    engine = PolicyEngine(registry, workspace)
    gate = ToolGate(engine, registry, workspace)
    call = ToolCall(
        tool_name="delete_simulated_record",
        arguments={"record_id": "rec-1"},
    )
    grant = ApprovalGrant.issue(
        call,
        approval_id="approval-failure",
        approved_by="reviewer",
        ttl_seconds=60,
    )

    result = gate.execute(call, approval=grant)

    assert result.status == ToolExecutionStatus.FAILED
    assert result.approved_by == "reviewer"
    assert result.result is not None
    assert result.result.error_category == "simulated_failure"
    assert failing_delete_tool.calls == 1


def test_unknown_tool_never_executes(
    gate: ToolGate,
    read_tool: object,
) -> None:
    result = gate.execute(
        ToolCall(tool_name="not_registered", arguments={})
    )

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.UNKNOWN_TOOL
    assert read_tool.calls == 0


def test_invalid_arguments_never_execute(
    gate: ToolGate,
    read_tool: object,
) -> None:
    result = gate.execute(ToolCall(tool_name="read_file", arguments={}))

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.INVALID_TOOL_ARGUMENTS
    assert read_tool.calls == 0


def test_malformed_request_never_executes(
    gate: ToolGate,
    read_tool: object,
) -> None:
    result = gate.execute({"tool_name": "read file", "arguments": {}})

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.MALFORMED_REQUEST
    assert result.evaluation.tool_name == "<invalid>"
    assert read_tool.calls == 0


def test_tool_failure_is_reported_without_crashing(
    workspace: Path,
    failing_read_tool: object,
) -> None:
    registry = ToolRegistry((failing_read_tool,))
    engine = PolicyEngine(registry, workspace)
    gate = ToolGate(engine, registry, workspace)

    result = gate.execute(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.status == ToolExecutionStatus.FAILED
    assert result.result is not None
    assert result.result.ok is False
    assert result.result.error == "simulated read failure"
    assert result.result.error_category == "simulated_failure"
    assert result.duration_ms is not None
    assert failing_read_tool.calls == 1


def test_unexpected_tool_error_is_sanitized(
    workspace: Path,
    exploding_read_tool: object,
) -> None:
    registry = ToolRegistry((exploding_read_tool,))
    engine = PolicyEngine(registry, workspace)
    gate = ToolGate(engine, registry, workspace)

    result = gate.execute(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.status == ToolExecutionStatus.FAILED
    assert result.result is not None
    assert result.result.error == "Tool execution failed."
    assert result.result.error_category == "unexpected_tool_error"
    assert "internal secret detail" not in result.result.error
    assert exploding_read_tool.calls == 1


def test_arguments_are_revalidated_before_execution(
    workspace: Path,
    flaky_read_tool: object,
) -> None:
    registry = ToolRegistry((flaky_read_tool,))
    engine = PolicyEngine(registry, workspace)
    gate = ToolGate(engine, registry, workspace)

    result = gate.execute(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.status == ToolExecutionStatus.DENIED
    assert result.evaluation.policy_id == PolicyIds.INVALID_TOOL_ARGUMENTS
    assert flaky_read_tool.validation_calls == 2
    assert flaky_read_tool.calls == 0
