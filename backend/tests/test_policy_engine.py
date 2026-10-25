from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.policies.engine import PolicyEngine
from app.policies.models import (
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyIds,
    PolicyRule,
    RiskCategory,
    ToolCall,
)
from app.tools.registry import ToolRegistry


def test_permitted_read_is_allowed(engine: PolicyEngine) -> None:
    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.decision == PolicyDecision.ALLOW
    assert result.policy_id == PolicyIds.READ_ALLOWED_FILE
    assert result.execution_permitted is True
    assert result.approval_required is False
    assert result.approval is None


def test_unknown_tool_is_denied(engine: PolicyEngine) -> None:
    result = engine.evaluate(ToolCall(tool_name="unknown_tool", arguments={}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.UNKNOWN_TOOL
    assert result.execution_permitted is False


def test_invalid_arguments_are_denied(engine: PolicyEngine) -> None:
    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.INVALID_TOOL_ARGUMENTS
    assert result.execution_permitted is False


def test_protected_file_is_denied(engine: PolicyEngine) -> None:
    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={"path": ".env"}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.READ_PROTECTED_SECRET
    assert result.risk_category == RiskCategory.SECRET


def test_protected_file_template_is_allowed(engine: PolicyEngine) -> None:
    result = engine.evaluate(
        ToolCall(tool_name="read_file", arguments={"path": ".env.example"})
    )

    assert result.decision == PolicyDecision.ALLOW
    assert result.policy_id == PolicyIds.READ_ALLOWED_FILE


def test_outside_workspace_is_denied(
    engine: PolicyEngine,
    tmp_path: Path,
) -> None:
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")

    result = engine.evaluate(
        ToolCall(tool_name="read_file", arguments={"path": "../outside.txt"})
    )

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.OUTSIDE_WORKSPACE_ACCESS
    assert result.risk_category == RiskCategory.WORKSPACE


def test_symlink_escape_is_denied(
    engine: PolicyEngine,
    workspace: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    link = workspace / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted on this machine")

    result = engine.evaluate(
        ToolCall(tool_name="read_file", arguments={"path": "link.txt"})
    )

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.OUTSIDE_WORKSPACE_ACCESS


def test_delete_requires_approval(engine: PolicyEngine) -> None:
    result = engine.evaluate(
        ToolCall(
            tool_name="delete_simulated_record",
            arguments={"record_id": "rec-1"},
        )
    )

    assert result.decision == PolicyDecision.REQUIRE_APPROVAL
    assert result.policy_id == PolicyIds.DELETE_SIMULATED_RECORD
    assert result.execution_permitted is False
    assert result.approval_required is True
    assert result.approval is not None
    assert result.approval.policy_id == PolicyIds.DELETE_SIMULATED_RECORD


def test_write_inside_workspace_requires_approval(engine: PolicyEngine) -> None:
    result = engine.evaluate(
        ToolCall(
            tool_name="write_file",
            arguments={"path": "app.py", "content": "print('updated')\n"},
        )
    )

    assert result.decision == PolicyDecision.REQUIRE_APPROVAL
    assert result.policy_id == PolicyIds.WRITE_REQUIRES_APPROVAL
    assert result.approval_required is True


def test_write_outside_workspace_is_denied(engine: PolicyEngine) -> None:
    result = engine.evaluate(
        ToolCall(
            tool_name="write_file",
            arguments={"path": "../outside.txt", "content": "outside\n"},
        )
    )

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.OUTSIDE_WORKSPACE_ACCESS


def test_write_protected_file_is_denied(engine: PolicyEngine) -> None:
    result = engine.evaluate(
        ToolCall(
            tool_name="write_file",
            arguments={"path": ".env", "content": "SECRET=overwritten\n"},
        )
    )

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.READ_PROTECTED_SECRET


def test_explicit_deny_overrides_general_allow(
    registry: ToolRegistry,
    workspace: Path,
) -> None:
    allow = PolicyRule(
        id="zz-allow-read",
        name="Allow Read",
        description="General read allow.",
        decision=PolicyDecision.ALLOW,
        risk_category=RiskCategory.READ,
        tool_names=("read_file",),
    )
    deny = PolicyRule(
        id="aa-deny-read",
        name="Deny Read",
        description="Explicit read deny.",
        decision=PolicyDecision.DENY,
        risk_category=RiskCategory.READ,
        tool_names=("read_file",),
    )
    engine = PolicyEngine(registry, workspace, rules=(allow, deny))

    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == "aa-deny-read"


def test_no_matching_rule_defaults_to_deny(
    registry: ToolRegistry,
    workspace: Path,
) -> None:
    engine = PolicyEngine(registry, workspace, rules=())

    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.DEFAULT_DENY


def test_policy_rule_exception_fails_closed(
    registry: ToolRegistry,
    workspace: Path,
) -> None:
    def explode(context: object) -> str | None:
        raise RuntimeError("unexpected policy failure")

    rule = PolicyRule(
        id="exploding-rule",
        name="Exploding Rule",
        description="Always fails.",
        decision=PolicyDecision.ALLOW,
        risk_category=RiskCategory.READ,
        tool_names=("read_file",),
        check=explode,
    )
    engine = PolicyEngine(registry, workspace, rules=(rule,))

    result = engine.evaluate(ToolCall(tool_name="read_file", arguments={"path": "app.py"}))

    assert result.decision == PolicyDecision.DENY
    assert result.policy_id == PolicyIds.EVALUATION_ERROR


@pytest.mark.parametrize(
    "payload",
    [
        {"tool_name": "read file", "arguments": {}},
        {"tool_name": "read_file", "arguments": {"path": object()}},
        {"tool_name": "read_file", "arguments": {"value": float("nan")}},
        {"tool_name": "read_file", "arguments": {"extra": {1: "value"}}},
        {"tool_name": "read_file", "arguments": {"path": "x" * 70000}},
    ],
)
def test_malformed_tool_calls_are_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ToolCall.model_validate(payload)


def test_result_rejects_inconsistent_decision(workspace: Path) -> None:
    with pytest.raises(ValidationError):
        PolicyEvaluationResult(
            tool_name="read_file",
            arguments={},
            workspace_root=workspace,
            decision=PolicyDecision.DENY,
            policy_id="test",
            policy_name="Test",
            reason="test",
            risk_category=RiskCategory.READ,
            execution_permitted=True,
            approval_required=False,
            approval=None,
        )


def test_workspace_root_must_exist(registry: ToolRegistry, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        PolicyEngine(registry, tmp_path / "missing")
