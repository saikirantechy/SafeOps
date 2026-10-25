from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.policies.engine import PolicyEngine
from app.policies.models import RiskCategory, ToolPermission, ToolResult
from app.tools.base import ToolArgumentError, ToolExecutionError, ToolGate
from app.tools.registry import ToolRegistry


class ReadTool:
    name = "read_file"
    description = "Read a permitted file."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.READ,
    )
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if set(arguments) != {"path"}:
            raise ToolArgumentError("read_file expects exactly one path argument")
        value = arguments["path"]
        if not isinstance(value, str) or not value.strip():
            raise ToolArgumentError("path must be a non-empty string")

    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        return ToolResult(ok=True, output=f"read:{arguments['path']}")


class DeleteRecordTool:
    name = "delete_simulated_record"
    description = "Delete a simulated record."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.DESTRUCTIVE,
    )
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if set(arguments) != {"record_id"}:
            raise ToolArgumentError(
                "delete_simulated_record expects exactly one record_id argument"
            )
        value = arguments["record_id"]
        if not isinstance(value, str) or not value.strip():
            raise ToolArgumentError("record_id must be a non-empty string")

    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        return ToolResult(ok=True, output=f"deleted:{arguments['record_id']}")


class GitPushTool:
    name = "git_push"
    description = "Push a repository."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.GIT,
    )
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if arguments:
            raise ToolArgumentError("git_push does not accept arguments")

    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        return ToolResult(ok=True, output="pushed")


class FailingDeleteTool(DeleteRecordTool):
    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        raise ToolExecutionError("simulated delete failure", "simulated_failure")


class WriteTool:
    name = "write_file"
    description = "Write a file."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.WRITE,
    )
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if set(arguments) != {"path", "content"}:
            raise ToolArgumentError(
                "write_file expects exactly path and content arguments"
            )
        for key in ("path", "content"):
            value = arguments[key]
            if not isinstance(value, str) or not value:
                raise ToolArgumentError(f"{key} must be a non-empty string")

    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        return ToolResult(ok=True, output=f"wrote:{arguments['path']}")


class FailingReadTool(ReadTool):
    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        raise ToolExecutionError("simulated read failure", "simulated_failure")


class ExplodingReadTool(ReadTool):
    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        raise RuntimeError("internal secret detail")


class FlakyValidationTool(ReadTool):
    def __init__(self) -> None:
        super().__init__()
        self.validation_calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        self.validation_calls += 1
        if self.validation_calls > 1:
            raise ToolArgumentError("arguments changed before execution")
        super().validate(arguments)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=not-a-real-secret\n", encoding="utf-8")
    (root / ".env.example").write_text("SECRET=\n", encoding="utf-8")
    return root


@pytest.fixture
def read_tool() -> ReadTool:
    return ReadTool()


@pytest.fixture
def failing_read_tool() -> FailingReadTool:
    return FailingReadTool()


@pytest.fixture
def exploding_read_tool() -> ExplodingReadTool:
    return ExplodingReadTool()


@pytest.fixture
def flaky_read_tool() -> FlakyValidationTool:
    return FlakyValidationTool()


@pytest.fixture
def delete_tool() -> DeleteRecordTool:
    return DeleteRecordTool()


@pytest.fixture
def failing_delete_tool() -> FailingDeleteTool:
    return FailingDeleteTool()


@pytest.fixture
def git_push_tool() -> GitPushTool:
    return GitPushTool()


@pytest.fixture
def write_tool() -> WriteTool:
    return WriteTool()


@pytest.fixture
def registry(
    read_tool: ReadTool,
    delete_tool: DeleteRecordTool,
    git_push_tool: GitPushTool,
    write_tool: WriteTool,
) -> ToolRegistry:
    return ToolRegistry((read_tool, delete_tool, git_push_tool, write_tool))


@pytest.fixture
def engine(registry: ToolRegistry, workspace: Path) -> PolicyEngine:
    return PolicyEngine(registry, workspace)


@pytest.fixture
def gate(
    engine: PolicyEngine,
    registry: ToolRegistry,
    workspace: Path,
) -> ToolGate:
    return ToolGate(engine, registry, workspace)
