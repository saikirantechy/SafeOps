from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.policies.models import (
    RiskCategory,
    ToolPermission,
    ToolResult,
)
from app.tools.base import ToolArgumentError
from app.tools.filesystem import ReadFileTool

ADMIN_TOKEN = "test-admin-token-1234"
ADMIN_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


class WriteTool:
    name = "write_file"
    description = "Write a file in the workspace."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.WRITE,
    )
    timeout_seconds = 2.0

    def __init__(self) -> None:
        self.calls = 0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if set(arguments) != {"path", "content"}:
            raise ToolArgumentError("write_file expects path and content")
        for key in ("path", "content"):
            value = arguments[key]
            if not isinstance(value, str) or not value:
                raise ToolArgumentError(f"{key} must be a non-empty string")

    def execute(self, arguments: Mapping[str, Any], context: Any) -> ToolResult:
        self.calls += 1
        return ToolResult(
            ok=True,
            output={"path": arguments["path"], "bytes": len(arguments["content"])},
        )


@pytest.fixture
def api_settings(workspace: Path, tmp_path: Path) -> Settings:
    return Settings(
        database_path=str(tmp_path / "safeops-api.db"),
        admin_token=ADMIN_TOKEN,
        environment="test",
        workspace_root=str(workspace),
        demo_mode=True,
        seed_demo_records=True,
    )


@pytest.fixture
def write_tool() -> WriteTool:
    return WriteTool()


@pytest.fixture
def client(api_settings: Settings, write_tool: WriteTool):
    app = create_app(api_settings, tools=(ReadFileTool(), write_tool))
    with TestClient(app) as test_client:
        yield test_client


def _create_run(client: TestClient, plan: list[dict[str, Any]] | None = None) -> dict:
    response = client.post(
        "/api/runs",
        json={"task": "Demo run", "plan": plan or []},
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _execute(
    client: TestClient,
    payload: dict[str, Any],
) -> Any:
    return client.post("/api/tools/execute", json=payload, headers=ADMIN_HEADERS)


def test_run_endpoints_require_admin(client: TestClient) -> None:
    assert client.post("/api/runs", json={"task": "no auth"}).status_code == 401
    assert client.get("/api/runs").status_code == 401
    assert client.get("/api/approvals").status_code == 401
    assert client.get("/api/runs/missing/trace").status_code == 401


def test_create_list_and_trace_run(client: TestClient) -> None:
    run = _create_run(
        client,
        plan=[{"tool_name": "read_file", "arguments": {"path": "app.py"}}],
    )

    assert run["status"] == "pending"
    assert run["plan"][0]["tool_name"] == "read_file"
    assert run["event_count"] == 0

    listed = client.get("/api/runs", headers=ADMIN_HEADERS)
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [run["id"]]

    fetched = client.get(f"/api/runs/{run['id']}", headers=ADMIN_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == run["id"]

    trace = client.get(f"/api/runs/{run['id']}/trace", headers=ADMIN_HEADERS)
    assert trace.status_code == 200
    assert trace.json()["run"]["id"] == run["id"]
    assert trace.json()["events"] == []


def test_execute_records_trace_and_metrics(client: TestClient) -> None:
    run = _create_run(client)

    response = _execute(
        client,
        {
            "tool_name": "read_file",
            "arguments": {"path": "app.py"},
            "run_id": run["id"],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "executed"

    trace = client.get(f"/api/runs/{run['id']}/trace", headers=ADMIN_HEADERS).json()
    assert trace["run"]["status"] == "running"
    assert trace["run"]["event_count"] == 1
    event = trace["events"][0]
    assert event["seq"] == 1
    assert event["tool_name"] == "read_file"
    assert event["policy_decision"] == "ALLOW"
    assert event["execution_status"] == "executed"
    assert event["result"]["output"]["path"] == "app.py"

    metrics = client.get("/api/metrics")
    assert metrics.status_code == 200
    payload = metrics.json()
    assert payload["total_runs"] == 1
    assert payload["total_events"] == 1
    assert payload["executions"]["executed"] == 1
    assert payload["success_rate"] == 1.0
    assert payload["approvals"]["pending"] == 0


def test_execute_with_missing_run_is_rejected(client: TestClient) -> None:
    response = _execute(
        client,
        {
            "tool_name": "read_file",
            "arguments": {"path": "app.py"},
            "run_id": "run_missing",
        },
    )

    assert response.status_code == 404


def test_approval_flow_executes_once(client: TestClient, write_tool: WriteTool) -> None:
    run = _create_run(client)
    call = {
        "tool_name": "write_file",
        "arguments": {"path": "notes.txt", "content": "hello"},
        "run_id": run["id"],
    }

    pending = _execute(client, call)
    assert pending.status_code == 200, pending.text
    payload = pending.json()
    assert payload["status"] == "pending_approval"
    assert payload["approval_id"].startswith("appr_")
    assert write_tool.calls == 0

    approvals = client.get(
        "/api/approvals?status=pending",
        headers=ADMIN_HEADERS,
    ).json()
    assert len(approvals) == 1
    approval = approvals[0]
    assert approval["tool_name"] == "write_file"
    assert approval["arguments"] == {"path": "notes.txt", "content": "hello"}

    decided = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "approve",
            "decided_by": "reviewer@example.test",
            "note": "Looks safe.",
        },
        headers=ADMIN_HEADERS,
    )
    assert decided.status_code == 200, decided.text
    assert decided.json()["status"] == "approved"

    approved_execution = _execute(
        client,
        {**call, "approval_id": approval["id"]},
    )
    assert approved_execution.status_code == 200, approved_execution.text
    assert approved_execution.json()["status"] == "executed"
    assert approved_execution.json()["approved_by"] == "reviewer@example.test"
    assert write_tool.calls == 1

    reused = _execute(client, {**call, "approval_id": approval["id"]})
    assert reused.status_code == 409
    assert write_tool.calls == 1

    stored = client.get(
        f"/api/approvals/{approval['id']}",
        headers=ADMIN_HEADERS,
    ).json()
    assert stored["status"] == "used"

    trace = client.get(f"/api/runs/{run['id']}/trace", headers=ADMIN_HEADERS).json()
    assert [event["execution_status"] for event in trace["events"]] == [
        "pending_approval",
        "executed",
    ]

    metrics = client.get("/api/metrics").json()
    assert metrics["approvals"]["used"] == 1
    assert metrics["executions"]["pending_approval"] == 1
    assert metrics["executions"]["executed"] == 1
    assert metrics["success_rate"] == 1.0


def test_rejected_approval_never_executes(
    client: TestClient,
    write_tool: WriteTool,
) -> None:
    run = _create_run(client)
    call = {
        "tool_name": "write_file",
        "arguments": {"path": "notes.txt", "content": "hello"},
        "run_id": run["id"],
    }

    pending = _execute(client, call).json()
    approval_id = pending["approval_id"]

    rejected = client.post(
        f"/api/approvals/{approval_id}/decision",
        json={"decision": "reject", "decided_by": "reviewer@example.test"},
        headers=ADMIN_HEADERS,
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    response = _execute(client, {**call, "approval_id": approval_id})
    assert response.status_code == 409
    assert write_tool.calls == 0

    metrics = client.get("/api/metrics").json()
    assert metrics["approvals"]["rejected"] == 1
    assert metrics["executions"]["executed"] == 0


def test_approval_cannot_be_decided_twice(client: TestClient) -> None:
    run = _create_run(client)
    pending = _execute(
        client,
        {
            "tool_name": "write_file",
            "arguments": {"path": "notes.txt", "content": "hello"},
            "run_id": run["id"],
        },
    ).json()
    approval_id = pending["approval_id"]

    first = client.post(
        f"/api/approvals/{approval_id}/decision",
        json={"decision": "approve", "decided_by": "reviewer@example.test"},
        headers=ADMIN_HEADERS,
    )
    second = client.post(
        f"/api/approvals/{approval_id}/decision",
        json={"decision": "reject", "decided_by": "reviewer@example.test"},
        headers=ADMIN_HEADERS,
    )

    assert first.status_code == 200
    assert second.status_code == 409


def test_metrics_are_public_and_start_empty(client: TestClient) -> None:
    response = client.get("/api/metrics")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_runs"] == 0
    assert payload["total_events"] == 0
    assert payload["success_rate"] is None
    assert payload["average_duration_ms"] is None
