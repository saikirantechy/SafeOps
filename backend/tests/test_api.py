from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN_TOKEN = "test-admin-token-1234"
ADMIN_HEADERS = {"X-Admin-Token": ADMIN_TOKEN}


@pytest.fixture
def api_settings(workspace: Path, tmp_path: Path) -> Settings:
    return Settings(
        database_path=str(tmp_path / "safeops-test.db"),
        admin_token=ADMIN_TOKEN,
        environment="test",
        workspace_root=str(workspace),
        demo_mode=True,
        seed_demo_records=True,
    )


@pytest.fixture
def client(api_settings: Settings):
    with TestClient(create_app(api_settings)) as test_client:
        yield test_client


def test_root(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "SafeOps Ai" in response.text
    assert "Policy-gated execution" in response.text


def test_api_info(client: TestClient) -> None:
    response = client.get("/api/info")

    assert response.status_code == 200
    assert response.json()["name"] == "SafeOps Ai"
    assert response.json()["docs"] == "/docs"


def test_health(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


def test_status_reports_safety_core(client: TestClient) -> None:
    response = client.get("/api/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "running"
    assert payload["environment"] == "test"
    assert payload["policy_count"] == 12
    assert payload["database_policy_count"] == 12
    assert payload["tool_count"] == 1
    assert payload["admin_token_configured"] is True


def test_database_is_initialized(api_settings: Settings, client: TestClient) -> None:
    assert Path(api_settings.database_path).is_file()


def test_list_policies(client: TestClient) -> None:
    response = client.get("/api/policies")

    assert response.status_code == 200
    policies = response.json()
    assert len(policies) == 12
    assert any(policy["id"] == "outside-workspace-access" for policy in policies)
    assert all("check" not in policy for policy in policies)


def test_list_tools(client: TestClient) -> None:
    response = client.get("/api/tools")

    assert response.status_code == 200
    tools = response.json()
    assert len(tools) == 1
    assert tools[0]["name"] == "read_file"
    assert tools[0]["risk_category"] == "read"


def test_evaluate_allowed_read(client: TestClient) -> None:
    response = client.post(
        "/api/tools/evaluate",
        json={"tool_name": "read_file", "arguments": {"path": "app.py"}},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["policy_id"] == "read-allowed-file"


def test_evaluate_protected_file(client: TestClient) -> None:
    response = client.post(
        "/api/tools/evaluate",
        json={"tool_name": "read_file", "arguments": {"path": ".env"}},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["policy_id"] == "read-protected-secret"


def test_execute_requires_admin_token(client: TestClient) -> None:
    response = client.post(
        "/api/tools/execute",
        json={"tool_name": "read_file", "arguments": {"path": "app.py"}},
    )

    assert response.status_code == 401


def test_execute_rejects_wrong_admin_token(client: TestClient) -> None:
    response = client.post(
        "/api/tools/execute",
        json={"tool_name": "read_file", "arguments": {"path": "app.py"}},
        headers={"X-Admin-Token": "wrong"},
    )

    assert response.status_code == 401


def test_execute_allowed_read(client: TestClient) -> None:
    response = client.post(
        "/api/tools/execute",
        json={"tool_name": "read_file", "arguments": {"path": "app.py"}},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "executed"
    assert payload["result"]["output"]["path"] == "app.py"
    assert payload["result"]["output"]["content"] == "print('ok')\n"


def test_execute_denied_read_never_returns_content(client: TestClient) -> None:
    response = client.post(
        "/api/tools/execute",
        json={"tool_name": "read_file", "arguments": {"path": ".env"}},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "denied"
    assert payload["result"] is None
    assert payload["evaluation"]["policy_id"] == "read-protected-secret"


def test_execute_unknown_tool_is_denied(client: TestClient) -> None:
    response = client.post(
        "/api/tools/execute",
        json={"tool_name": "unknown_tool", "arguments": {}},
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "denied"
    assert response.json()["evaluation"]["policy_id"] == "unknown-tool"


def test_invalid_tool_call_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/tools/evaluate",
        json={"tool_name": "read file", "arguments": {}},
    )

    assert response.status_code == 422
