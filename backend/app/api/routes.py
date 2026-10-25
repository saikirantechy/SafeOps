from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.database import repository
from app.database.db import connect
from app.policies.models import (
    PolicyDecision,
    PolicyEvaluationResult,
    RiskCategory,
    ToolCall,
    ToolExecutionStatus,
    ToolGateResult,
)

router = APIRouter()
INDEX_HTML = Path(__file__).resolve().parents[1] / "static" / "index.html"


class AppInfo(BaseModel):
    name: str
    version: str
    docs: str
    health: str


class HealthResponse(BaseModel):
    status: str
    database: str


class StatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    status: str
    environment: str
    demo_mode: bool
    workspace_root: str
    database: str
    database_policy_count: int
    policy_count: int
    tool_count: int
    admin_token_configured: bool
    live_agent_configured: bool
    failproof_enabled: bool


class ToolInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    risk_category: RiskCategory
    timeout_seconds: float


class PolicyInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    decision: PolicyDecision
    risk_category: RiskCategory
    tool_names: tuple[str, ...]
    priority: int
    enabled: bool


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=1, max_length=repository.MAX_TASK_LENGTH)
    plan: list[PlanStep] = Field(default_factory=list)
    provider: str = Field(default="demo", min_length=1, max_length=50)
    provider_mode: str = Field(default="demo", min_length=1, max_length=50)
    fault: Literal["none", "tool_failure", "timeout"] = "none"

    @field_validator("task")
    @classmethod
    def normalize_task(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("task must not be empty")
        return normalized


class RunInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task: str
    provider: str
    provider_mode: str
    status: str
    error_category: str | None = None
    plan: list[PlanStep]
    next_index: int
    fault: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    event_count: int = 0


class ToolEventInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    run_id: str
    seq: int
    created_at: str
    tool_name: str
    arguments: dict[str, Any]
    policy_id: str | None = None
    policy_name: str | None = None
    policy_decision: PolicyDecision
    execution_status: ToolExecutionStatus
    error_category: str | None = None
    retry_count: int = 0
    duration_ms: int | None = None
    result: Any | None = None
    reason: str | None = None


ApprovalStatus = Literal["pending", "approved", "rejected", "used"]


class ApprovalInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    run_id: str
    event_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    status: ApprovalStatus
    requested_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    decision_note: str | None = None


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    decided_by: str = Field(min_length=1, max_length=repository.MAX_DECIDED_BY_LENGTH)
    note: str | None = Field(
        default=None,
        max_length=repository.MAX_DECISION_NOTE_LENGTH,
    )


class TraceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run: RunInfo
    events: list[ToolEventInfo]


class MetricsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_runs: int
    total_events: int
    runs_by_status: dict[str, int]
    decisions: dict[str, int]
    executions: dict[str, int]
    approvals: dict[str, int]
    blocked_events: int
    total_retries: int
    average_duration_ms: float | None = None
    success_rate: float | None = None
    last_event_at: str | None = None


class ExecuteToolRequest(ToolCall):
    run_id: str | None = Field(default=None, min_length=1, max_length=120)
    approval_id: str | None = Field(default=None, min_length=1, max_length=120)


def require_admin(
    request: Request,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    settings = request.app.state.settings
    if not x_admin_token or not secrets.compare_digest(
        x_admin_token.encode("utf-8"),
        settings.admin_token.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token",
            headers={"WWW-Authenticate": "X-Admin-Token"},
        )


def get_connection(request: Request) -> Iterator[sqlite3.Connection]:
    connection = connect(request.app.state.settings)
    try:
        yield connection
    finally:
        connection.close()


def _not_found(exc: repository.NotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def _conflict(exc: repository.PersistenceError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


def _approval_info(approval: dict[str, Any]) -> ApprovalInfo:
    return ApprovalInfo(
        id=approval["id"],
        run_id=approval["run_id"],
        event_id=approval["event_id"],
        tool_name=approval["tool_name"],
        arguments=approval["arguments"],
        reason=approval["reason"],
        status=approval["status"],
        requested_at=approval["requested_at"],
        decided_at=approval.get("decided_at"),
        decided_by=approval.get("decided_by"),
        decision_note=approval.get("decision_note"),
    )


@router.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(INDEX_HTML)


@router.get("/api/info", response_model=AppInfo)
def app_info(request: Request) -> AppInfo:
    return AppInfo(
        name="SafeOps Ai",
        version=request.app.version,
        docs="/docs",
        health="/health",
    )


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    connection: sqlite3.Connection | None = None
    try:
        connection = connect(request.app.state.settings)
        connection.execute("SELECT 1").fetchone()
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    finally:
        if connection is not None:
            connection.close()
    return HealthResponse(status="ok", database="ok")


@router.get("/api/status", response_model=StatusResponse)
def app_status(request: Request) -> StatusResponse:
    settings = request.app.state.settings
    engine = request.app.state.engine
    connection: sqlite3.Connection | None = None
    try:
        connection = connect(settings)
        row = connection.execute("SELECT COUNT(*) AS count FROM policies").fetchone()
        database_policy_count = int(row["count"])
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    finally:
        if connection is not None:
            connection.close()

    return StatusResponse(
        name="SafeOps Ai",
        version=request.app.version,
        status="running",
        environment=settings.environment,
        demo_mode=settings.demo_mode,
        workspace_root=str(engine.workspace_root),
        database="ok",
        database_policy_count=database_policy_count,
        policy_count=len(engine.rules),
        tool_count=len(request.app.state.registry.list_tools()),
        admin_token_configured=not settings.using_default_admin_token,
        live_agent_configured=settings.live_agent_configured,
        failproof_enabled=settings.failproof_enabled,
    )


@router.get("/api/tools", response_model=list[ToolInfo])
def list_tools(request: Request) -> list[ToolInfo]:
    return [
        ToolInfo(
            name=tool.name,
            description=tool.description,
            risk_category=tool.permission.risk_category,
            timeout_seconds=tool.timeout_seconds,
        )
        for tool in request.app.state.registry.list_tools()
    ]


@router.get("/api/policies", response_model=list[PolicyInfo])
def list_policies(request: Request) -> list[PolicyInfo]:
    return [
        PolicyInfo(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            decision=rule.decision,
            risk_category=rule.risk_category,
            tool_names=rule.tool_names,
            priority=rule.priority,
            enabled=rule.enabled,
        )
        for rule in request.app.state.engine.rules
    ]


@router.post("/api/tools/evaluate", response_model=PolicyEvaluationResult)
def evaluate_tool(call: ToolCall, request: Request) -> PolicyEvaluationResult:
    return request.app.state.engine.evaluate(call)


@router.post("/api/tools/execute", response_model=ToolGateResult)
def execute_tool(
    payload: ExecuteToolRequest,
    request: Request,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> ToolGateResult:
    call = ToolCall(tool_name=payload.tool_name, arguments=payload.arguments)

    if payload.run_id:
        try:
            repository.get_run(connection, payload.run_id)
        except repository.NotFoundError as exc:
            raise _not_found(exc) from exc

    approval: dict[str, Any] | None = None
    grant = None
    if payload.approval_id:
        try:
            approval = repository.get_approval(connection, payload.approval_id)
            grant = repository.build_approval_grant(approval)
        except repository.NotFoundError as exc:
            raise _not_found(exc) from exc
        except repository.PersistenceError as exc:
            raise _conflict(exc) from exc

    outcome = request.app.state.gate.execute(call, approval=grant)

    if payload.run_id:
        event_id = repository.record_tool_event(
            connection,
            run_id=payload.run_id,
            call=call,
            evaluation=outcome.evaluation,
            outcome=outcome,
        )
        if outcome.status == ToolExecutionStatus.PENDING_APPROVAL:
            approval_request = repository.record_approval_request(
                connection,
                run_id=payload.run_id,
                event_id=event_id,
                call=call,
                reason=outcome.evaluation.reason,
            )
            outcome = outcome.model_copy(
                update={"approval_id": approval_request["id"]}
            )

    if approval is not None and outcome.status in {
        ToolExecutionStatus.EXECUTED,
        ToolExecutionStatus.FAILED,
    }:
        repository.mark_approval_used(connection, approval["id"])

    return outcome


@router.post(
    "/api/runs",
    response_model=RunInfo,
    status_code=status.HTTP_201_CREATED,
)
def create_run(
    payload: RunCreateRequest,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> RunInfo:
    try:
        run = repository.create_run(
            connection,
            task=payload.task,
            plan=[step.model_dump() for step in payload.plan],
            provider=payload.provider,
            provider_mode=payload.provider_mode,
            fault=payload.fault,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return RunInfo(**run)


@router.get("/api/runs", response_model=list[RunInfo])
def list_runs(
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[RunInfo]:
    return [
        RunInfo(**run)
        for run in repository.list_runs(connection, limit=limit)
    ]


@router.get("/api/runs/{run_id}", response_model=RunInfo)
def get_run(
    run_id: str,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> RunInfo:
    try:
        run = repository.get_run(connection, run_id)
    except repository.NotFoundError as exc:
        raise _not_found(exc) from exc
    return RunInfo(**run)


@router.get("/api/runs/{run_id}/trace", response_model=TraceResponse)
def get_run_trace(
    run_id: str,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> TraceResponse:
    try:
        trace = repository.get_trace(connection, run_id)
    except repository.NotFoundError as exc:
        raise _not_found(exc) from exc
    return TraceResponse(
        run=RunInfo(**trace["run"]),
        events=[ToolEventInfo.model_validate(event) for event in trace["events"]],
    )


@router.get("/api/approvals", response_model=list[ApprovalInfo])
def list_approvals(
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
    approval_status: ApprovalStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=200),
) -> list[ApprovalInfo]:
    rows = repository.list_approvals(
        connection,
        status=approval_status,
        limit=limit,
    )
    return [_approval_info(row) for row in rows]


@router.get("/api/approvals/{approval_id}", response_model=ApprovalInfo)
def get_approval(
    approval_id: str,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> ApprovalInfo:
    try:
        approval = repository.get_approval(connection, approval_id)
    except repository.NotFoundError as exc:
        raise _not_found(exc) from exc
    return _approval_info(approval)


@router.post("/api/approvals/{approval_id}/decision", response_model=ApprovalInfo)
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    _: None = Depends(require_admin),
    connection: sqlite3.Connection = Depends(get_connection),
) -> ApprovalInfo:
    try:
        approval = repository.decide_approval(
            connection,
            approval_id,
            approved=payload.decision == "approve",
            decided_by=payload.decided_by,
            note=payload.note,
        )
    except repository.NotFoundError as exc:
        raise _not_found(exc) from exc
    except repository.ConflictError as exc:
        raise _conflict(exc) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return _approval_info(approval)


@router.get("/api/metrics", response_model=MetricsResponse)
def get_metrics(
    connection: sqlite3.Connection = Depends(get_connection),
) -> MetricsResponse:
    return MetricsResponse(**repository.compute_metrics(connection))
