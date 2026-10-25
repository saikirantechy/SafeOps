from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_ARGUMENT_BYTES = 64 * 1024


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskCategory(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DESTRUCTIVE = "destructive"
    SECRET = "secret"
    WORKSPACE = "workspace"
    GIT = "git"
    APPROVAL = "approval"
    UNKNOWN = "unknown"


class PolicyIds:
    READ_PROTECTED_SECRET = "read-protected-secret"
    OUTSIDE_WORKSPACE_ACCESS = "outside-workspace-access"
    UNAPPROVED_GIT_PUSH = "unapproved-git-push"
    UNAUTHORIZED_COMMAND = "unauthorized-command"
    DELETE_SIMULATED_RECORD = "delete-simulated-record"
    WRITE_REQUIRES_APPROVAL = "write-requires-approval"
    READ_ALLOWED_FILE = "read-allowed-file"
    SEARCH_REPOSITORY = "search-repository"
    CREATE_SIMULATED_ISSUE = "create-simulated-issue"
    READ_SIMULATED_RECORD = "read-simulated-record"
    RUN_TESTS = "run-tests"
    INSPECT_GIT = "inspect-git"
    UNKNOWN_TOOL = "unknown-tool"
    INVALID_TOOL_ARGUMENTS = "invalid-tool-arguments"
    MALFORMED_REQUEST = "malformed-tool-request"
    DEFAULT_DENY = "default-deny"
    EVALUATION_ERROR = "policy-evaluation-error"
    APPROVAL_MISMATCH = "approval-mismatch"
    APPROVAL_EXPIRED = "approval-expired"
    APPROVAL_REUSED = "approval-reused"


def _require_string_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("argument object keys must be strings")
            _require_string_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _require_string_keys(item)


def canonical_arguments(arguments: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(arguments),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def arguments_fingerprint(tool_name: str, arguments: Mapping[str, Any]) -> str:
    payload = f"{tool_name}\n{canonical_arguments(arguments)}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_]*$")
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            _require_string_keys(value)
            encoded = canonical_arguments(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments must be JSON-serializable") from exc
        if len(encoded.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError(f"arguments must not exceed {MAX_ARGUMENT_BYTES} bytes")
        return value


class ToolContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    workspace_root: Path
    run_id: str | None = None


class ToolPermission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1, max_length=100)
    risk_category: RiskCategory
    description: str = ""


class PolicyContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    arguments: dict[str, Any]
    workspace_root: Path
    permission: ToolPermission | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        arbitrary_types_allowed=True,
    )

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str
    decision: PolicyDecision
    risk_category: RiskCategory
    tool_names: tuple[str, ...] = ()
    priority: int = 0
    enabled: bool = True
    check: Callable[[PolicyContext], str | None] | None = Field(default=None, exclude=True)

    def applies_to(self, tool_name: str) -> bool:
        return not self.tool_names or tool_name in self.tool_names

    def match_reason(self, context: PolicyContext) -> str | None:
        if not self.enabled or not self.applies_to(context.tool_name):
            return None
        if self.check is None:
            return self.description or self.name
        reason = self.check(context)
        return reason if reason else None


class ApprovalRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    required: bool
    reason: str
    risk_category: RiskCategory
    policy_id: str


class PolicyEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str
    arguments: dict[str, Any]
    workspace_root: Path
    decision: PolicyDecision
    policy_id: str
    policy_name: str
    reason: str
    risk_category: RiskCategory


class PolicyEvaluationResult(PolicyEvaluation):
    execution_permitted: bool
    approval_required: bool
    approval: ApprovalRequirement | None = None

    @model_validator(mode="after")
    def validate_consistency(self) -> PolicyEvaluationResult:
        if self.execution_permitted != (self.decision == PolicyDecision.ALLOW):
            raise ValueError("execution_permitted must match ALLOW")
        if self.approval_required != (self.decision == PolicyDecision.REQUIRE_APPROVAL):
            raise ValueError("approval_required must match REQUIRE_APPROVAL")
        if self.approval_required and self.approval is None:
            raise ValueError("approval details are required for REQUIRE_APPROVAL")
        if not self.approval_required and self.approval is not None:
            raise ValueError("approval details are only valid for REQUIRE_APPROVAL")
        return self


class ApprovalGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by: str = Field(min_length=1)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @classmethod
    def issue(
        cls,
        call: ToolCall,
        *,
        approval_id: str,
        approved_by: str,
        ttl_seconds: int = 300,
    ) -> ApprovalGrant:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        return cls(
            approval_id=approval_id,
            tool_name=call.tool_name,
            arguments_hash=arguments_fingerprint(call.tool_name, call.arguments),
            approved_by=approved_by,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )

    def matches(self, call: ToolCall) -> bool:
        return (
            self.tool_name == call.tool_name
            and self.arguments_hash == arguments_fingerprint(call.tool_name, call.arguments)
        )

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at


class ToolCatalog(Protocol):
    def get(self, name: str) -> Tool | None: ...

    def require(self, name: str) -> Tool: ...

    def validate_arguments(self, name: str, arguments: Mapping[str, Any]) -> None: ...


class PolicyEvaluator(Protocol):
    def evaluate(self, call: ToolCall) -> PolicyEvaluationResult: ...


class Tool(Protocol):
    name: str
    description: str
    permission: ToolPermission
    timeout_seconds: float

    def validate(self, arguments: Mapping[str, Any]) -> None: ...

    def execute(self, arguments: Mapping[str, Any], context: ToolContext) -> ToolResult: ...


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    output: Any = None
    error: str | None = None
    error_category: str | None = None


class ToolExecutionStatus(str, Enum):
    EXECUTED = "executed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    FAILED = "failed"


class ToolGateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ToolExecutionStatus
    evaluation: PolicyEvaluationResult
    result: ToolResult | None = None
    approved_by: str | None = None
    duration_ms: int | None = None
    approval_id: str | None = None

    @model_validator(mode="after")
    def validate_status(self) -> ToolGateResult:
        if self.status in {ToolExecutionStatus.EXECUTED, ToolExecutionStatus.FAILED}:
            if self.result is None:
                raise ValueError("result is required for executed or failed status")
        elif self.result is not None:
            raise ValueError("result is only valid for executed or failed status")
        if self.status == ToolExecutionStatus.PENDING_APPROVAL:
            if self.evaluation.decision != PolicyDecision.REQUIRE_APPROVAL:
                raise ValueError("pending approval requires REQUIRE_APPROVAL")
        return self
