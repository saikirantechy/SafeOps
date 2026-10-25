from __future__ import annotations

import copy
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from app.policies.models import (
    ApprovalGrant,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyEvaluator,
    PolicyIds,
    RiskCategory,
    ToolCall,
    ToolCatalog,
    ToolContext,
    ToolExecutionStatus,
    ToolGateResult,
    ToolResult,
)


class UnknownToolError(KeyError):
    pass


class ToolArgumentError(ValueError):
    pass


class ToolExecutionError(RuntimeError):
    def __init__(self, message: str, category: str = "tool_error") -> None:
        super().__init__(message)
        self.category = category


class ToolGate:
    def __init__(
        self,
        evaluator: PolicyEvaluator,
        tools: ToolCatalog,
        workspace_root: str | Path,
    ) -> None:
        root = Path(workspace_root).expanduser().resolve()
        if not root.exists():
            raise ValueError("workspace_root must exist")
        if not root.is_dir():
            raise ValueError("workspace_root must be a directory")

        self._evaluator = evaluator
        self._tools = tools
        self._workspace_root = root
        self._consumed_approvals: set[str] = set()
        self._approval_lock = threading.Lock()

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    def execute(
        self,
        call: ToolCall | Mapping[str, Any],
        *,
        approval: ApprovalGrant | None = None,
    ) -> ToolGateResult:
        try:
            validated = self._validate_call(call)
        except (ValidationError, TypeError, ValueError):
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=self._malformed_result(call),
            )

        evaluation = self._evaluator.evaluate(validated)
        if evaluation.decision == PolicyDecision.DENY:
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=evaluation,
            )

        approved_by: str | None = None
        if evaluation.decision == PolicyDecision.REQUIRE_APPROVAL:
            if approval is None:
                return ToolGateResult(
                    status=ToolExecutionStatus.PENDING_APPROVAL,
                    evaluation=evaluation,
                )

            approval_denial = self._consume_approval(validated, approval)
            if approval_denial is not None:
                return approval_denial

            evaluation = self._evaluator.evaluate(validated)
            if evaluation.decision == PolicyDecision.DENY:
                return ToolGateResult(
                    status=ToolExecutionStatus.DENIED,
                    evaluation=evaluation,
                )
            if evaluation.decision == PolicyDecision.REQUIRE_APPROVAL:
                approved_by = approval.approved_by

        try:
            self._tools.validate_arguments(validated.tool_name, validated.arguments)
        except UnknownToolError:
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=self._deny_result(
                    validated,
                    PolicyIds.UNKNOWN_TOOL,
                    "Unknown Tool",
                    f"Tool '{validated.tool_name}' is not registered.",
                    RiskCategory.UNKNOWN,
                ),
            )
        except ToolArgumentError as exc:
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=self._deny_result(
                    validated,
                    PolicyIds.INVALID_TOOL_ARGUMENTS,
                    "Invalid Tool Arguments",
                    f"Invalid arguments for tool '{validated.tool_name}': {self._detail(exc)}",
                    RiskCategory.UNKNOWN,
                ),
            )
        except Exception:
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=self._deny_result(
                    validated,
                    PolicyIds.EVALUATION_ERROR,
                    "Policy Evaluation Error",
                    "Tool validation failed unexpectedly; the action was denied.",
                    RiskCategory.UNKNOWN,
                ),
            )

        tool = self._tools.get(validated.tool_name)
        if tool is None:
            return ToolGateResult(
                status=ToolExecutionStatus.DENIED,
                evaluation=self._deny_result(
                    validated,
                    PolicyIds.UNKNOWN_TOOL,
                    "Unknown Tool",
                    f"Tool '{validated.tool_name}' is not registered.",
                    RiskCategory.UNKNOWN,
                ),
            )

        started = time.perf_counter()
        try:
            result = tool.execute(
                validated.arguments,
                ToolContext(workspace_root=self._workspace_root),
            )
            if not isinstance(result, ToolResult):
                raise TypeError("tool returned an invalid result")
        except ToolExecutionError as exc:
            return self._failed_result(
                evaluation,
                ToolResult(
                    ok=False,
                    error=self._limit(self._detail(exc), 500),
                    error_category=exc.category,
                ),
                started,
                approved_by,
            )
        except Exception:
            return self._failed_result(
                evaluation,
                ToolResult(
                    ok=False,
                    error="Tool execution failed.",
                    error_category="unexpected_tool_error",
                ),
                started,
                approved_by,
            )

        duration_ms = self._elapsed_ms(started)
        status = (
            ToolExecutionStatus.EXECUTED
            if result.ok
            else ToolExecutionStatus.FAILED
        )
        return ToolGateResult(
            status=status,
            evaluation=evaluation,
            result=result,
            approved_by=approved_by,
            duration_ms=duration_ms,
        )

    def _validate_call(self, call: ToolCall | Mapping[str, Any]) -> ToolCall:
        if isinstance(call, ToolCall):
            return ToolCall(
                tool_name=call.tool_name,
                arguments=copy.deepcopy(call.arguments),
            )
        validated = ToolCall.model_validate(call)
        return ToolCall(
            tool_name=validated.tool_name,
            arguments=copy.deepcopy(validated.arguments),
        )

    def _consume_approval(
        self,
        call: ToolCall,
        approval: ApprovalGrant,
    ) -> ToolGateResult | None:
        with self._approval_lock:
            if approval.approval_id in self._consumed_approvals:
                return ToolGateResult(
                    status=ToolExecutionStatus.DENIED,
                    evaluation=self._deny_result(
                        call,
                        PolicyIds.APPROVAL_REUSED,
                        "Approval Reused",
                        "This approval has already been used.",
                        RiskCategory.APPROVAL,
                    ),
                )
            if approval.is_expired():
                return ToolGateResult(
                    status=ToolExecutionStatus.DENIED,
                    evaluation=self._deny_result(
                        call,
                        PolicyIds.APPROVAL_EXPIRED,
                        "Approval Expired",
                        "This approval has expired.",
                        RiskCategory.APPROVAL,
                    ),
                )
            if not approval.matches(call):
                return ToolGateResult(
                    status=ToolExecutionStatus.DENIED,
                    evaluation=self._deny_result(
                        call,
                        PolicyIds.APPROVAL_MISMATCH,
                        "Approval Mismatch",
                        "This approval does not match the requested action.",
                        RiskCategory.APPROVAL,
                    ),
                )
            self._consumed_approvals.add(approval.approval_id)
        return None

    def _malformed_result(
        self,
        call: ToolCall | Mapping[str, Any],
    ) -> PolicyEvaluationResult:
        raw_name: Any = None
        if isinstance(call, Mapping):
            raw_name = call.get("tool_name")
        elif isinstance(call, ToolCall):
            raw_name = call.tool_name
        tool_name = (
            raw_name
            if isinstance(raw_name, str)
            and 0 < len(raw_name) <= 100
            and raw_name.replace("_", "").isalnum()
            and raw_name.islower()
            else "<invalid>"
        )
        return PolicyEvaluationResult(
            tool_name=tool_name,
            arguments={},
            workspace_root=self._workspace_root,
            decision=PolicyDecision.DENY,
            policy_id=PolicyIds.MALFORMED_REQUEST,
            policy_name="Malformed Tool Request",
            reason="Malformed tool request rejected.",
            risk_category=RiskCategory.UNKNOWN,
            execution_permitted=False,
            approval_required=False,
            approval=None,
        )

    def _deny_result(
        self,
        call: ToolCall,
        policy_id: str,
        policy_name: str,
        reason: str,
        risk_category: RiskCategory,
    ) -> PolicyEvaluationResult:
        return PolicyEvaluationResult(
            tool_name=call.tool_name,
            arguments=copy.deepcopy(call.arguments),
            workspace_root=self._workspace_root,
            decision=PolicyDecision.DENY,
            policy_id=policy_id,
            policy_name=policy_name,
            reason=reason,
            risk_category=risk_category,
            execution_permitted=False,
            approval_required=False,
            approval=None,
        )

    def _failed_result(
        self,
        evaluation: PolicyEvaluationResult,
        result: ToolResult,
        started: float,
        approved_by: str | None,
    ) -> ToolGateResult:
        return ToolGateResult(
            status=ToolExecutionStatus.FAILED,
            evaluation=evaluation,
            result=result,
            approved_by=approved_by,
            duration_ms=self._elapsed_ms(started),
        )

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.perf_counter() - started) * 1000))

    @staticmethod
    def _detail(exc: Exception) -> str:
        detail = " ".join(str(exc).split())
        return detail[:500] if detail else "validation failed"

    @staticmethod
    def _limit(value: str, limit: int) -> str:
        return value[:limit]
