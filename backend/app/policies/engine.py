from __future__ import annotations

import copy
from pathlib import Path
from typing import Sequence

from app.policies.defaults import build_default_rules
from app.policies.models import (
    ApprovalRequirement,
    PolicyContext,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyIds,
    PolicyRule,
    RiskCategory,
    ToolCall,
)
from app.tools.base import ToolArgumentError, ToolCatalog


class PolicyEngine:
    def __init__(
        self,
        tools: ToolCatalog,
        workspace_root: str | Path,
        rules: Sequence[PolicyRule] | None = None,
    ) -> None:
        root = Path(workspace_root).expanduser().resolve()
        if not root.exists():
            raise ValueError("workspace_root must exist")
        if not root.is_dir():
            raise ValueError("workspace_root must be a directory")

        selected_rules = tuple(build_default_rules() if rules is None else rules)
        identifiers = [rule.id for rule in selected_rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("policy rule ids must be unique")

        self._tools = tools
        self._workspace_root = root
        self._rules = tuple(
            sorted(selected_rules, key=lambda rule: (-rule.priority, rule.id))
        )

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    def evaluate(self, call: ToolCall) -> PolicyEvaluationResult:
        if not isinstance(call, ToolCall):
            call = ToolCall.model_validate(call)

        tool = self._tools.get(call.tool_name)
        if tool is None:
            return self._deny(
                call,
                PolicyIds.UNKNOWN_TOOL,
                "Unknown Tool",
                f"Tool '{call.tool_name}' is not registered.",
                RiskCategory.UNKNOWN,
            )

        try:
            self._tools.validate_arguments(call.tool_name, call.arguments)
        except ToolArgumentError as exc:
            return self._deny(
                call,
                PolicyIds.INVALID_TOOL_ARGUMENTS,
                "Invalid Tool Arguments",
                f"Invalid arguments for tool '{call.tool_name}': {self._detail(exc)}",
                tool.permission.risk_category,
            )
        except Exception:
            return self._deny(
                call,
                PolicyIds.EVALUATION_ERROR,
                "Policy Evaluation Error",
                "Argument validation failed unexpectedly; the action was denied.",
                tool.permission.risk_category,
            )

        context = PolicyContext(
            tool_name=call.tool_name,
            arguments=copy.deepcopy(call.arguments),
            workspace_root=self._workspace_root,
            permission=tool.permission,
        )

        for decision in (
            PolicyDecision.DENY,
            PolicyDecision.REQUIRE_APPROVAL,
            PolicyDecision.ALLOW,
        ):
            for rule in self._rules:
                if rule.decision != decision:
                    continue
                try:
                    reason = rule.match_reason(context)
                except Exception:
                    return self._deny(
                        call,
                        PolicyIds.EVALUATION_ERROR,
                        "Policy Evaluation Error",
                        "Policy evaluation failed; the action was denied for safety.",
                        tool.permission.risk_category,
                    )
                if reason is not None:
                    return self._result(
                        call,
                        decision,
                        rule.id,
                        rule.name,
                        reason,
                        rule.risk_category,
                    )

        return self._deny(
            call,
            PolicyIds.DEFAULT_DENY,
            "Default Deny",
            f"No policy authorizes tool '{call.tool_name}'.",
            tool.permission.risk_category,
        )

    def _result(
        self,
        call: ToolCall,
        decision: PolicyDecision,
        policy_id: str,
        policy_name: str,
        reason: str,
        risk_category: RiskCategory,
    ) -> PolicyEvaluationResult:
        approval_required = decision == PolicyDecision.REQUIRE_APPROVAL
        return PolicyEvaluationResult(
            tool_name=call.tool_name,
            arguments=copy.deepcopy(call.arguments),
            workspace_root=self._workspace_root,
            decision=decision,
            policy_id=policy_id,
            policy_name=policy_name,
            reason=reason,
            risk_category=risk_category,
            execution_permitted=decision == PolicyDecision.ALLOW,
            approval_required=approval_required,
            approval=(
                ApprovalRequirement(
                    required=True,
                    reason=reason,
                    risk_category=risk_category,
                    policy_id=policy_id,
                )
                if approval_required
                else None
            ),
        )

    def _deny(
        self,
        call: ToolCall,
        policy_id: str,
        policy_name: str,
        reason: str,
        risk_category: RiskCategory,
    ) -> PolicyEvaluationResult:
        return self._result(
            call,
            PolicyDecision.DENY,
            policy_id,
            policy_name,
            reason,
            risk_category,
        )

    @staticmethod
    def _detail(exc: Exception) -> str:
        detail = " ".join(str(exc).split())
        return detail[:300] if detail else "validation failed"
