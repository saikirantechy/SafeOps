from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from app.policies.models import (
    PolicyContext,
    PolicyDecision,
    PolicyIds,
    PolicyRule,
    RiskCategory,
)

PATH_ARGUMENT_KEYS = (
    "path",
    "file_path",
    "filepath",
    "directory",
    "dir",
    "cwd",
    "workspace_root",
    "paths",
)

READ_PATH_TOOLS = ("list_files", "read_file", "inspect_project")
SEARCH_TOOLS = ("search_code",)
READ_RECORD_TOOLS = ("read_simulated_record",)
CREATE_ISSUE_TOOLS = ("create_simulated_issue",)
DELETE_RECORD_TOOLS = ("delete_simulated_record",)
WRITE_TOOLS = ("write_file", "edit_file", "delete_file", "install_dependency")
RUN_TEST_TOOLS = ("run_tests",)
GIT_INSPECT_TOOLS = ("inspect_git_status", "inspect_git_diff")
GIT_PUSH_TOOLS = ("git_push",)
COMMAND_TOOLS = ("run_command",)

PROTECTED_DIRS = frozenset(
    {".git", ".ssh", ".aws", ".kube", ".failproofai", ".gnupg", ".docker"}
)
PROTECTED_FILES = frozenset(
    {
        ".npmrc",
        ".netrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
    }
)
PROTECTED_SUFFIXES = frozenset({".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"})
ENV_TEMPLATES = frozenset({".env.dist", ".env.example", ".env.sample", ".env.template"})


def iter_candidate_paths(arguments: dict[str, Any]) -> Iterable[str]:
    for key in PATH_ARGUMENT_KEYS:
        if key not in arguments:
            continue
        value = arguments[key]
        if isinstance(value, str):
            yield value
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str):
                    yield item


def resolve_path(raw: str, workspace_root: Path) -> Path | None:
    if "\x00" in raw:
        return None
    candidate = Path(raw).expanduser()
    if candidate.drive and not candidate.is_absolute():
        return None
    if not candidate.is_absolute():
        candidate = workspace_root / candidate
    try:
        return candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def is_within_workspace(path: Path, workspace_root: Path) -> bool:
    try:
        path.relative_to(workspace_root)
    except ValueError:
        return False
    return True


def is_protected_path(path: Path, workspace_root: Path) -> bool:
    try:
        relative = path.relative_to(workspace_root)
    except ValueError:
        relative = path
    parts = tuple(part.lower() for part in relative.parts)
    if any(part in PROTECTED_DIRS for part in parts):
        return True
    if not parts:
        return False
    name = parts[-1]
    if name == ".env":
        return True
    if name.startswith(".env.") and name not in ENV_TEMPLATES:
        return True
    if name in PROTECTED_FILES:
        return True
    return Path(name).suffix in PROTECTED_SUFFIXES


def workspace_reason(context: PolicyContext) -> str | None:
    for raw in iter_candidate_paths(context.arguments):
        resolved = resolve_path(raw, context.workspace_root)
        if resolved is None:
            return "Path could not be resolved safely."
        if not is_within_workspace(resolved, context.workspace_root):
            return f"Path '{raw}' is outside the approved workspace."
    return None


def protected_reason(context: PolicyContext) -> str | None:
    for raw in iter_candidate_paths(context.arguments):
        resolved = resolve_path(raw, context.workspace_root)
        if resolved is None:
            return "Path could not be resolved safely."
        if not is_within_workspace(resolved, context.workspace_root):
            continue
        if is_protected_path(resolved, context.workspace_root):
            return f"Access to protected path '{raw}' is denied."
    return None


def build_default_rules() -> tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            id=PolicyIds.OUTSIDE_WORKSPACE_ACCESS,
            name="Outside Workspace Access",
            description="Access outside the approved workspace is denied.",
            decision=PolicyDecision.DENY,
            risk_category=RiskCategory.WORKSPACE,
            tool_names=READ_PATH_TOOLS + SEARCH_TOOLS + WRITE_TOOLS,
            priority=1100,
            check=workspace_reason,
        ),
        PolicyRule(
            id=PolicyIds.READ_PROTECTED_SECRET,
            name="Protected Secret Access",
            description="Access to protected secret files is denied.",
            decision=PolicyDecision.DENY,
            risk_category=RiskCategory.SECRET,
            tool_names=READ_PATH_TOOLS + SEARCH_TOOLS + WRITE_TOOLS,
            priority=1000,
            check=protected_reason,
        ),
        PolicyRule(
            id=PolicyIds.UNAPPROVED_GIT_PUSH,
            name="Unapproved Git Push",
            description="Git push is denied and cannot be approved.",
            decision=PolicyDecision.DENY,
            risk_category=RiskCategory.GIT,
            tool_names=GIT_PUSH_TOOLS,
            priority=950,
        ),
        PolicyRule(
            id=PolicyIds.UNAUTHORIZED_COMMAND,
            name="Unauthorized Command",
            description="Unrestricted command execution is denied.",
            decision=PolicyDecision.DENY,
            risk_category=RiskCategory.EXECUTE,
            tool_names=COMMAND_TOOLS,
            priority=950,
        ),
        PolicyRule(
            id=PolicyIds.DELETE_SIMULATED_RECORD,
            name="Delete Simulated Record",
            description="Deleting a simulated record requires explicit approval.",
            decision=PolicyDecision.REQUIRE_APPROVAL,
            risk_category=RiskCategory.DESTRUCTIVE,
            tool_names=DELETE_RECORD_TOOLS,
            priority=800,
        ),
        PolicyRule(
            id=PolicyIds.WRITE_REQUIRES_APPROVAL,
            name="Write Requires Approval",
            description="Modifying files or dependencies requires explicit approval.",
            decision=PolicyDecision.REQUIRE_APPROVAL,
            risk_category=RiskCategory.WRITE,
            tool_names=WRITE_TOOLS,
            priority=800,
        ),
        PolicyRule(
            id=PolicyIds.SEARCH_REPOSITORY,
            name="Search Repository",
            description="Searching the approved workspace is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.READ,
            tool_names=SEARCH_TOOLS,
            priority=120,
        ),
        PolicyRule(
            id=PolicyIds.READ_ALLOWED_FILE,
            name="Read Allowed File",
            description="Reading allowed files inside the workspace is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.READ,
            tool_names=READ_PATH_TOOLS,
            priority=100,
        ),
        PolicyRule(
            id=PolicyIds.READ_SIMULATED_RECORD,
            name="Read Simulated Record",
            description="Reading simulated records is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.READ,
            tool_names=READ_RECORD_TOOLS,
            priority=100,
        ),
        PolicyRule(
            id=PolicyIds.CREATE_SIMULATED_ISSUE,
            name="Create Simulated Issue",
            description="Creating simulated issues is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.WRITE,
            tool_names=CREATE_ISSUE_TOOLS,
            priority=100,
        ),
        PolicyRule(
            id=PolicyIds.RUN_TESTS,
            name="Run Approved Tests",
            description="Running approved tests is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.EXECUTE,
            tool_names=RUN_TEST_TOOLS,
            priority=100,
        ),
        PolicyRule(
            id=PolicyIds.INSPECT_GIT,
            name="Inspect Git State",
            description="Read-only Git inspection is allowed.",
            decision=PolicyDecision.ALLOW,
            risk_category=RiskCategory.GIT,
            tool_names=GIT_INSPECT_TOOLS,
            priority=100,
        ),
    )
