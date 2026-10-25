from __future__ import annotations

from typing import Any, Mapping

from app.policies.defaults import is_protected_path, is_within_workspace, resolve_path
from app.policies.models import RiskCategory, ToolContext, ToolPermission, ToolResult
from app.tools.base import ToolArgumentError, ToolExecutionError

MAX_READ_BYTES = 256 * 1024


class ReadFileTool:
    name = "read_file"
    description = "Read a UTF-8 text file inside the approved workspace."
    permission = ToolPermission(
        tool_name=name,
        risk_category=RiskCategory.READ,
        description=description,
    )
    timeout_seconds = 2.0

    def validate(self, arguments: Mapping[str, Any]) -> None:
        if set(arguments) != {"path"}:
            raise ToolArgumentError("read_file expects exactly one path argument")
        path = arguments["path"]
        if not isinstance(path, str) or not path.strip():
            raise ToolArgumentError("path must be a non-empty string")
        if len(path) > 4096:
            raise ToolArgumentError("path is too long")

    def execute(self, arguments: Mapping[str, Any], context: ToolContext) -> ToolResult:
        raw_path = arguments["path"]
        resolved = resolve_path(raw_path, context.workspace_root)
        if (
            resolved is None
            or not is_within_workspace(resolved, context.workspace_root)
            or is_protected_path(resolved, context.workspace_root)
        ):
            raise ToolExecutionError(
                "Access to the requested path is denied.",
                "access_denied",
            )
        if not resolved.exists():
            raise ToolExecutionError("File not found.", "not_found")
        if not resolved.is_file():
            raise ToolExecutionError("Path is not a file.", "invalid_path")

        try:
            size = resolved.stat().st_size
        except OSError as exc:
            raise ToolExecutionError(
                "File metadata could not be read.",
                "read_error",
            ) from exc
        if size > MAX_READ_BYTES:
            raise ToolExecutionError(
                "File is too large to read.",
                "file_too_large",
            )

        try:
            content = resolved.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ToolExecutionError(
                "File is not valid UTF-8 text.",
                "invalid_encoding",
            ) from exc
        except OSError as exc:
            raise ToolExecutionError("File could not be read.", "read_error") from exc

        relative = resolved.relative_to(context.workspace_root).as_posix()
        return ToolResult(
            ok=True,
            output={
                "path": relative,
                "content": content,
                "size_bytes": size,
            },
        )
