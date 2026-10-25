from __future__ import annotations

import re
from typing import Iterable, Mapping

from app.policies.models import Tool
from app.tools.base import ToolArgumentError, UnknownToolError

TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        name = tool.name
        if not TOOL_NAME_PATTERN.fullmatch(name):
            raise ValueError(f"invalid tool name: {name!r}")
        if tool.permission.tool_name != name:
            raise ValueError("tool permission name does not match tool name")
        if tool.timeout_seconds <= 0:
            raise ValueError("tool timeout must be positive")
        if name in self._tools:
            raise ValueError(f"tool already registered: {name}")
        self._tools[name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def require(self, name: str) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise UnknownToolError(f"Tool '{name}' is not registered.")
        return tool

    def validate_arguments(
        self,
        name: str,
        arguments: Mapping[str, object],
    ) -> None:
        tool = self.require(name)
        try:
            tool.validate(arguments)
        except ToolArgumentError:
            raise
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError(
                f"Invalid arguments for tool '{name}'."
            ) from exc

    def list_tools(self) -> tuple[Tool, ...]:
        return tuple(self._tools[name] for name in sorted(self._tools))
