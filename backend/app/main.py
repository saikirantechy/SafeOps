from __future__ import annotations

from collections.abc import Iterable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import Settings, load_settings
from app.database.db import initialize_database
from app.policies.engine import PolicyEngine
from app.policies.models import Tool
from app.tools.base import ToolGate
from app.tools.filesystem import ReadFileTool
from app.tools.registry import ToolRegistry

APP_VERSION = "0.1.0"


def create_app(
    settings: Settings | None = None,
    tools: Iterable[Tool] | None = None,
) -> FastAPI:
    resolved = settings or load_settings()
    resolved.validate_for_startup()
    registered_tools = tuple(tools) if tools is not None else (ReadFileTool(),)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        initialize_database(resolved)
        registry = ToolRegistry(registered_tools)
        engine = PolicyEngine(registry, resolved.workspace_root)
        gate = ToolGate(engine, registry, resolved.workspace_root)

        app.state.settings = resolved
        app.state.registry = registry
        app.state.engine = engine
        app.state.gate = gate
        yield

    app = FastAPI(
        title="SafeOps Ai",
        version=APP_VERSION,
        description="Policy-gated tool execution with human approval support.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()
