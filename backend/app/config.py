from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ADMIN_TOKEN = "dev-admin-token-change-me"
INSECURE_ADMIN_TOKENS = {
    DEFAULT_ADMIN_TOKEN,
    "change-me-before-use",
}
BACKEND_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BACKEND_ROOT / "data" / "safeops.db"
DEFAULT_WORKSPACE_ROOT = BACKEND_ROOT.parent
VALID_ENVIRONMENTS = frozenset({"development", "test", "production"})


def _csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    database_path: str = str(DEFAULT_DB_PATH)
    admin_token: str = DEFAULT_ADMIN_TOKEN
    environment: str = "development"
    workspace_root: str = str(DEFAULT_WORKSPACE_ROOT)
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    demo_mode: bool = True
    llm_provider: str = "demo"
    llm_base_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    tool_timeout_seconds: float = 2.0
    retry_max_attempts: int = 3
    failproof_enabled: bool = False
    failproof_dashboard_url: str = "http://localhost:8020"
    failproof_docs_url: str = "https://docs.befailproof.ai/"
    seed_demo_records: bool = True

    @property
    def using_default_admin_token(self) -> bool:
        return self.admin_token in INSECURE_ADMIN_TOKENS

    @property
    def live_agent_configured(self) -> bool:
        return bool(self.llm_base_url and self.llm_api_key and self.llm_model)

    def validate_for_startup(self) -> None:
        if self.environment not in VALID_ENVIRONMENTS:
            allowed = ", ".join(sorted(VALID_ENVIRONMENTS))
            raise ValueError(f"ENVIRONMENT must be one of: {allowed}")
        workspace = Path(self.workspace_root).expanduser()
        if not workspace.is_dir():
            raise ValueError("WORKSPACE_ROOT must be an existing directory")
        if self.environment == "production":
            if not self.admin_token.strip() or len(self.admin_token) < 16:
                raise ValueError("ADMIN_TOKEN must be at least 16 characters in production")
            if self.using_default_admin_token:
                raise ValueError("ADMIN_TOKEN must not use a default value in production")
            if self.demo_mode:
                raise ValueError("DEMO_MODE must be false in production")


def load_settings() -> Settings:
    settings = Settings(
        database_path=os.getenv("DATABASE_PATH", str(DEFAULT_DB_PATH)),
        admin_token=os.getenv("ADMIN_TOKEN", DEFAULT_ADMIN_TOKEN),
        environment=os.getenv("ENVIRONMENT", "development").strip().lower(),
        workspace_root=os.getenv("WORKSPACE_ROOT", str(DEFAULT_WORKSPACE_ROOT)),
        cors_origins=_csv(os.getenv("CORS_ORIGINS", "http://localhost:3000")) or ("http://localhost:3000",),
        demo_mode=os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes"},
        llm_provider=os.getenv("LLM_PROVIDER", "demo"),
        llm_base_url=os.getenv("LLM_BASE_URL") or None,
        llm_api_key=os.getenv("LLM_API_KEY") or None,
        llm_model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        tool_timeout_seconds=float(os.getenv("TOOL_TIMEOUT_SECONDS", "2")),
        retry_max_attempts=max(1, int(os.getenv("RETRY_MAX_ATTEMPTS", "3"))),
        failproof_enabled=os.getenv("FAILPROOF_ENABLED", "false").lower() in {"1", "true", "yes"},
        failproof_dashboard_url=os.getenv("FAILPROOF_DASHBOARD_URL", "http://localhost:8020"),
        failproof_docs_url=os.getenv("FAILPROOF_DOCS_URL", "https://docs.befailproof.ai/"),
        seed_demo_records=os.getenv("SEED_DEMO_RECORDS", "true").lower() in {"1", "true", "yes"},
    )
    settings.validate_for_startup()
    return settings
