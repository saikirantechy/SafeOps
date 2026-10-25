from __future__ import annotations

from pathlib import Path

import pytest

from app.config import DEFAULT_ADMIN_TOKEN, Settings


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "admin_token": "a" * 24,
        "environment": "production",
        "workspace_root": str(tmp_path),
        "demo_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_accepts_strong_configuration(tmp_path: Path) -> None:
    make_settings(tmp_path).validate_for_startup()


def test_production_rejects_default_admin_token(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, admin_token=DEFAULT_ADMIN_TOKEN)

    with pytest.raises(ValueError, match="ADMIN_TOKEN"):
        settings.validate_for_startup()


def test_production_rejects_short_admin_token(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, admin_token="short")

    with pytest.raises(ValueError, match="ADMIN_TOKEN"):
        settings.validate_for_startup()


def test_production_rejects_demo_mode(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, demo_mode=True)

    with pytest.raises(ValueError, match="DEMO_MODE"):
        settings.validate_for_startup()


def test_invalid_environment_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, environment="staging")

    with pytest.raises(ValueError, match="ENVIRONMENT"):
        settings.validate_for_startup()


def test_missing_workspace_is_rejected(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, workspace_root=str(tmp_path / "missing"))

    with pytest.raises(ValueError, match="WORKSPACE_ROOT"):
        settings.validate_for_startup()


def test_development_allows_default_token(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path,
        admin_token=DEFAULT_ADMIN_TOKEN,
        environment="development",
        demo_mode=True,
    )

    settings.validate_for_startup()
