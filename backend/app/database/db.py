from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.config import BACKEND_ROOT, Settings
from app.policies.defaults import build_default_rules

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

DEMO_RECORDS = (
    ("rec-001", "Alpha", "demo-user", 0),
    ("rec-002", "Beta", "demo-user", 0),
    ("rec-003", "Gamma", "demo-user", 1),
)


def resolve_database_path(settings: Settings) -> Path:
    path = Path(settings.database_path).expanduser()
    if not path.is_absolute():
        path = BACKEND_ROOT.parent / path
    return path.resolve()


def connect(settings: Settings) -> sqlite3.Connection:
    path = resolve_database_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(settings: Settings) -> Path:
    settings.validate_for_startup()
    path = resolve_database_path(settings)
    connection = connect(settings)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        _migrate_schema(connection)
        _sync_builtin_policies(connection)
        if settings.seed_demo_records:
            _seed_demo_records(connection)
        connection.commit()
    finally:
        connection.close()
    return path


def _migrate_schema(connection: sqlite3.Connection) -> None:
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(approvals)").fetchall()
    }
    if "arguments_hash" not in columns:
        connection.execute("ALTER TABLE approvals ADD COLUMN arguments_hash TEXT")
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_approvals_pending
        ON approvals(run_id, tool_name, arguments_hash)
        WHERE status = 'pending'
        """
    )


def _sync_builtin_policies(connection: sqlite3.Connection) -> None:
    updated_at = datetime.now(timezone.utc).isoformat()
    for rule in build_default_rules():
        tool_pattern = ", ".join(rule.tool_names) if rule.tool_names else "*"
        connection.execute(
            """
            INSERT INTO policies (
                id, rule_key, name, description, decision,
                tool_pattern, priority, enabled, builtin, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(rule_key) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                decision = excluded.decision,
                tool_pattern = excluded.tool_pattern,
                priority = excluded.priority,
                enabled = excluded.enabled,
                builtin = excluded.builtin,
                updated_at = excluded.updated_at
            """,
            (
                rule.id,
                rule.id,
                rule.name,
                rule.description,
                rule.decision.value,
                tool_pattern,
                rule.priority,
                int(rule.enabled),
                updated_at,
            ),
        )


def _seed_demo_records(connection: sqlite3.Connection) -> None:
    connection.executemany(
        """
        INSERT OR IGNORE INTO simulated_records (id, name, owner, is_deleted)
        VALUES (?, ?, ?, ?)
        """,
        DEMO_RECORDS,
    )
