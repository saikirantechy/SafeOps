PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    task TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    error_category TEXT,
    plan_json TEXT NOT NULL,
    next_index INTEGER NOT NULL DEFAULT 0,
    fault TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS tool_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    policy_id TEXT,
    policy_name TEXT,
    policy_decision TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    error_category TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER,
    result_json TEXT,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_tool_events_run ON tool_events(run_id, seq);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES tool_events(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT,
    decision_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    rule_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    decision TEXT NOT NULL,
    tool_pattern TEXT NOT NULL,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulated_issues (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulated_records (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS demo_files (
    path TEXT PRIMARY KEY,
    content TEXT NOT NULL
);
