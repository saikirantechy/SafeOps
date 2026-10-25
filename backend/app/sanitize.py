from __future__ import annotations

from typing import Any, Mapping

MAX_TRACE_TEXT = 2000
REDACTED = "[REDACTED]"

SENSITIVE_KEY_MARKERS = (
    "token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "access_key",
)


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
    return any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)


def _truncate(value: str) -> str:
    if len(value) <= MAX_TRACE_TEXT:
        return value
    removed = len(value) - MAX_TRACE_TEXT
    return f"{value[:MAX_TRACE_TEXT]}... [truncated {removed} chars]"


def sanitize_payload(value: Any, *, _key: str | None = None) -> Any:
    if _key is not None and is_sensitive_key(_key):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            str(key): sanitize_payload(item, _key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_payload(item) for item in value]
    if isinstance(value, str):
        return _truncate(value)
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _truncate(str(value))
