"""Structured logging with ContextVar migration correlation for LKMP."""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import sys
import time
from typing import Any, Dict, Iterator, Optional

_CTX_MIGRATION_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "lkmp_migration_id", default=None
)
_CTX_GANG_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "lkmp_gang_id", default=None
)
_CTX_PID: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "lkmp_pid", default=None
)
_CTX_DRIVER: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "lkmp_driver", default=None
)


class _CorrelationFilter(logging.Filter):
    """Inject active ContextVar correlation fields onto every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "migration_id") or getattr(record, "migration_id") is None:
            record.migration_id = _CTX_MIGRATION_ID.get()
        if not hasattr(record, "gang_id") or getattr(record, "gang_id") is None:
            record.gang_id = _CTX_GANG_ID.get()
        if not hasattr(record, "target_pid") or getattr(record, "target_pid") is None:
            record.target_pid = _CTX_PID.get()
        if not hasattr(record, "driver") or getattr(record, "driver") is None:
            record.driver = _CTX_DRIVER.get()
        return True


class JsonLogFormatter(logging.Formatter):
    """Structured single-line JSON log formatter for production observability."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": round(record.created, 6),
            "iso_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("migration_id", "gang_id", "target_pid", "driver"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


class HumanContextFormatter(logging.Formatter):
    """Compact human-readable formatter including correlation tags when present."""

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        ms = int((record.created - int(record.created)) * 1000)
        tags = []
        for label, attr in (
            ("mig", "migration_id"),
            ("gang", "gang_id"),
            ("pid", "target_pid"),
            ("drv", "driver"),
        ):
            val = getattr(record, attr, None)
            if val is not None:
                tags.append(f"{label}={val}")
        ctx_str = f" [{' '.join(tags)}]" if tags else ""
        base = f"{ts}.{ms:03d} {record.levelname:<5} {record.name}{ctx_str}: {record.getMessage()}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


@contextlib.contextmanager
def migration_log_context(
    *,
    migration_id: Optional[str] = None,
    gang_id: Optional[str] = None,
    pid: Optional[int] = None,
    driver: Optional[str] = None,
) -> Iterator[None]:
    """Bind correlation attributes to the current thread/task execution context."""
    tokens = []
    if migration_id is not None:
        tokens.append((_CTX_MIGRATION_ID, _CTX_MIGRATION_ID.set(migration_id)))
    if gang_id is not None:
        tokens.append((_CTX_GANG_ID, _CTX_GANG_ID.set(gang_id)))
    if pid is not None:
        tokens.append((_CTX_PID, _CTX_PID.set(pid)))
    if driver is not None:
        tokens.append((_CTX_DRIVER, _CTX_DRIVER.set(driver)))
    try:
        yield
    finally:
        for var, tok in reversed(tokens):
            var.reset(tok)


def get_logger(name: str) -> logging.Logger:
    """Return an `lkmp.*` logger wired with correlation context filtering."""
    full_name = name if name.startswith("lkmp") else f"lkmp.{name}"
    logger = logging.getLogger(full_name)
    if not any(isinstance(f, _CorrelationFilter) for f in logger.filters):
        logger.addFilter(_CorrelationFilter())
    return logger


def configure_logging(
    level: str = "WARNING",
    json_logs: bool = False,
    stream: Any = None,
) -> logging.Logger:
    """Configure root `lkmp` logger handler, level, and structured format."""
    root_logger = logging.getLogger("lkmp")
    numeric_level = getattr(logging, level.upper(), logging.WARNING)
    root_logger.setLevel(numeric_level)
    root_logger.propagate = False

    for existing in list(root_logger.handlers):
        root_logger.removeHandler(existing)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.addFilter(_CorrelationFilter())
    if json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(HumanContextFormatter())
    root_logger.addHandler(handler)
    return root_logger


# Install NullHandler by default so library imports stay silent unless configured
logging.getLogger("lkmp").addHandler(logging.NullHandler())
