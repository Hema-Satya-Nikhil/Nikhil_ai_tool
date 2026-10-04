"""Sanitized rotating logging for scans."""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from nikhil_ai_modules.config import resolve_path
from nikhil_ai_modules.evidence import redact_text, sanitize_url

URL_RE = re.compile(r"""https?://[^\s<>"']+""", re.I)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
            message = URL_RE.sub(lambda match: sanitize_url(match.group(0)), message)
            record.msg = redact_text(message, 2000)
            record.args = ()
        except Exception:
            record.msg = "[log message redacted]"
            record.args = ()
        return True


def configure_logger(log_dir: str | Path) -> logging.Logger:
    directory = resolve_path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("nikhil_ai")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(getattr(handler, "_nikhil_handler", False) for handler in logger.handlers):
        handler = RotatingFileHandler(directory / "scanner.log", maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.addFilter(RedactingFilter())
        try:
            Path(handler.baseFilename).chmod(0o600)
        except OSError:
            pass
        handler._nikhil_handler = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    return logger
