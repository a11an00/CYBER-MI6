import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from backend.models import MAX_BATCH_SIZE, SEVERITIES


@lru_cache(maxsize=4)
def _load_web_path_patterns(path: str) -> dict[str, Any] | None:
    """Read and validate the web_paths pattern file (JSON). Cached, so it is read once.

    Returns None when no file is configured (the rule then uses its built-in defaults).
    Raises ValueError with a clear message when the file is missing or invalid, so a bad
    file is caught at startup and not in the middle of processing events.
    """
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"WEB_PATH_PATTERNS_FILE {path!r} cannot be loaded: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ValueError(f"{path!r} must contain a non-empty JSON object of categories")
    for name, cfg in data.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"{path!r}: category {name!r} must be an object")
        if cfg.get("severity", "medium") not in SEVERITIES:
            raise ValueError(f"{path!r}: category {name!r} severity must be one of {SEVERITIES}")
        patterns = cfg.get("patterns")
        if not isinstance(patterns, list) or not patterns or not all(isinstance(p, str) for p in patterns):
            raise ValueError(f"{path!r}: category {name!r} needs a non-empty 'patterns' list of strings")
        for pattern in patterns:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"{path!r}: invalid regex in {name!r}: {pattern!r} ({exc})") from exc
    return data


class Settings(BaseSettings):
    """Settings loaded from environment variables or .env. Names match the handbook."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Ingestion security. Empty means ingestion is disabled (fail closed).

    api_key: str = ""

    # Storage

    database_path: str = "data/cybermi6.db"
    event_retention_days: int = Field(default=7, ge=1)

    # Ingestion limits. Capped by models.MAX_BATCH_SIZE.

    ingest_max_batch: int = Field(default=100, ge=1, le=MAX_BATCH_SIZE)
    ingest_rate_limit: int = Field(default=300, ge=1)
    ingest_rate_window_seconds: int = Field(default=60, ge=1)

    # Detection thresholds (bounds stop a bad .env value from making a rule fire on everything)
    port_scan_ports: int = Field(default=20, ge=2)
    port_scan_window_seconds: int = Field(default=30, ge=1)
    dns_max_label_length: int = Field(default=40, ge=10, le=63)  # a DNS label is at most 63 characters
    dns_min_entropy: float = Field(default=3.8, ge=0, le=8)
    auth_fail_count: int = Field(default=5, ge=2)
    auth_fail_window_seconds: int = Field(default=300, ge=1)
    alert_cooldown_seconds: int = Field(default=300, ge=0)  # 0 disables de-duplication

    # Web path rule (app/detection/web_paths.py)
    # WEB_PATH_PATTERNS_FILE: path to a JSON file of pattern categories; empty = built-in defaults.
    # WEB_PATH_DISABLED: comma-separated category names to switch off, e.g. "admin_panel_probe".
    web_path_patterns_file: str = ""
    web_path_disabled: str = ""

    # Web
    allowed_origins: str = ""  # comma-separated; empty means same-origin only

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # The two properties below are the names the web_paths rule reads from settings.
    @property
    def web_path_patterns(self) -> dict[str, Any] | None:
        return _load_web_path_patterns(self.web_path_patterns_file)

    @property
    def web_path_disabled_categories(self) -> list[str]:
        return [c.strip().lower() for c in self.web_path_disabled.split(",") if c.strip()]

    @model_validator(mode="after")
    def _validate_web_path_file(self) -> "Settings":
        _load_web_path_patterns(self.web_path_patterns_file)  # fail at startup, not mid-request
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()