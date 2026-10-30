from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from environment variables or .env. Names match the handbook."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Ingestion security. Empty means ingestion is disabled (fail closed).
  
    api_key: str = ""

    # Storage

    database_path: str = "data/cybermi6.db"
    event_retention_days: int = Field(default=7, ge=1)

    # Ingestion limits. 500 mirrors models.MAX_BATCH_SIZE; switch to the import once models.py is merged.

    ingest_max_batch: int = Field(default=100, ge=1, le=500)
    ingest_rate_limit: int = Field(default=300, ge=1)
    ingest_rate_window_seconds: int = Field(default=60, ge=1)

    # Detection thresholds 
    port_scan_ports: int = 20
    port_scan_window_seconds: int = 30
    dns_max_label_length: int = 40
    dns_min_entropy: float = 3.8
    auth_fail_count: int = 5
    auth_fail_window_seconds: int = 300
    alert_cooldown_seconds: int = 300

    # Web
    allowed_origins: str = ""  # comma-separated; empty means same-origin only

    @property
    def origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
