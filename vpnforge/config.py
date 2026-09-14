"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Values come from env or .env file."""

    model_config = SettingsConfigDict(
        env_prefix="VPNFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(default=Path("./data"))
    log_level: str = Field(default="INFO")
    ansible_bin: str = Field(default="ansible-playbook")
    ansible_timeout: int = Field(default=1800)

    cf_api_token: str = Field(default="")

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    """Clear the cached Settings (used in tests)."""
    global _settings
    _settings = None