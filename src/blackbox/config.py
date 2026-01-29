"""Configuration management for Black Box.

Uses pydantic-settings to load configuration from environment variables
and .env files.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Black Box configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="BLACKBOX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    db_path: Path = Field(default=Path("data/blackbox.db"))
    db_echo: bool = Field(default=False)

    # HIBP (Have I Been Pwned)
    hibp_api_key: str = Field(default="")
    hibp_emails: str = Field(default="")  # Comma-separated list

    # GitHub
    github_token: str = Field(default="")

    # NVD
    nvd_api_key: str = Field(default="")

    # Finnhub (earnings calendar)
    finnhub_api_key: str = Field(default="")

    # SEC EDGAR
    sec_user_agent: str = Field(
        default="BlackBox/0.1.0 (contact@example.com)",
        description="SEC requires identifying user agent",
    )
    sec_tracked_companies: str = Field(default="")  # Comma-separated tickers

    # Juno integration
    juno_inbox_dir: Path = Field(default=Path("/home/atoms/code/juno-inbox/blackbox"))

    # Schedule intervals (minutes)
    rss_sync_interval: int = Field(default=30)
    hibp_sync_interval: int = Field(default=1440)  # Daily
    nvd_sync_interval: int = Field(default=240)  # 4 hours
    github_sync_interval: int = Field(default=360)  # 6 hours
    noaa_sync_interval: int = Field(default=60)  # Hourly
    earnings_sync_interval: int = Field(default=360)  # 6 hours
    sec_sync_interval: int = Field(default=120)  # 2 hours
    detection_interval: int = Field(default=60)  # Hourly
    digest_interval: int = Field(default=1440)  # Daily

    @property
    def hibp_email_list(self) -> list[str]:
        """Parse comma-separated email list."""
        if not self.hibp_emails:
            return []
        return [e.strip() for e in self.hibp_emails.split(",") if e.strip()]

    @property
    def sec_tracked_companies_list(self) -> list[str]:
        """Parse comma-separated company/ticker list."""
        if not self.sec_tracked_companies:
            return []
        return [c.strip().upper() for c in self.sec_tracked_companies.split(",") if c.strip()]


# Global settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset settings (useful for testing)."""
    global _settings
    _settings = None
