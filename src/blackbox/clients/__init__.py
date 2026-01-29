"""Black Box data source clients."""

from blackbox.clients.base import BreachClient
from blackbox.clients.earnings import (
    EarningsClient,
    EarningsConfig,
    EarningsEvent,
    EarningsSearchResult,
)
from blackbox.clients.github_advisory import (
    GitHubAdvisory,
    GitHubAdvisoryClient,
    GitHubAdvisoryConfig,
    GitHubAdvisoryResult,
)
from blackbox.clients.hibp import (
    Breach,
    HIBPClient,
    HIBPConfig,
    Paste,
)
from blackbox.clients.noaa import (
    KC_METRO_STATES,
    NOAAClient,
    NOAAConfig,
    NOAAAlertResult,
    WeatherAlert,
    create_kc_weather_client,
)
from blackbox.clients.nvd import (
    CVE,
    NVDClient,
    NVDConfig,
    NVDSearchResult,
)
from blackbox.clients.rss import (
    ALL_NEWS_FEEDS,
    KC_LOCATION_KEYWORDS,
    KC_MUSIC_FEEDS,
    KC_NEWS_FEEDS,
    FINANCIAL_FEEDS,
    FeedConfig,
    FeedEntry,
    FeedResult,
    RSSClient,
    RSSConfig,
    create_all_news_client,
    create_kc_news_client,
)
from blackbox.clients.sec import (
    FilingType,
    MATERIAL_EVENTS,
    SECClient,
    SECConfig,
    SECFiling,
    SECSearchResult,
)

__all__ = [
    # Base protocols
    "BreachClient",
    # Earnings
    "EarningsClient",
    "EarningsConfig",
    "EarningsEvent",
    "EarningsSearchResult",
    # GitHub Advisory
    "GitHubAdvisory",
    "GitHubAdvisoryClient",
    "GitHubAdvisoryConfig",
    "GitHubAdvisoryResult",
    # HIBP
    "Breach",
    "HIBPClient",
    "HIBPConfig",
    "Paste",
    # NOAA
    "KC_METRO_STATES",
    "NOAAClient",
    "NOAAConfig",
    "NOAAAlertResult",
    "WeatherAlert",
    "create_kc_weather_client",
    # NVD
    "CVE",
    "NVDClient",
    "NVDConfig",
    "NVDSearchResult",
    # RSS
    "FeedConfig",
    "FeedEntry",
    "FeedResult",
    "RSSClient",
    "RSSConfig",
    "KC_NEWS_FEEDS",
    "KC_MUSIC_FEEDS",
    "KC_LOCATION_KEYWORDS",
    "FINANCIAL_FEEDS",
    "ALL_NEWS_FEEDS",
    "create_kc_news_client",
    "create_all_news_client",
    # SEC
    "FilingType",
    "MATERIAL_EVENTS",
    "SECClient",
    "SECConfig",
    "SECFiling",
    "SECSearchResult",
]
