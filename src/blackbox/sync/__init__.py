"""Black Box sync services."""

from blackbox.sync.earnings_sync import (
    EarningsSyncConfig,
    EarningsSyncResult,
    EarningsSyncService,
)
from blackbox.sync.github_sync import (
    GitHubSyncConfig,
    GitHubSyncResult,
    GitHubSyncService,
)
from blackbox.sync.hibp_sync import (
    HIBPSyncConfig,
    HIBPSyncResult,
    HIBPSyncService,
    get_hibp_sync_service,
    set_hibp_sync_service,
)
from blackbox.sync.noaa_sync import (
    NOAASyncConfig,
    NOAASyncResult,
    NOAASyncService,
    create_kc_weather_sync_service,
)
from blackbox.sync.nvd_sync import (
    NVDSyncConfig,
    NVDSyncResult,
    NVDSyncService,
)
from blackbox.sync.rss_sync import (
    RSSSyncConfig,
    RSSSyncResult,
    RSSSyncService,
    create_all_news_sync_service,
    create_kc_news_sync_service,
)
from blackbox.sync.sec_sync import (
    SECSyncConfig,
    SECSyncResult,
    SECSyncService,
)

__all__ = [
    # Earnings sync
    "EarningsSyncConfig",
    "EarningsSyncResult",
    "EarningsSyncService",
    # GitHub Advisory sync
    "GitHubSyncConfig",
    "GitHubSyncResult",
    "GitHubSyncService",
    # HIBP sync
    "HIBPSyncConfig",
    "HIBPSyncResult",
    "HIBPSyncService",
    "get_hibp_sync_service",
    "set_hibp_sync_service",
    # NOAA sync
    "NOAASyncConfig",
    "NOAASyncResult",
    "NOAASyncService",
    "create_kc_weather_sync_service",
    # NVD sync
    "NVDSyncConfig",
    "NVDSyncResult",
    "NVDSyncService",
    # RSS sync
    "RSSSyncConfig",
    "RSSSyncResult",
    "RSSSyncService",
    "create_kc_news_sync_service",
    "create_all_news_sync_service",
    # SEC sync
    "SECSyncConfig",
    "SECSyncResult",
    "SECSyncService",
]
