"""Voice notifications for high-severity alerts."""

import httpx
import structlog

from blackbox.models.alert import Alert, AlertSeverity

log = structlog.get_logger(__name__)

TTS_URL = "http://localhost:5050/speak"


async def notify_voice(alert: Alert) -> None:
    """Speak high-severity alerts via TTS. Fire-and-forget.

    Only speaks for HIGH and CRITICAL alerts. Failure is logged
    but never blocks alert processing.
    """
    if alert.severity not in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
        return

    text = f"{alert.severity.value} alert: {alert.title}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(TTS_URL, json={"text": text})
        log.info("Voice notification sent", title=alert.title, severity=alert.severity.value)
    except Exception as e:
        log.debug("Voice notification failed", error=str(e))
