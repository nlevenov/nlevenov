"""Push notifications for alerts that cross the configured priority."""

from __future__ import annotations

import logging

import httpx

from .config import NotifySettings
from .models import Alert, Priority

log = logging.getLogger(__name__)

_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:",
          "medium": ":large_yellow_circle:", "low": ":large_green_circle:"}


class Notifier:
    """Posts a Slack/Mattermost/Teams-compatible message to an incoming webhook."""

    def __init__(self, settings: NotifySettings, dashboard_url: str = "") -> None:
        self.url = settings.webhook_url
        self.min_priority = Priority(settings.min_priority)
        self.dashboard_url = dashboard_url.rstrip("/")
        self.sent = 0

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def should_notify(self, alert: Alert, previous: Priority | None) -> bool:
        if not self.enabled or alert.priority.rank < self.min_priority.rank:
            return False
        # only on first sighting or escalation, never for every repeat
        return previous is None or alert.priority.rank > previous.rank

    def format(self, alert: Alert) -> str:
        lines = [
            f"{_EMOJI[alert.priority.value]} *{alert.priority.value.upper()}* "
            f"({alert.risk_score}/100) - {alert.alert_type}: {alert.signature}",
            f"src `{alert.src_ip or '-'}` -> dst `{alert.dst_ip or '-'}`"
            + (f" | host `{alert.hostname}`" if alert.hostname else "")
            + (f" | user `{alert.username}`" if alert.username else ""),
        ]
        if alert.intel:
            lines.append("intel: " + ", ".join(
                f"{h.provider} {h.score}" for h in alert.intel[:4]))
        if alert.asset:
            lines.append(f"asset: {alert.asset.name} (criticality {alert.asset.criticality})")
        if self.dashboard_url:
            lines.append(f"{self.dashboard_url}/alerts/{alert.id}")
        return "\n".join(lines)

    def send(self, alert: Alert) -> bool:
        try:
            response = httpx.post(self.url, json={"text": self.format(alert)}, timeout=5.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("webhook notification for %s failed: %s", alert.id, exc)
            return False
        self.sent += 1
        return True
