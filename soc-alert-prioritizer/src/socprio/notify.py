"""Push notifications for alerts that cross the configured priority."""

from __future__ import annotations

import logging
import queue
import threading
from urllib.parse import urlsplit

import httpx

from .config import NotifySettings
from .models import Alert, Priority

log = logging.getLogger(__name__)

_EMOJI = {"critical": ":red_circle:", "high": ":large_orange_circle:",
          "medium": ":large_yellow_circle:", "low": ":large_green_circle:"}


def escape_mrkdwn(text: object) -> str:
    """Escape Slack/Mattermost control sequences.

    Alert fields come from log content. Unescaped, a signature such as
    ``<!channel>`` or ``<https://evil|click here>`` would ping everyone or
    render a disguised link in the SOC channel.
    """
    value = str(text if text is not None else "-")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return value.replace("`", "'")


class Notifier:
    """Posts a Slack/Mattermost/Teams-compatible message to an incoming webhook.

    Sending happens on a background thread so a slow or unreachable webhook
    never stalls alert processing.
    """

    def __init__(self, settings: NotifySettings, dashboard_url: str = "",
                 timeout: float = 5.0) -> None:
        self.url = settings.webhook_url
        if self.url and urlsplit(self.url).scheme != "https":
            raise ValueError("notify.webhook_url must be an https:// URL")
        self.min_priority = Priority(settings.min_priority)
        self.dashboard_url = dashboard_url.rstrip("/")
        self.timeout = timeout
        self.sent = 0
        self.failed = 0
        self._queue: queue.Queue[Alert | None] = queue.Queue(maxsize=1000)
        self._worker: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def should_notify(self, alert: Alert, previous: Priority | None) -> bool:
        if not self.enabled or alert.priority.rank < self.min_priority.rank:
            return False
        # only on first sighting or escalation, never for every repeat
        return previous is None or alert.priority.rank > previous.rank

    def format(self, alert: Alert) -> str:
        e = escape_mrkdwn
        lines = [
            f"{_EMOJI[alert.priority.value]} *{alert.priority.value.upper()}* "
            f"({alert.risk_score}/100) - {e(alert.alert_type)}: {e(alert.signature)}",
            f"src `{e(alert.src_ip)}` -> dst `{e(alert.dst_ip)}`"
            + (f" | host `{e(alert.hostname)}`" if alert.hostname else "")
            + (f" | user `{e(alert.username)}`" if alert.username else ""),
        ]
        if alert.intel:
            lines.append("intel: " + ", ".join(
                f"{e(h.provider)} {h.score}" for h in alert.intel[:4]))
        if alert.asset:
            lines.append(f"asset: {e(alert.asset.name)} "
                         f"(criticality {alert.asset.criticality})")
        if self.dashboard_url:
            lines.append(f"{self.dashboard_url}/alerts/{alert.id}")
        return "\n".join(lines)

    def submit(self, alert: Alert) -> None:
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="notifier", daemon=True)
            self._worker.start()
        try:
            self._queue.put_nowait(alert.model_copy(deep=True))
        except queue.Full:
            self.failed += 1
            log.error("notification queue full, dropping alert %s", alert.id)

    def _run(self) -> None:
        while (alert := self._queue.get()) is not None:
            self.send(alert)
            self._queue.task_done()
        self._queue.task_done()

    def send(self, alert: Alert) -> bool:
        try:
            response = httpx.post(self.url, json={"text": self.format(alert)},
                                  timeout=self.timeout, follow_redirects=False)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            self.failed += 1
            # the webhook URL is a secret - never log it
            log.warning("webhook notification for %s failed: %s", alert.id, type(exc).__name__)
            return False
        self.sent += 1
        return True

    def flush(self) -> None:
        if self._worker is not None:
            self._queue.join()

    def close(self) -> None:
        if self._worker is not None:
            self._queue.put(None)
            self._worker.join(timeout=self.timeout + 1)
            self._worker = None
