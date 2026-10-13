"""Ties every stage together: dedup -> enrich -> rules -> ML -> score -> store."""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta

from .analysis.ml import AlertClassifier
from .analysis.rules import RuleEngine
from .analysis.scoring import RiskScorer
from .config import Settings
from .enrich import Enricher
from .enrich.indicators import NetworkScope
from .models import Alert, Priority
from .notify import Notifier
from .storage import AlertStore

log = logging.getLogger(__name__)


@dataclass
class BatchResult:
    received: int = 0
    created: int = 0
    merged: int = 0
    notified: int = 0
    by_priority: dict[str, int] = field(default_factory=lambda: {p.value: 0 for p in Priority})
    alerts: list[Alert] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        return {"received": self.received, "created": self.created, "merged": self.merged,
                "notified": self.notified, "by_priority": self.by_priority}


class Pipeline:
    def __init__(self, settings: Settings, store: AlertStore, enricher: Enricher,
                 rules: RuleEngine, scorer: RiskScorer, classifier: AlertClassifier | None,
                 notifier: Notifier | None = None) -> None:
        self.settings = settings
        self.store = store
        self.enricher = enricher
        self.rules = rules
        self.scorer = scorer
        self.classifier = classifier
        self.notifier = notifier
        self.window = timedelta(minutes=settings.dedup_window_minutes)
        # Concurrent batches (API workers, watch mode) would otherwise race on
        # the dedup lookup and create the same alert twice.
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: Settings, store: AlertStore | None = None,
                      dashboard_url: str = "", load_model: bool = True) -> Pipeline:
        scope = NetworkScope(settings.internal_networks)
        classifier = AlertClassifier.load(settings.model_path, scope,
                                          settings.model_signing_key) if load_model else None
        if classifier is None and load_model:
            log.info("no trained model at %s - scoring without the ML factor",
                     settings.model_path)
        return cls(
            settings=settings,
            store=store or AlertStore(settings.database),
            enricher=Enricher.from_settings(settings),
            rules=RuleEngine.from_file(settings.rules_path, scope),
            scorer=RiskScorer(settings.scoring),
            classifier=classifier,
            notifier=Notifier(settings.notify, dashboard_url),
        )

    def reload_model(self) -> bool:
        self.classifier = AlertClassifier.load(self.settings.model_path, self.enricher.scope,
                                               self.settings.model_signing_key)
        return self.classifier is not None

    # ------------------------------------------------------------------ run
    def process(self, incoming: Iterable[Alert]) -> BatchResult:
        with self._lock:
            return self._process(incoming)

    def _process(self, incoming: Iterable[Alert]) -> BatchResult:
        result = BatchResult()
        batch: dict[str, Alert] = {}            # fingerprint -> alert being built
        previous: dict[str, Priority | None] = {}

        for alert in sorted(incoming, key=lambda a: a.timestamp):
            result.received += 1
            current = batch.get(alert.fingerprint)
            if current is None:
                current = self.store.find_recent_duplicate(
                    alert.fingerprint, alert.timestamp - self.window)
                if current is not None:
                    previous[alert.fingerprint] = current.priority
            if current is not None and alert.timestamp - current.last_seen <= self.window:
                self._merge(current, alert)
                result.merged += 1
            else:
                alert.id = alert.id or self._new_id(alert)
                current = alert
                previous[alert.fingerprint] = None
                result.created += 1
            batch[alert.fingerprint] = current

        alerts = list(batch.values())
        adjustments = {}
        for alert in alerts:
            self.enricher.enrich(alert)
            adjustments[alert.id] = self.rules.apply(alert).score

        if self.classifier is not None:
            probabilities = self.classifier.predict_proba(alerts)
            for alert, probability in zip(alerts, probabilities, strict=True):
                alert.ml_probability = probability

        for alert in alerts:
            self.scorer.score(alert, adjustments[alert.id])
            self.store.save(alert)
            result.by_priority[alert.priority.value] += 1
            if self.notifier and self.notifier.should_notify(alert, previous[alert.fingerprint]):
                self.notifier.submit(alert)
                result.notified += 1

        result.alerts = sorted(alerts, key=lambda a: a.risk_score, reverse=True)
        return result

    def close(self) -> None:
        if self.notifier:
            self.notifier.close()

    @staticmethod
    def _merge(target: Alert, repeat: Alert) -> None:
        target.occurrences += 1
        target.last_seen = max(target.last_seen, repeat.timestamp)
        target.severity = max(target.severity, repeat.severity)
        # keep the richest observables seen across repeats
        for attr in ("domain", "url", "file_hash", "username", "hostname"):
            if not getattr(target, attr) and getattr(repeat, attr):
                setattr(target, attr, getattr(repeat, attr))

    @staticmethod
    def _new_id(alert: Alert) -> str:
        return f"{alert.timestamp:%Y%m%d}-{uuid.uuid4().hex[:8]}"
