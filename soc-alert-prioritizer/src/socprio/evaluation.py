"""Training helpers and the rule-based vs ML-based benchmark."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from sklearn.metrics import f1_score, precision_score, recall_score

from .analysis.ml import AlertClassifier, TrainReport
from .config import Settings
from .models import Alert, Priority
from .pipeline import Pipeline
from .storage import AlertStore

POSITIVE_LABELS = {"true_positive", "tp", "malicious", "1", "true"}


def label_of(alert: Alert) -> bool | None:
    value = alert.raw.get("label", alert.raw.get("verdict"))
    if value is None:
        return None
    return str(value).strip().lower() in POSITIVE_LABELS


def _scratch_pipeline(settings: Settings, classifier: AlertClassifier | None) -> Pipeline:
    pipeline = Pipeline.from_settings(settings, store=AlertStore(":memory:"), load_model=False)
    pipeline.classifier = classifier
    pipeline.notifier = None
    return pipeline


def prepare(alerts: list[Alert], labels: dict[str, bool], settings: Settings,
            classifier: AlertClassifier | None = None) -> tuple[list[Alert], list[bool]]:
    """Run alerts through dedup/enrichment/scoring in a throwaway store.

    ``labels`` maps fingerprint -> label. A deduplicated alert is a true
    positive if any of the raw events behind it was one.
    """
    result = _scratch_pipeline(settings, classifier).process(copy.deepcopy(alerts))
    processed = [a for a in result.alerts if a.fingerprint in labels]
    return processed, [labels[a.fingerprint] for a in processed]


def labels_by_fingerprint(alerts: list[Alert]) -> dict[str, bool]:
    labels: dict[str, bool] = {}
    for alert in alerts:
        label = label_of(alert)
        if label is not None:
            labels[alert.fingerprint] = labels.get(alert.fingerprint, False) or label
    return labels


def train_from_alerts(alerts: list[Alert], settings: Settings,
                      labels: dict[str, bool] | None = None) -> tuple[AlertClassifier, TrainReport]:
    labels = labels if labels is not None else labels_by_fingerprint(alerts)
    if not labels:
        raise ValueError("no labelled alerts found (expected a 'label' field per record)")
    processed, y = prepare([a for a in alerts if a.fingerprint in labels], labels, settings)
    scope = _scratch_pipeline(settings, None).enricher.scope
    return AlertClassifier.train(processed, y, scope)


@dataclass
class StrategyScore:
    name: str
    flagged: int
    precision: float
    recall: float
    f1: float
    precision_at_k: float

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _score(name: str, y_true: list[bool], flagged: list[bool], ranking: list[float],
           k: int) -> StrategyScore:
    order = sorted(range(len(ranking)), key=lambda i: ranking[i], reverse=True)[:k]
    p_at_k = sum(y_true[i] for i in order) / max(len(order), 1)
    return StrategyScore(
        name=name,
        flagged=sum(flagged),
        precision=round(float(precision_score(y_true, flagged, zero_division=0)), 3),
        recall=round(float(recall_score(y_true, flagged, zero_division=0)), 3),
        f1=round(float(f1_score(y_true, flagged, zero_division=0)), 3),
        precision_at_k=round(p_at_k, 3),
    )


def benchmark(train: list[Alert], test: list[Alert], settings: Settings,
              k: int = 50) -> dict[str, Any]:
    """Compare four prioritization strategies on the same held-out alerts.

    An alert counts as "flagged" when it would land in an analyst's queue,
    i.e. priority high or critical (or the equivalent threshold).
    """
    classifier, train_report = train_from_alerts(train, settings)
    test_labels = labels_by_fingerprint(test)
    labelled_test = [a for a in test if a.fingerprint in test_labels]

    rules_only, y_true = prepare(labelled_test, test_labels, settings, classifier=None)
    scored, _ = prepare(labelled_test, test_labels, settings, classifier=classifier)
    by_fp = {a.fingerprint: a for a in scored}
    hybrid = [by_fp[a.fingerprint] for a in rules_only]  # same order as y_true

    actionable = {Priority.CRITICAL, Priority.HIGH}
    strategies = [
        _score("vendor severity", y_true, [a.severity >= 7 for a in rules_only],
               [a.severity for a in rules_only], k),
        _score("rules + intel", y_true, [a.priority in actionable for a in rules_only],
               [a.risk_score for a in rules_only], k),
        _score("ml only", y_true, [(a.ml_probability or 0) >= 0.5 for a in hybrid],
               [a.ml_probability or 0 for a in hybrid], k),
        _score("hybrid (rules + intel + ml)", y_true, [a.priority in actionable for a in hybrid],
               [a.risk_score for a in hybrid], k),
    ]
    return {
        "train": train_report.as_dict(),
        "test_alerts": len(y_true),
        "test_positives": int(sum(y_true)),
        "k": k,
        "strategies": [s.as_dict() for s in strategies],
        "top_features": classifier.top_features(10),
    }
