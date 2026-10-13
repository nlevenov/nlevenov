from datetime import timedelta

import pytest

from socprio.evaluation import benchmark, labels_by_fingerprint, train_from_alerts
from socprio.ingest.parsers import parse_generic
from socprio.models import Priority, Status, Verdict
from socprio.pipeline import Pipeline
from socprio.simulate import generate
from socprio.storage import AlertStore

from helpers import BAD_HASH, make_alert


@pytest.fixture
def pipeline(settings):
    return Pipeline.from_settings(settings)


def test_repeats_inside_window_are_merged(pipeline):
    first = make_alert(signature="SSH failed password login", alert_type="Brute Force",
                       src_ip="203.0.113.70", dst_ip="10.0.1.50", username="root")
    repeats = [first.model_copy(update={"timestamp": first.timestamp + timedelta(seconds=10 * i)})
               for i in range(12)]
    result = pipeline.process(repeats)
    assert (result.created, result.merged) == (1, 11)
    alert = result.alerts[0]
    assert alert.occurrences == 12
    assert alert.last_seen - alert.first_seen == timedelta(seconds=110)
    assert any(h.startswith("R004") for h in alert.rule_hits)

    # a later batch inside the window continues the same alert
    later = first.model_copy(update={"timestamp": first.timestamp + timedelta(minutes=5)})
    result = pipeline.process([later])
    assert result.merged == 1 and result.alerts[0].id == alert.id
    assert pipeline.store.get(alert.id).occurrences == 13

    # outside the window it is a new incident
    much_later = first.model_copy(update={"timestamp": first.timestamp + timedelta(hours=3)})
    assert pipeline.process([much_later]).created == 1


def test_malicious_beacon_beats_noise(pipeline):
    beacon = make_alert(file_hash=BAD_HASH, domain="evil.test")
    noise = make_alert(signature="PUA adware bundler detected", severity=4,
                       dst_ip="192.0.2.10")
    result = pipeline.process([beacon, noise])
    by_sig = {a.signature: a for a in result.alerts}
    assert by_sig["Trojan beacon"].priority == Priority.CRITICAL
    assert by_sig["PUA adware bundler detected"].priority == Priority.LOW
    assert "pua" in by_sig["PUA adware bundler detected"].tags


def test_approved_scanner_is_auto_closed(pipeline):
    scan = make_alert(alert_type="Port Scan", signature="ET SCAN Nmap", src_ip="10.0.5.5",
                      dst_ip="10.0.1.20", severity=4)
    alert = pipeline.process([scan]).alerts[0]
    assert alert.status == Status.CLOSED
    assert "approved-scanner" in alert.tags


def test_notifier_fires_once_per_escalation(pipeline, monkeypatch):
    sent = []
    pipeline.notifier.url = "https://hooks.test/x"
    monkeypatch.setattr(pipeline.notifier, "send", lambda alert: sent.append(alert.id) or True)
    beacon = make_alert(file_hash=BAD_HASH)
    pipeline.process([beacon])
    pipeline.process([beacon.model_copy(update={"timestamp": beacon.timestamp
                                                 + timedelta(minutes=1)})])
    assert len(sent) == 1


def test_store_query_update_and_labels(pipeline):
    pipeline.process([make_alert(), make_alert(src_ip="10.0.10.99", signature="Other",
                                               severity=1, dst_ip="192.0.2.1")])
    store: AlertStore = pipeline.store
    items, total = store.query(sort="risk")
    assert total == 2 and items[0].risk_score >= items[1].risk_score
    assert store.query(search="10.0.10.99")[1] == 1
    assert store.query(priority=["critical"])[1] == 1

    updated = store.update(items[0].id, status=Status.CLOSED, verdict=Verdict.TRUE_POSITIVE,
                           notes="confirmed")
    assert updated.verdict == Verdict.TRUE_POSITIVE and updated.notes == "confirmed"
    alerts, labels = store.labelled()
    assert [a.id for a in alerts] == [items[0].id] and labels == [True]


def test_stats_shape(pipeline):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    pipeline.process([make_alert(timestamp=now), make_alert(timestamp=now, src_ip="10.0.10.7")])
    stats = pipeline.store.stats(24)
    assert stats["total"] == 2 and stats["events"] == 2
    assert sum(stats["by_priority"].values()) == 2
    assert stats["timeline"] and stats["top_sources"]


def _synthetic(count, seed, hours=48):
    return [a for r in generate(count, seed=seed, hours=hours) if (a := parse_generic(r))]


def test_training_and_model_roundtrip(settings):
    alerts = _synthetic(1500, seed=3)
    classifier, report = train_from_alerts(alerts, settings)
    assert report.roc_auc > 0.8
    classifier.save(settings.model_path)

    pipeline = Pipeline.from_settings(settings)
    assert pipeline.classifier is not None
    result = pipeline.process(_synthetic(200, seed=4))
    assert all(a.ml_probability is not None for a in result.alerts)
    assert all("ml" in a.score_breakdown for a in result.alerts)


def test_benchmark_reports_every_strategy(settings):
    alerts = sorted(_synthetic(2000, seed=5, hours=72), key=lambda a: a.timestamp)
    report = benchmark(alerts[:1400], alerts[1400:], settings, k=20)
    names = [s["name"] for s in report["strategies"]]
    assert names == ["vendor severity", "rules + intel", "ml only",
                     "hybrid (rules + intel + ml)"]
    scores = {s["name"]: s["f1"] for s in report["strategies"]}
    assert scores["hybrid (rules + intel + ml)"] > scores["vendor severity"]


def test_labels_by_fingerprint_marks_any_positive():
    a = make_alert(raw={"label": "false_positive"})
    b = make_alert(raw={"label": "true_positive"})
    assert labels_by_fingerprint([a, b]) == {a.fingerprint: True}
