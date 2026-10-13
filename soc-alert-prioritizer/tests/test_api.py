from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from socprio.api import create_app
from socprio.pipeline import Pipeline

from helpers import BAD_HASH


@pytest.fixture
def client(settings):
    settings.api_key = "s3cret"
    app = create_app(settings, Pipeline.from_settings(settings))
    return TestClient(app)


AUTH = {"X-API-Key": "s3cret"}
NOW = datetime.now(timezone.utc).isoformat()
EVENTS = [
    {"timestamp": NOW, "signature": "Trojan beacon to C2", "severity": 9,
     "src_ip": "10.0.10.25", "dst_ip": "203.0.113.10", "file_hash": BAD_HASH},
    {"timestamp": NOW, "signature": "P2P BitTorrent traffic", "severity": 2,
     "src_ip": "10.0.10.30", "dst_ip": "192.0.2.50"},
    {"no_signature": True},
]


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_ingest_requires_key(client):
    assert client.post("/api/ingest", json={"events": EVENTS}).status_code == 401


def test_ingest_list_detail_and_triage(client):
    response = client.post("/api/ingest", json={"format": "json", "events": EVENTS}, headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 2 and body["skipped"] == 1

    page = client.get("/api/alerts", params={"priority": "critical"}).json()
    assert page["total"] == 1
    alert = page["items"][0]
    assert alert["signature"] == "Trojan beacon to C2"

    assert client.get(f"/api/alerts/{alert['id']}").json()["id"] == alert["id"]
    assert client.get("/api/alerts/missing").status_code == 404

    patched = client.patch(f"/api/alerts/{alert['id']}", json={"verdict": "true_positive"},
                           headers=AUTH).json()
    assert patched["verdict"] == "true_positive" and patched["status"] == "closed"

    open_alerts = client.get("/api/alerts", params={"status": ["new"]}).json()
    assert open_alerts["total"] == 1


def test_line_formats_over_http(client):
    lines = ["Oct 12 14:00:01 jump01 sshd[1]: Failed password for root from 203.0.113.70 "
             "port 50122 ssh2"] * 3
    body = client.post("/api/ingest", json={"format": "authlog", "events": lines},
                       headers=AUTH).json()
    assert body["created"] == 1 and body["merged"] == 2


def test_pages_and_reports(client):
    client.post("/api/ingest", json={"events": EVENTS[:2]}, headers=AUTH)
    assert "Alert queue" in client.get("/").text
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    page = client.get(f"/alerts/{alert_id}")
    assert page.status_code == 200 and "Response playbook" in page.text
    assert client.get("/api/stats").json()["total"] == 2
    csv_text = client.get("/api/report.csv").text
    assert csv_text.startswith("id,") and len(csv_text.strip().splitlines()) == 3
    assert "Alerts by priority" in client.get("/api/report.html").text
    assert client.get("/vendor/plotly.min.js").status_code == 200


def test_retrain_needs_enough_verdicts(client):
    response = client.post("/api/model/retrain", headers=AUTH)
    assert response.status_code == 409
    assert client.get("/api/model").json() == {"loaded": False}
