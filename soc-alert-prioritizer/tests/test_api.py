from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from socprio.api import create_app
from socprio.api.security import SESSION_COOKIE
from socprio.pipeline import Pipeline

from helpers import BAD_HASH

API_KEY = "test-key-0123456789abcdef"
AUTH = {"X-API-Key": API_KEY}
BASE = "http://localhost"
NOW = datetime.now(timezone.utc).isoformat()
EVENTS = [
    {"timestamp": NOW, "signature": "Trojan beacon to C2", "severity": 9,
     "src_ip": "10.0.10.25", "dst_ip": "203.0.113.10", "file_hash": BAD_HASH},
    {"timestamp": NOW, "signature": "P2P BitTorrent traffic", "severity": 2,
     "src_ip": "10.0.10.30", "dst_ip": "192.0.2.50"},
    {"no_signature": True},
]


@pytest.fixture
def client(settings):
    settings.api_key = API_KEY
    return TestClient(create_app(settings, Pipeline.from_settings(settings)), base_url=BASE)


@pytest.fixture
def open_client(settings):
    return TestClient(create_app(settings, Pipeline.from_settings(settings)), base_url=BASE)


def _login(client):
    return client.post("/login", data={"api_key": API_KEY}, headers={"Origin": BASE},
                       follow_redirects=False)


# ---------------------------------------------------------------- behaviour

def test_health_is_public(client):
    assert client.get("/health").json()["status"] == "ok"


def test_ingest_list_detail_and_triage(client):
    response = client.post("/api/ingest", json={"format": "json", "events": EVENTS}, headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["created"] == 2 and body["skipped"] == 1

    page = client.get("/api/alerts", params={"priority": "critical"}, headers=AUTH).json()
    assert page["total"] == 1
    alert = page["items"][0]
    assert alert["signature"] == "Trojan beacon to C2"

    assert client.get(f"/api/alerts/{alert['id']}", headers=AUTH).json()["id"] == alert["id"]
    assert client.get("/api/alerts/missing", headers=AUTH).status_code == 404

    patched = client.patch(f"/api/alerts/{alert['id']}", json={"verdict": "true_positive"},
                           headers=AUTH).json()
    assert patched["verdict"] == "true_positive" and patched["status"] == "closed"
    open_alerts = client.get("/api/alerts", params={"status": ["new"]}, headers=AUTH).json()
    assert open_alerts["total"] == 1


def test_invalid_filter_values_are_rejected(client):
    assert client.get("/api/alerts", params={"priority": "urgent"},
                      headers=AUTH).status_code == 422


def test_line_formats_over_http(client):
    lines = ["Oct 12 14:00:01 jump01 sshd[1]: Failed password for root from 203.0.113.70 "
             "port 50122 ssh2"] * 3
    body = client.post("/api/ingest", json={"format": "authlog", "events": lines},
                       headers=AUTH).json()
    assert body["created"] == 1 and body["merged"] == 2


def test_pages_and_reports(client):
    client.post("/api/ingest", json={"events": EVENTS[:2]}, headers=AUTH)
    _login(client)
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
    assert client.post("/api/model/retrain", headers=AUTH).status_code == 409
    assert client.get("/api/model", headers=AUTH).json() == {"loaded": False}


# ----------------------------------------------------------------- security

@pytest.mark.parametrize("method,path", [
    ("get", "/api/alerts"), ("get", "/api/stats"), ("get", "/api/report.csv"),
    ("get", "/api/report.html"), ("get", "/api/model"), ("post", "/api/ingest"),
    ("post", "/api/model/retrain"), ("patch", "/api/alerts/x"),
])
def test_every_api_endpoint_requires_auth(client, method, path):
    assert getattr(client, method)(path).status_code in (401, 422)
    assert client.request(method.upper(), path, headers={"X-API-Key": "wrong" * 5}) \
        .status_code == 401


def test_pages_redirect_to_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_login_sets_hardened_session_cookie(client):
    response = _login(client)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert SESSION_COOKIE in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/api/alerts").status_code == 200


def test_wrong_password_and_lockout(client):
    for _ in range(10):
        response = client.post("/login", data={"api_key": "nope"}, headers={"Origin": BASE})
        assert response.status_code == 401
    assert client.post("/login", data={"api_key": API_KEY},
                       headers={"Origin": BASE}).status_code == 429


def test_forged_session_cookie_is_rejected(client):
    client.cookies.set(SESSION_COOKIE, "MTk5OTk5OTk5OTpmb28=.deadbeef")
    assert client.get("/api/alerts").status_code == 401


def test_cookie_writes_require_same_origin(client):
    client.post("/api/ingest", json={"events": EVENTS[:1]}, headers=AUTH)
    alert_id = client.get("/api/alerts", headers=AUTH).json()["items"][0]["id"]
    _login(client)
    cross = client.patch(f"/api/alerts/{alert_id}", json={"notes": "x"},
                         headers={"Origin": "https://evil.test"})
    assert cross.status_code == 403
    missing = client.patch(f"/api/alerts/{alert_id}", json={"notes": "x"})
    assert missing.status_code == 403
    same = client.patch(f"/api/alerts/{alert_id}", json={"notes": "x"}, headers={"Origin": BASE})
    assert same.status_code == 200


def test_cross_site_write_blocked_without_auth(open_client):
    response = open_client.post("/api/ingest", json={"events": EVENTS[:1]},
                                headers={"Origin": "https://evil.test"})
    assert response.status_code == 403


def test_unauthenticated_mode_only_answers_to_localhost(open_client, settings):
    assert open_client.get("/health").status_code == 200
    rebinding = TestClient(open_client.app, base_url="http://attacker.test")
    assert rebinding.get("/api/alerts").status_code == 400


def test_weak_api_key_is_refused(settings):
    settings.api_key = "change-me"
    with pytest.raises(ValueError, match="too weak"):
        create_app(settings, Pipeline.from_settings(settings))


def test_security_headers(client):
    headers = client.get("/login").headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert "unsafe-inline" not in headers["content-security-policy"].split("script-src")[1] \
        .split(";")[0]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"


def test_oversized_body_is_rejected(client):
    huge = "x" * (11 * 1024 * 1024)
    response = client.post("/api/ingest", content=huge, headers={
        **AUTH, "Content-Type": "application/json"})
    assert response.status_code == 413


def test_log_content_cannot_inject_into_reports(client):
    payload = '<img src=x onerror=alert(1)>'
    client.post("/api/ingest", headers=AUTH, json={"events": [{
        "timestamp": NOW, "signature": f'=HYPERLINK("http://x.test","{payload}")',
        "severity": 9, "src_ip": payload, "hostname": payload, "dst_ip": "203.0.113.10"}]})
    report = client.get("/api/report.html", headers=AUTH).text
    assert payload not in report
    csv_rows = client.get("/api/report.csv", headers=AUTH).text.splitlines()
    assert ",\"'=HYPERLINK" in csv_rows[1]
    alert = client.get("/api/alerts", headers=AUTH).json()["items"][0]
    assert alert["src_ip"] is None  # not an IP address, kept only in raw
    _login(client)
    page = client.get(f"/alerts/{alert['id']}").text
    assert payload not in page
