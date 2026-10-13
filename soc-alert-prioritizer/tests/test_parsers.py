import json

import pytest

from socprio.ingest import detect_format, parse_file
from socprio.ingest.normalize import classify_alert_type, normalize_severity, parse_timestamp
from socprio.ingest.parsers import parse_authlog, parse_cef, parse_generic, parse_suricata

CEF_LINE = (
    "<134>Oct 12 14:00:00 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|9999|"
    "Trojan C2 beacon detected|8|rt=1760277600000 src=10.0.10.25 dst=203.0.113.10 spt=51515 "
    "dpt=443 proto=TCP suser=jsmith request=https://evil.test/gate.php cat=malware "
    "msg=beacon with spaces in it fileHash=" + "a" * 64
)


def test_cef_header_and_extension():
    alert = parse_cef(CEF_LINE)
    assert alert is not None
    assert alert.source == "Palo Alto Networks PAN-OS"
    assert alert.signature == "Trojan C2 beacon detected"
    assert alert.alert_type == "Malware"
    assert alert.severity == 8.0
    assert (alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port) == (
        "10.0.10.25", "203.0.113.10", 51515, 443)
    assert alert.protocol == "tcp"
    assert alert.username == "jsmith"
    assert alert.domain == "evil.test"
    assert alert.raw["msg"] == "beacon with spaces in it"
    assert alert.timestamp.year == 2025


def test_cef_escaped_pipe_in_name():
    alert = parse_cef(r"CEF:0|Acme|IDS|1|42|Exploit a\|b attempt|5|src=1.2.3.4")
    assert alert is not None
    assert alert.signature == "Exploit a|b attempt"


def test_cef_rejects_garbage():
    assert parse_cef("not a cef line") is None
    assert parse_cef("CEF:0|too|few") is None


def test_suricata_alert_event():
    event = {
        "timestamp": "2026-10-12T14:00:00.123456+0000",
        "event_type": "alert", "src_ip": "203.0.113.70", "src_port": 4444,
        "dest_ip": "10.0.1.30", "dest_port": 80, "proto": "TCP",
        "alert": {"signature": "ET SCAN Nmap SYN scan", "category": "Attempted Information Leak",
                  "severity": 2, "signature_id": 2009582},
        "http": {"hostname": "web01.example.com", "url": "/index.php"},
    }
    alert = parse_suricata(event)
    assert alert is not None
    assert alert.alert_type == "Port Scan"
    assert alert.severity == 6.0
    assert alert.url == "http://web01.example.com/index.php"
    assert alert.raw["signature_id"] == 2009582


def test_suricata_ignores_non_alert_events():
    assert parse_suricata({"event_type": "flow"}) is None


def test_authlog_failed_and_accepted():
    failed = parse_authlog("Oct 12 14:00:01 jump01 sshd[1234]: Failed password for invalid user "
                           "admin from 203.0.113.70 port 50122 ssh2", year=2026)
    assert failed is not None
    assert failed.alert_type == "Brute Force"
    assert (failed.username, failed.src_ip, failed.src_port) == ("admin", "203.0.113.70", 50122)
    assert failed.timestamp.isoformat() == "2026-10-12T14:00:01+00:00"

    accepted = parse_authlog("2026-10-12T14:05:00Z jump01 sshd[99]: Accepted password for root "
                             "from 203.0.113.70 port 50200 ssh2")
    assert accepted is not None and accepted.alert_type == "Authentication"
    assert parse_authlog("Oct 12 14:00:01 jump01 sshd[1]: Connection closed by 1.2.3.4") is None


def test_generic_json_with_ecs_fields():
    record = {"@timestamp": "2026-10-12T14:00:00Z", "rule": {"name": "Phishing URL click"},
              "event": {"severity": 73}, "source": {"ip": "10.0.10.40"},
              "destination": {"ip": "203.0.113.10"}, "url": {"full": "https://evil.test/login"}}
    alert = parse_generic(record)
    assert alert is not None
    assert alert.signature == "Phishing URL click"
    assert alert.alert_type == "Phishing"
    assert alert.severity == pytest.approx(7.3)
    assert alert.domain == "evil.test"


def test_generic_requires_a_signature():
    assert parse_generic({"src_ip": "1.2.3.4"}) is None


@pytest.mark.parametrize("text,expected", [
    ("Cobalt Strike beacon", "Malware"),
    ("Mimikatz credential dumping", "Privilege Escalation"),
    ("SQL injection attempt", "Exploit Attempt"),
    ("SSH failed password", "Brute Force"),
    ("Files encrypted, ransom note dropped", "Ransomware"),
    ("something odd", "Unknown"),
])
def test_classify_alert_type(text, expected):
    assert classify_alert_type(text) == expected


def test_severity_scales():
    assert normalize_severity(1, "1-3") == 9.0
    assert normalize_severity(85, "0-100") == 8.5
    assert normalize_severity("High") == 8.0
    assert normalize_severity(None) == 5.0
    assert normalize_severity(42) == 10.0


def test_timestamp_formats():
    assert parse_timestamp(1760277600).year == 2025
    assert parse_timestamp(1760277600000) == parse_timestamp(1760277600)
    assert parse_timestamp("14/02/2018 08:31:01").month == 2
    with pytest.raises(ValueError):
        parse_timestamp("yesterday-ish")


def test_parse_file_detects_formats(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("\n".join(json.dumps(e) for e in [
        {"event_type": "flow"},
        {"event_type": "alert", "timestamp": "2026-10-12T14:00:00Z", "src_ip": "1.2.3.4",
         "dest_ip": "10.0.0.10", "alert": {"signature": "ET SCAN test", "severity": 3}},
    ]))
    assert detect_format(eve.read_text()) == "suricata"
    alerts, skipped = parse_file(eve)
    assert len(alerts) == 1 and skipped == 1

    csv_file = tmp_path / "alerts.csv"
    csv_file.write_text("time,signature,src_ip,severity\n"
                        "2026-10-12T14:00:00Z,Brute force on VPN,203.0.113.5,6\n")
    alerts, skipped = parse_file(csv_file)
    assert len(alerts) == 1 and alerts[0].alert_type == "Brute Force"
