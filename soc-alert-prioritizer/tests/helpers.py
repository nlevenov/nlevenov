from __future__ import annotations

from datetime import datetime, timezone

from socprio.models import Alert

BAD_HASH = "a" * 64


def make_alert(**overrides) -> Alert:
    data = {
        "timestamp": datetime(2026, 10, 12, 14, 0, tzinfo=timezone.utc),
        "source": "test",
        "alert_type": "Malware",
        "signature": "Trojan beacon",
        "severity": 8.0,
        "src_ip": "10.0.10.25",
        "dst_ip": "203.0.113.10",
    }
    data.update(overrides)
    return Alert(**data)
