"""Flat view of an alert used by both the rule engine and the ML features."""

from __future__ import annotations

from typing import Any

from ..enrich.indicators import NetworkScope
from ..models import Alert

SENSITIVE_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017}


def alert_context(alert: Alert, scope: NetworkScope) -> dict[str, Any]:
    ts = alert.timestamp
    return {
        "source": alert.source,
        "alert_type": alert.alert_type,
        "signature": alert.signature,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "protocol": alert.protocol,
        "hostname": alert.hostname,
        "username": alert.username,
        "domain": alert.domain,
        "url": alert.url,
        "file_hash": alert.file_hash,
        "occurrences": alert.occurrences,
        "src_internal": scope.is_internal(alert.src_ip),
        "dst_internal": scope.is_internal(alert.dst_ip),
        "sensitive_port": alert.dst_port in SENSITIVE_PORTS,
        "hour": ts.hour,
        "weekday": ts.weekday(),
        "off_hours": ts.hour < 7 or ts.hour >= 20 or ts.weekday() >= 5,
        "intel_score": alert.max_intel_score,
        "intel_hits": len(alert.intel),
        "intel_providers": len({h.provider for h in alert.intel}),
        "intel_tags": alert.intel_tags,
        "asset_criticality": alert.asset_criticality,
        "asset_name": alert.asset.name if alert.asset else None,
        "asset_tags": alert.asset.tags if alert.asset else [],
        "privileged_user": bool(alert.username) and alert.username.lower() in
        {"root", "admin", "administrator", "sa", "domain admin", "system"},
    }
