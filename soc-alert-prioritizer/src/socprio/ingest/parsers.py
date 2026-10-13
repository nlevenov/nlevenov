"""Parsers for the log formats seen most often in a SOC.

Every parser takes one record (a line or a decoded JSON object) and returns an
``Alert`` or ``None`` when the record is not an alert (e.g. a Suricata flow
event). Parsers never raise on bad input; the caller counts the skips.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..models import Alert
from .normalize import classify_alert_type, normalize_severity, parse_timestamp, to_int

# --------------------------------------------------------------------------
# CEF (ArcSight, many firewalls / IDS appliances, Splunk forwarders)
# --------------------------------------------------------------------------

_CEF_HEADER = re.compile(r"CEF:\s?(?P<body>.*)$")
_CEF_EXT_KEY = re.compile(r"(?:^|\s)([A-Za-z0-9_.\[\]]+)=")


def _split_cef_header(body: str) -> list[str]:
    """Split on unescaped pipes; the extension is everything after the 7th pipe."""
    parts, current, escaped = [], [], False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|" and len(parts) < 7:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _parse_cef_extension(ext: str) -> dict[str, str]:
    # Values may contain spaces, so a value ends where the next "key=" begins.
    matches = list(_CEF_EXT_KEY.finditer(ext))
    result = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        value = ext[match.end():end].strip()
        result[match.group(1)] = value.replace("\\=", "=").replace("\\\\", "\\")
    return result


def parse_cef(line: str) -> Alert | None:
    match = _CEF_HEADER.search(line)
    if not match:
        return None
    parts = _split_cef_header(match.group("body"))
    if len(parts) < 7:
        return None
    _version, vendor, product, _pver, sig_id, name, severity = parts[:7]
    ext = _parse_cef_extension(parts[7]) if len(parts) > 7 else {}

    url = ext.get("request")
    domain = ext.get("dhost") or (urlparse(url).hostname if url else None)
    category = ext.get("cat", "")
    return Alert(
        timestamp=parse_timestamp(ext.get("rt") or ext.get("end") or ext.get("start")),
        source=f"{vendor} {product}".strip(),
        alert_type=classify_alert_type(name, category),
        signature=name,
        severity=normalize_severity(severity),
        src_ip=ext.get("src"),
        dst_ip=ext.get("dst"),
        src_port=to_int(ext.get("spt")),
        dst_port=to_int(ext.get("dpt")),
        protocol=(ext.get("proto") or "").lower() or None,
        hostname=ext.get("shost") or ext.get("dvchost"),
        username=ext.get("suser") or ext.get("duser"),
        domain=domain if domain and not _looks_like_ip(domain) else None,
        url=url,
        file_hash=ext.get("fileHash") or ext.get("fileId"),
        raw={"signature_id": sig_id, "category": category, **ext},
    )


# --------------------------------------------------------------------------
# Suricata EVE JSON
# --------------------------------------------------------------------------

def parse_suricata(event: dict[str, Any]) -> Alert | None:
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert", {})
    signature = alert.get("signature", "")
    category = alert.get("category", "")
    http = event.get("http", {})
    dns = event.get("dns", {})
    tls = event.get("tls", {})
    fileinfo = event.get("fileinfo", {})

    domain = http.get("hostname") or tls.get("sni") or dns.get("rrname")
    if not domain and isinstance(dns.get("query"), list) and dns["query"]:
        domain = dns["query"][0].get("rrname")
    url = None
    if http.get("hostname") and http.get("url"):
        url = f"http://{http['hostname']}{http['url']}"

    return Alert(
        timestamp=parse_timestamp(event.get("timestamp")),
        source="Suricata",
        alert_type=classify_alert_type(signature, category),
        signature=signature,
        severity=normalize_severity(alert.get("severity"), scale="1-3"),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dest_ip"),
        src_port=to_int(event.get("src_port")),
        dst_port=to_int(event.get("dest_port")),
        protocol=(event.get("proto") or "").lower() or None,
        hostname=event.get("host"),
        domain=domain,
        url=url,
        file_hash=fileinfo.get("sha256") or fileinfo.get("md5"),
        raw={"signature_id": alert.get("signature_id"), "category": category,
             "action": alert.get("action")},
    )


# --------------------------------------------------------------------------
# Linux auth.log (sshd) - turns failed logins into alerts that the
# correlation step then aggregates into brute-force activity.
# --------------------------------------------------------------------------

_AUTH_LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-][\d:]+)?)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_AUTH_FAILED = re.compile(
    r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
_AUTH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_AUTH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)


def parse_authlog(line: str, year: int | None = None) -> Alert | None:
    match = _AUTH_LINE.match(line.strip())
    if not match:
        return None
    ts_text, host, msg = match.group("ts"), match.group("host"), match.group("msg")
    if ts_text[0].isalpha():
        # syslog timestamps have no year
        ts_text = f"{ts_text.split()[0]} {ts_text.split()[1]} {year or datetime.now().year} " \
                  f"{ts_text.split()[2]}"
    timestamp = parse_timestamp(ts_text)

    if failed := _AUTH_FAILED.search(msg):
        return Alert(
            timestamp=timestamp, source="sshd", alert_type="Brute Force",
            signature=f"SSH failed {failed.group('method')} login", severity=3.0,
            src_ip=failed.group("ip"), src_port=int(failed.group("port")), dst_port=22,
            protocol="tcp", hostname=host, username=failed.group("user"), raw={"message": msg},
        )
    if invalid := _AUTH_INVALID.search(msg):
        return Alert(
            timestamp=timestamp, source="sshd", alert_type="Brute Force",
            signature="SSH login attempt for invalid user", severity=3.5,
            src_ip=invalid.group("ip"), dst_port=22, protocol="tcp", hostname=host,
            username=invalid.group("user"), raw={"message": msg},
        )
    if accepted := _AUTH_ACCEPTED.search(msg):
        # Successful logins are informational on their own; rules raise them
        # when the source is also brute-forcing or on a blocklist.
        return Alert(
            timestamp=timestamp, source="sshd", alert_type="Authentication",
            signature=f"SSH accepted {accepted.group('method')} login", severity=1.0,
            src_ip=accepted.group("ip"), src_port=int(accepted.group("port")), dst_port=22,
            protocol="tcp", hostname=host, username=accepted.group("user"),
            raw={"message": msg},
        )
    return None


# --------------------------------------------------------------------------
# Generic JSON / CSV - field names vary between SIEMs, so try known aliases.
# --------------------------------------------------------------------------

_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "_time", "event_time", "date", "created_at"),
    "signature": ("signature", "rule_name", "rule.name", "alert_name", "name", "title",
                  "message", "description"),
    "alert_type": ("alert_type", "type", "category", "event.category", "threat.tactic.name"),
    "severity": ("severity", "event.severity", "risk", "level", "priority", "urgency"),
    "src_ip": ("src_ip", "source_ip", "source.ip", "src", "srcip", "client_ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "destination.ip", "dst", "dstip"),
    "src_port": ("src_port", "source_port", "source.port", "spt", "sport"),
    "dst_port": ("dst_port", "dest_port", "destination_port", "destination.port", "dpt",
                 "dport"),
    "protocol": ("protocol", "proto", "network.transport", "transport"),
    "hostname": ("hostname", "host", "host.name", "computer", "device", "dvc_host"),
    "username": ("username", "user", "user.name", "account", "src_user"),
    "domain": ("domain", "dns.question.name", "query", "dest_host", "url.domain"),
    "url": ("url", "url.full", "request", "uri"),
    "file_hash": ("file_hash", "hash", "sha256", "file.hash.sha256", "md5", "file.hash.md5"),
    "source": ("source", "product", "observer.product", "sourcetype", "vendor"),
}


def _lookup(record: dict[str, Any], dotted: str) -> Any:
    if dotted in record:
        return record[dotted]
    node: Any = record
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _first(record: dict[str, Any], field: str) -> Any:
    for alias in _ALIASES[field]:
        value = _lookup(record, alias)
        # ECS nests objects under names other schemas use for scalars
        # ("source", "url", "host"), so only accept scalar values.
        if value not in (None, "") and not isinstance(value, (dict, list)):
            return value
    return None


def parse_generic(record: dict[str, Any], source: str = "SIEM") -> Alert | None:
    signature = _first(record, "signature")
    if not signature:
        return None
    raw_type = _first(record, "alert_type")
    alert_type = raw_type if raw_type in _KNOWN_TYPES else classify_alert_type(
        str(signature), str(raw_type or "")
    )
    url = _first(record, "url")
    domain = _first(record, "domain") or (urlparse(str(url)).hostname if url else None)
    severity = _first(record, "severity")
    scale = "0-100" if _is_number(severity) and float(severity) > 10 else "0-10"
    return Alert(
        timestamp=parse_timestamp(_first(record, "timestamp")),
        source=str(_first(record, "source") or source),
        alert_type=alert_type,
        signature=str(signature),
        severity=normalize_severity(severity, scale=scale),
        src_ip=_str_or_none(_first(record, "src_ip")),
        dst_ip=_str_or_none(_first(record, "dst_ip")),
        src_port=to_int(_first(record, "src_port")),
        dst_port=to_int(_first(record, "dst_port")),
        protocol=_str_or_none(_first(record, "protocol"), lower=True),
        hostname=_str_or_none(_first(record, "hostname")),
        username=_str_or_none(_first(record, "username")),
        domain=_str_or_none(domain),
        url=_str_or_none(url),
        file_hash=_str_or_none(_first(record, "file_hash")),
        raw=record,
    )


_KNOWN_TYPES = {
    "Ransomware", "Malware", "Phishing", "Brute Force", "Exploit Attempt", "Data Exfiltration",
    "Privilege Escalation", "Lateral Movement", "Port Scan", "Suspicious Domain",
    "Policy Violation", "Authentication",
}


def _str_or_none(value: Any, lower: bool = False) -> str | None:
    if value is None or value == "" or (isinstance(value, float) and value != value):
        return None
    text = str(value).strip()
    return text.lower() if lower else text


def _is_number(value: Any) -> bool:
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _looks_like_ip(text: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", text))


# --------------------------------------------------------------------------
# File-level helpers
# --------------------------------------------------------------------------

FORMATS = ("auto", "cef", "suricata", "json", "csv", "authlog")


def detect_format(sample: str) -> str:
    stripped = sample.strip()
    if "CEF:" in stripped[:200]:
        return "cef"
    if stripped.startswith("{"):
        try:
            first = json.loads(stripped.splitlines()[0])
        except json.JSONDecodeError:
            return "json"
        return "suricata" if "event_type" in first else "json"
    if " sshd[" in stripped:
        return "authlog"
    if "," in stripped.splitlines()[0]:
        return "csv"
    raise ValueError("could not detect log format; pass --format explicitly")


def parse_record(line: str, fmt: str) -> Alert | None:
    """Parse a single line in a known format. Used by the live tail mode."""
    line = line.strip()
    if not line:
        return None
    try:
        if fmt == "cef":
            return parse_cef(line)
        if fmt == "authlog":
            return parse_authlog(line)
        if fmt in ("suricata", "json"):
            record = json.loads(line)
            return parse_suricata(record) if fmt == "suricata" else parse_generic(record)
    except (ValueError, KeyError, TypeError):
        return None
    raise ValueError(f"format '{fmt}' cannot be parsed line by line")


def parse_file(path: str | Path, fmt: str = "auto") -> tuple[list[Alert], int]:
    """Parse a whole file. Returns (alerts, number_of_skipped_records)."""
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "auto":
        fmt = detect_format(text[:4096])

    if fmt == "csv":
        import pandas as pd

        frame = pd.read_csv(path, dtype=str, keep_default_na=False)
        records: Iterable[dict[str, Any]] = frame.to_dict(orient="records")
        return _collect(records, parse_generic)

    if fmt == "json" and text.lstrip().startswith("["):
        return _collect(json.loads(text), parse_generic)

    alerts, skipped = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        alert = parse_record(line, fmt)
        if alert is None:
            skipped += 1
        else:
            alerts.append(alert)
    return alerts, skipped


def _collect(records: Iterable[dict[str, Any]],
             parser: Callable[[dict[str, Any]], Alert | None]) -> tuple[list[Alert], int]:
    alerts, skipped = [], 0
    for record in records:
        try:
            alert = parser(record)
        except (ValueError, KeyError, TypeError):
            alert = None
        if alert is None:
            skipped += 1
        else:
            alerts.append(alert)
    return alerts, skipped


def iter_parse(records: Iterable[dict[str, Any]], fmt: str) -> Iterator[Alert]:
    """Parse already-decoded JSON records (used by the HTTP ingest endpoint)."""
    parser = parse_suricata if fmt == "suricata" else parse_generic
    for record in records:
        try:
            alert = parser(record)
        except (ValueError, KeyError, TypeError):
            continue
        if alert is not None:
            yield alert
