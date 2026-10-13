"""Helpers that turn vendor-specific values into the common Alert schema."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Ordered: the first matching pattern wins, so put specific ones first.
_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Ransomware", re.compile(r"ransom|encrypt(ed|ion) of files|shadow ?cop", re.I)),
    ("Malware", re.compile(r"malware|trojan|virus|worm|backdoor|\brat\b|\bc2\b|command.and.control|"
                           r"botnet|beacon|cobalt ?strike|emotet|infostealer", re.I)),
    ("Phishing", re.compile(r"phish|credential harvest|spoof", re.I)),
    ("Brute Force", re.compile(r"brute|password spray|failed (password|login)|"
                               r"authentication fail|logon fail|too many", re.I)),
    ("Exploit Attempt", re.compile(r"exploit|cve-\d{4}|injection|sqli|xss|rce|overflow|"
                                   r"traversal|log4j|shellshock", re.I)),
    ("Data Exfiltration", re.compile(r"exfil|large (upload|transfer)|data leak|dns tunnel", re.I)),
    ("Privilege Escalation", re.compile(r"privilege|escalat|sudo|admin group|mimikatz|"
                                        r"credential dump|lsass", re.I)),
    ("Lateral Movement", re.compile(r"lateral|psexec|wmi exec|pass.the.hash|smb admin", re.I)),
    ("Port Scan", re.compile(r"scan|sweep|recon|nmap|masscan", re.I)),
    ("Suspicious Domain", re.compile(r"domain|dns|dga|newly registered|suspicious (host|url)",
                                     re.I)),
    ("Policy Violation", re.compile(r"policy|p2p|tor\b|torrent|unauthori[sz]ed app", re.I)),
]

SEVERITY_WORDS = {
    "critical": 10.0, "very-high": 9.0, "high": 8.0, "medium": 5.0,
    "moderate": 5.0, "low": 2.0, "info": 1.0, "informational": 1.0,
}


def classify_alert_type(*texts: str | None) -> str:
    blob = " ".join(t for t in texts if t)
    for name, pattern in _TYPE_PATTERNS:
        if pattern.search(blob):
            return name
    return "Unknown"


def parse_timestamp(value: Any) -> datetime:
    """Accept epoch seconds/millis, ISO-8601 and a few common SIEM formats."""
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        number = float(value)
        if number > 1e11:  # milliseconds
            number /= 1000
        return datetime.fromtimestamp(number, tz=timezone.utc)

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Suricata writes +0000 rather than +00:00
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
        for fmt in ("%b %d %Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                    "%m/%d/%Y %I:%M:%S %p", "%Y/%m/%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            raise ValueError(f"unrecognised timestamp: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalize_severity(value: Any, scale: str = "0-10") -> float:
    """Map vendor severities onto 0-10.

    ``scale`` describes the input:
      * ``0-10``   CEF / generic numeric
      * ``1-3``    Suricata (1 = high)
      * ``1-4``    Snort-style priority (1 = high)
      * ``0-100``  many EDR products
    """
    if value is None or value == "":
        return 5.0
    if isinstance(value, str) and not _is_number(value):
        return SEVERITY_WORDS.get(value.strip().lower(), 5.0)
    number = float(value)
    if scale == "1-3":
        return {1: 9.0, 2: 6.0, 3: 3.0}.get(int(number), 2.0)
    if scale == "1-4":
        return {1: 9.0, 2: 7.0, 3: 4.0, 4: 2.0}.get(int(number), 2.0)
    if scale == "0-100":
        number /= 10
    return max(0.0, min(10.0, number))


def to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True
