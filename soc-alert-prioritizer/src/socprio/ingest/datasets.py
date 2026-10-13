"""Loaders for public research datasets.

CIC-IDS2017 / CSE-CIC-IDS2018 ship as flow CSVs with a ``Label`` column. Each
non-benign flow becomes an alert, and benign flows are sampled in as the noise
that a real IDS produces, which gives a labelled set for the evaluation module.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from ..models import Alert
from .normalize import parse_timestamp

_LABEL_MAP = {
    "ddos": ("Denial of Service", 7.0),
    "dos": ("Denial of Service", 6.5),
    "portscan": ("Port Scan", 4.0),
    "ftp-patator": ("Brute Force", 5.5),
    "ssh-patator": ("Brute Force", 5.5),
    "brute force": ("Brute Force", 5.5),
    "bot": ("Malware", 8.0),
    "infiltration": ("Lateral Movement", 8.5),
    "infilteration": ("Lateral Movement", 8.5),  # spelling used in CSE-CIC-IDS2018
    "sql injection": ("Exploit Attempt", 7.5),
    "xss": ("Exploit Attempt", 6.0),
    "heartbleed": ("Exploit Attempt", 9.0),
}


def _map_label(label: str) -> tuple[str, float]:
    lowered = label.lower()
    for key, value in _LABEL_MAP.items():
        if key in lowered:
            return value
    return ("Unknown", 5.0)


def load_cicids(path: str | Path, benign_ratio: float = 1.0, limit: int | None = None,
                seed: int = 7) -> list[tuple[Alert, bool]]:
    """Return ``(alert, is_malicious)`` pairs from a CIC-IDS CSV file."""
    frame = pd.read_csv(path, low_memory=False, nrows=limit)
    frame.columns = [c.strip() for c in frame.columns]
    if "Label" not in frame.columns:
        raise ValueError(f"{path} does not look like a CIC-IDS file (no Label column)")

    attacks = frame[frame["Label"].str.upper() != "BENIGN"]
    benign = frame[frame["Label"].str.upper() == "BENIGN"]
    n_benign = min(len(benign), int(len(attacks) * benign_ratio) or len(benign))
    frame = pd.concat([attacks, benign.sample(n=n_benign, random_state=seed)])

    pairs = []
    for row in frame.to_dict(orient="records"):
        label = str(row["Label"])
        malicious = label.upper() != "BENIGN"
        if malicious:
            alert_type, severity = _map_label(label)
            signature = f"IDS: {label}"
        else:
            # A benign flow that still triggered a low-fidelity rule.
            alert_type, severity, signature = "Policy Violation", 2.0, "IDS: anomalous flow"
        timestamp = row.get("Timestamp")
        pairs.append((
            Alert(
                timestamp=parse_timestamp(timestamp) if timestamp else parse_timestamp(None),
                source="CIC-IDS",
                alert_type=alert_type,
                signature=signature,
                severity=severity,
                src_ip=_clean(row.get("Source IP") or row.get("Src IP")),
                dst_ip=_clean(row.get("Destination IP") or row.get("Dst IP")),
                src_port=_port(row.get("Source Port") or row.get("Src Port")),
                dst_port=_port(row.get("Destination Port") or row.get("Dst Port")),
                protocol={6: "tcp", 17: "udp", 1: "icmp"}.get(_port(row.get("Protocol")) or 0),
                raw={"label": label, "flow_duration": row.get("Flow Duration")},
            ),
            malicious,
        ))
    return pairs


def _clean(value: object) -> str | None:
    if value is None or (isinstance(value, float) and value != value):
        return None
    return str(value).strip() or None


def _port(value: object) -> int | None:
    try:
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
