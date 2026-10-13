"""Synthetic alert generator.

Produces a realistic mix of SOC alerts for a fictional company, including the
ground-truth label an analyst would eventually assign. Used to seed the demo
dashboard, to train an initial model and to benchmark rule-based against
ML-based prioritization.

All "malicious" infrastructure lives in the documentation ranges
(RFC 5737 - 203.0.113.0/24, 198.51.100.0/24) and the reserved .test TLD,
so the sample data never points at real third parties.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

WORKSTATIONS = [f"10.0.10.{i}" for i in range(20, 120)]
SERVERS = {"10.0.0.10": "dc01", "10.0.1.20": "sql-prod01", "10.0.1.30": "web01",
           "10.0.1.40": "files01", "10.0.1.50": "jump01"}
SCANNER = "10.0.5.5"
BAD_IPS = [f"203.0.113.{i}" for i in range(10, 60)]
GREY_IPS = [f"198.51.100.{i}" for i in range(1, 120)]
GOOD_IPS = [f"192.0.2.{i}" for i in range(1, 60)]
BAD_DOMAINS = ["cdn-update.badcdn.test", "login-micros0ft-support.test", "pay-portal-verify.test",
               "x9f3kq2lz.dyn-dns.test", "files-share-secure.test", "telemetry-svc.badcdn.test"]
GOOD_DOMAINS = ["updates.example.com", "cdn.example.net", "api.example.org", "intranet.example.com"]
USERS = ["jsmith", "mpetrova", "akumar", "lchen", "dgarcia", "operator", "svc_backup", "nlee"]
PRIV_USERS = ["administrator", "root", "admin"]


def _sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


# Stable hash lists so the sample feed and the generator agree.
BAD_HASHES = [_sha256(f"bad-sample-{i}") for i in range(25)]
PUA_HASHES = [_sha256(f"pua-sample-{i}") for i in range(25)]


@dataclass
class Scenario:
    name: str
    weight: float
    build: Callable[[random.Random, datetime], tuple[dict[str, Any], bool]]


def _workstation(rng: random.Random) -> tuple[str, str]:
    ip = rng.choice(WORKSTATIONS)
    return ip, f"wks-{ip.rsplit('.', 1)[1]:0>3}"


def _malware(rng, ts):
    ip, host = _workstation(rng)
    real = rng.random() < 0.55
    if real:
        sig = rng.choice(["Trojan.GenericKD beacon detected", "Cobalt Strike beacon C2 traffic",
                          "Emotet loader download", "Infostealer exfil to C2 server",
                          "Backdoor reverse shell connection"])
        dst = rng.choice(BAD_IPS) if rng.random() < 0.7 else rng.choice(GREY_IPS)
        file_hash = rng.choice(BAD_HASHES) if rng.random() < 0.6 else _sha256(str(rng.random()))
        domain = rng.choice(BAD_DOMAINS) if rng.random() < 0.6 else None
        severity = rng.choice([7, 8, 9, 10])
    else:
        sig = rng.choice(["PUA adware bundler detected", "Riskware toolbar installer",
                          "Generic heuristic detection (low confidence)",
                          "Potentially unwanted browser extension"])
        dst = rng.choice(GOOD_IPS + GREY_IPS)
        file_hash = rng.choice(PUA_HASHES)
        domain = rng.choice(GOOD_DOMAINS) if rng.random() < 0.5 else None
        severity = rng.choice([3, 4, 5, 6, 7])
    return {"timestamp": ts, "source": "EDR", "signature": sig, "category": "Malware",
            "severity": severity, "src_ip": ip, "dst_ip": dst, "dst_port": rng.choice([443, 80,
            8080, 4444]), "protocol": "tcp", "hostname": host, "username": rng.choice(USERS),
            "domain": domain, "file_hash": file_hash}, real


def _brute_force(rng, ts):
    attacker = rng.choice(BAD_IPS + GREY_IPS + GREY_IPS)
    target_ip = rng.choice(["10.0.1.50", "10.0.1.30", rng.choice(WORKSTATIONS)])
    real = attacker in BAD_IPS or (target_ip == "10.0.1.50" and rng.random() < 0.6)
    user = rng.choice(PRIV_USERS) if rng.random() < 0.5 else rng.choice(USERS)
    return {"timestamp": ts, "source": "sshd", "signature": "SSH failed password login",
            "category": "Brute Force", "severity": 3, "src_ip": attacker, "dst_ip": target_ip,
            "dst_port": 22, "protocol": "tcp", "hostname": SERVERS.get(target_ip, "wks"),
            "username": user, "_burst": rng.randint(4, 60) if real else rng.randint(1, 6)}, real


def _port_scan(rng, ts):
    internal_scanner = rng.random() < 0.45
    src = SCANNER if internal_scanner else rng.choice(BAD_IPS + GREY_IPS + GREY_IPS)
    real = not internal_scanner and src in BAD_IPS and rng.random() < 0.5
    return {"timestamp": ts, "source": "Suricata", "category": "Attempted Information Leak",
            "signature": rng.choice(["ET SCAN Nmap SYN scan", "ET SCAN Possible masscan sweep",
                                     "ET SCAN Suspicious inbound to MSSQL port 1433"]),
            "severity": rng.choice([2, 3, 4]), "src_ip": src,
            "dst_ip": rng.choice(list(SERVERS) + WORKSTATIONS[:5]),
            "dst_port": rng.choice([22, 80, 443, 445, 1433, 3389]), "protocol": "tcp"}, real


def _phishing(rng, ts):
    ip, host = _workstation(rng)
    real = rng.random() < 0.5
    domain = rng.choice(BAD_DOMAINS[:3]) if real else rng.choice(GOOD_DOMAINS)
    sig = (rng.choice(["Credential harvesting page visited", "Phishing URL click from email"])
           if real else rng.choice(["Phishing URL click from email",
                                    "User reported suspicious email"]))
    return {"timestamp": ts, "source": "Proxy", "signature": sig, "category": "Phishing",
            "severity": rng.choice([5, 6, 7]) if real else rng.choice([4, 5]),
            "src_ip": ip, "dst_ip": rng.choice(BAD_IPS[30:] if real else GOOD_IPS),
            "dst_port": 443, "protocol": "tcp", "hostname": host,
            "username": rng.choice(USERS), "domain": domain,
            "url": f"https://{domain}/{'auth/login.php' if real else 'newsletter'}"}, real


def _exploit(rng, ts):
    src = rng.choice(BAD_IPS + GREY_IPS)
    target = rng.choice(["10.0.1.30", "10.0.1.20", "10.0.1.30"])
    real = src in BAD_IPS and rng.random() < 0.6
    sig = rng.choice(["ET EXPLOIT Apache Log4j RCE attempt (CVE-2021-44228)",
                      "SQL injection attempt in query string",
                      "Path traversal attempt ../../etc/passwd",
                      "ET EXPLOIT Possible Shellshock attempt", "XSS attempt in User-Agent"])
    return {"timestamp": ts, "source": "WAF", "signature": sig, "category": "Exploit",
            "severity": rng.choice([6, 7, 8, 9]), "src_ip": src, "dst_ip": target,
            "dst_port": rng.choice([80, 443]), "protocol": "tcp", "hostname": SERVERS[target]}, real


def _exfil(rng, ts):
    ip, host = _workstation(rng)
    real = rng.random() < 0.3
    return {"timestamp": ts, "source": "DLP",
            "signature": "Large upload to unsanctioned cloud storage" if real
            else rng.choice(["Large upload to unsanctioned cloud storage",
                             "Large transfer to backup provider"]),
            "category": "Data Exfiltration", "severity": rng.choice([5, 6, 7]),
            "src_ip": ip, "dst_ip": rng.choice(BAD_IPS if real else GOOD_IPS),
            "dst_port": 443, "protocol": "tcp", "hostname": host,
            "username": rng.choice(USERS),
            "domain": rng.choice(BAD_DOMAINS[3:]) if real else rng.choice(GOOD_DOMAINS)}, real


def _privilege(rng, ts):
    host_ip = rng.choice(["10.0.0.10", "10.0.1.40", rng.choice(WORKSTATIONS)])
    real = rng.random() < 0.35
    sig = (rng.choice(["Mimikatz credential dumping from LSASS",
                       "User added to Domain Admins group"])
           if real else rng.choice(["User added to Domain Admins group",
                                    "Sudo privilege use outside change window"]))
    return {"timestamp": ts, "source": "Windows Security" if host_ip != "10.0.1.40" else "auditd",
            "signature": sig, "category": "Privilege Escalation",
            "severity": rng.choice([7, 8, 9]) if real else rng.choice([5, 6]),
            "src_ip": host_ip, "hostname": SERVERS.get(host_ip, "wks-priv"),
            "username": rng.choice(PRIV_USERS + USERS)}, real


def _policy(rng, ts):
    ip, host = _workstation(rng)
    return {"timestamp": ts, "source": "Firewall",
            "signature": rng.choice(["P2P BitTorrent traffic", "TOR client detected",
                                     "Unauthorized remote access tool (AnyDesk)",
                                     "Cryptocurrency mining pool connection"]),
            "category": "Policy Violation", "severity": rng.choice([2, 3, 4]),
            "src_ip": ip, "dst_ip": rng.choice(GREY_IPS), "dst_port": rng.choice([6881, 9001, 443]),
            "protocol": "tcp", "hostname": host, "username": rng.choice(USERS)}, \
        rng.random() < 0.1


def _dns(rng, ts):
    ip, host = _workstation(rng)
    real = rng.random() < 0.3
    domain = rng.choice(BAD_DOMAINS[3:]) if real else rng.choice(
        ["newsite-promo.example.net", "cdn-assets.example.org", "a1b2c3.example.com"])
    return {"timestamp": ts, "source": "DNS", "category": "Suspicious Domain",
            "signature": "DNS query to newly registered domain" if not real
            else rng.choice(["DNS query to DGA-like domain", "DNS tunneling suspected (long TXT)"]),
            "severity": rng.choice([4, 5, 6]), "src_ip": ip, "dst_ip": "10.0.0.10",
            "dst_port": 53, "protocol": "udp", "hostname": host, "domain": domain}, real


SCENARIOS = [
    Scenario("malware", 0.14, _malware),
    Scenario("brute_force", 0.16, _brute_force),
    Scenario("port_scan", 0.20, _port_scan),
    Scenario("phishing", 0.09, _phishing),
    Scenario("exploit", 0.11, _exploit),
    Scenario("exfil", 0.05, _exfil),
    Scenario("privilege", 0.05, _privilege),
    Scenario("policy", 0.10, _policy),
    Scenario("dns", 0.10, _dns),
]


def generate(count: int, seed: int = 1337, end: datetime | None = None,
             hours: int = 24) -> list[dict[str, Any]]:
    """Return ``count`` generic-JSON alert records, each with a ``label`` field."""
    # seeded PRNG on purpose: datasets must be reproducible (not used for crypto)
    rng = random.Random(seed)  # nosec B311
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    weights = [s.weight for s in SCENARIOS]
    records: list[dict[str, Any]] = []
    while len(records) < count:
        scenario = rng.choices(SCENARIOS, weights)[0]
        offset = rng.random() * hours * 3600
        ts = start + timedelta(seconds=offset)
        record, real = scenario.build(rng, ts)
        # True positives skew towards nights and weekends.
        if real and rng.random() < 0.35:
            night = ts.replace(hour=rng.choice([0, 1, 2, 3, 4, 22, 23]))
            if start <= night <= end:
                ts = night
        burst = record.pop("_burst", 1)
        for i in range(burst):
            if len(records) >= count:
                break
            item = {k: v for k, v in record.items() if v is not None}
            item["timestamp"] = (ts + timedelta(seconds=7 * i)).isoformat(timespec="seconds")
            item["label"] = "true_positive" if real else "false_positive"
            item["scenario"] = scenario.name
            records.append(item)
    records.sort(key=lambda r: r["timestamp"])
    return records


def write_jsonl(records: list[dict[str, Any]], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def write_sample_feed(path: str | Path) -> None:
    """Write the CSV feed that matches the generator's malicious infrastructure."""
    rows = ["indicator,type,score,tags,description"]
    rows += [f"203.0.113.{i},ip,85,c2;botnet,Known C2 infrastructure" for i in range(10, 40)]
    rows.append("203.0.113.40/29,ip,75,scanner;bruteforce,Aggressive SSH scanners")
    rows += [f"{d},domain,90,phishing;malware,Malicious domain" for d in BAD_DOMAINS]
    rows += [f"{h},sha256,95,malware,Known malware sample" for h in BAD_HASHES[:15]]
    rows += [f"{h},sha256,30,pua,Potentially unwanted application" for h in PUA_HASHES[:10]]
    Path(path).write_text("\n".join(rows) + "\n", encoding="utf-8")
