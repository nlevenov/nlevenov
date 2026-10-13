"""Threat intelligence providers.

Each provider answers one question: "what do you know about this indicator?"
and returns zero or more ``IntelHit`` objects scored 0-100. Network providers
are wrapped by ``CachedProvider`` and never raise - an outage of one feed must
not stop alert processing.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from abc import ABC, abstractmethod
from pathlib import Path

import httpx

from ..models import IntelHit
from .cache import IntelCache
from .indicators import Indicator, NetworkScope, hash_kind

log = logging.getLogger(__name__)


class IntelProvider(ABC):
    name: str = "provider"
    supported: frozenset[str] = frozenset({"ip", "domain", "url", "md5", "sha1", "sha256"})

    def supports(self, indicator: Indicator) -> bool:
        return indicator.kind in self.supported

    @abstractmethod
    def lookup(self, indicator: Indicator) -> list[IntelHit]: ...


# --------------------------------------------------------------------------
# Local feeds
# --------------------------------------------------------------------------

class LocalFeedProvider(IntelProvider):
    """Reads blocklists from a directory.

    * ``*.txt`` - one indicator (or CIDR) per line, ``#`` comments allowed.
      The file name becomes the tag, e.g. ``tor_exit_nodes.txt``.
    * ``*.csv`` - columns ``indicator,type,score,tags,description`` with
      ``tags`` separated by ``;``.
    """

    name = "local-feed"
    default_score = 70

    def __init__(self, feeds_dir: str | Path) -> None:
        self.exact: dict[str, list[IntelHit]] = {}
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IntelHit]] = []
        self.loaded_files: list[str] = []
        directory = Path(feeds_dir)
        if directory.is_dir():
            for path in sorted(directory.iterdir()):
                if path.suffix == ".txt":
                    self._load_txt(path)
                elif path.suffix == ".csv":
                    self._load_csv(path)

    def _add(self, value: str, kind: str, score: int, tags: list[str], description: str) -> None:
        value = value.strip().lower()
        hit = IntelHit(provider=self.name, indicator=value, indicator_type=kind, score=score,
                       tags=tags, description=description)
        if kind == "ip" and "/" in value:
            self.networks.append((ipaddress.ip_network(value, strict=False), hit))
        else:
            self.exact.setdefault(value, []).append(hit)

    def _load_txt(self, path: Path) -> None:
        tag = path.stem.replace("_", "-")
        description = f"listed in {path.name}"
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                self._add(value, _guess_kind(value), self.default_score, [tag], description)
        self.loaded_files.append(path.name)

    def _load_csv(self, path: Path) -> None:
        with path.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                value = (row.get("indicator") or "").strip()
                if not value or value.startswith("#"):
                    continue
                self._add(
                    value,
                    row.get("type") or _guess_kind(value),
                    int(row.get("score") or self.default_score),
                    [t.strip() for t in (row.get("tags") or "").split(";") if t.strip()],
                    row.get("description") or f"listed in {path.name}",
                )
        self.loaded_files.append(path.name)

    def lookup(self, indicator: Indicator) -> list[IntelHit]:
        value = indicator.value.lower()
        matches = list(self.exact.get(value, []))
        if indicator.kind == "domain":
            # a listed parent domain also covers its subdomains
            labels = value.split(".")
            for i in range(1, len(labels) - 1):
                matches += self.exact.get(".".join(labels[i:]), [])
        if indicator.kind == "ip" and self.networks:
            address = ipaddress.ip_address(value)
            matches += [hit for net, hit in self.networks
                        if address.version == net.version and address in net]
        return [hit.model_copy(update={"indicator": value}) for hit in matches]

    def __len__(self) -> int:
        return sum(len(v) for v in self.exact.values()) + len(self.networks)


def _guess_kind(value: str) -> str:
    if hash_kind(value.lower()):
        return hash_kind(value.lower())  # type: ignore[return-value]
    try:
        ipaddress.ip_network(value, strict=False)
        return "ip"
    except ValueError:
        pass
    return "url" if "://" in value else "domain"


# --------------------------------------------------------------------------
# Remote providers
# --------------------------------------------------------------------------

class MispProvider(IntelProvider):
    """Queries a MISP instance through /attributes/restSearch."""

    name = "misp"
    _threat_level_score = {"1": 90, "2": 70, "3": 45, "4": 25}  # high, medium, low, undefined

    def __init__(self, url: str, api_key: str, verify_tls: bool = True,
                 timeout: float = 8.0) -> None:
        self.client = httpx.Client(
            base_url=url.rstrip("/"), verify=verify_tls, timeout=timeout,
            headers={"Authorization": api_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
        )

    def lookup(self, indicator: Indicator) -> list[IntelHit]:
        response = self.client.post("/attributes/restSearch", json={
            "returnFormat": "json", "value": indicator.value, "to_ids": True,
            "includeEventTags": True, "limit": 20,
        })
        response.raise_for_status()
        attributes = response.json().get("response", {}).get("Attribute", [])
        hits = []
        for attr in attributes:
            event = attr.get("Event", {})
            tags = sorted({t["name"] for t in attr.get("Tag", []) + event.get("Tag", [])
                           if "name" in t})
            score = self._threat_level_score.get(str(event.get("threat_level_id")), 50)
            hits.append(IntelHit(
                provider=self.name, indicator=indicator.value, indicator_type=indicator.kind,
                score=score, tags=tags[:10],
                description=f"MISP event {event.get('id')}: {event.get('info', '')}".strip(),
            ))
        return hits


class AbuseIpdbProvider(IntelProvider):
    name = "abuseipdb"
    supported = frozenset({"ip"})

    def __init__(self, api_key: str, timeout: float = 8.0) -> None:
        self.client = httpx.Client(
            base_url="https://api.abuseipdb.com/api/v2", timeout=timeout,
            headers={"Key": api_key, "Accept": "application/json"},
        )

    def supports(self, indicator: Indicator) -> bool:
        return indicator.kind == "ip" and NetworkScope.is_public(indicator.value)

    def lookup(self, indicator: Indicator) -> list[IntelHit]:
        response = self.client.get("/check", params={"ipAddress": indicator.value,
                                                     "maxAgeInDays": 90})
        response.raise_for_status()
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore") or 0)
        if score == 0:
            return []
        tags = ["tor"] if data.get("isTor") else []
        return [IntelHit(
            provider=self.name, indicator=indicator.value, indicator_type="ip", score=score,
            tags=tags,
            description=f"{data.get('totalReports', 0)} reports, "
                        f"ISP {data.get('isp') or 'unknown'}, {data.get('countryCode') or '??'}",
        )]


class VirusTotalProvider(IntelProvider):
    name = "virustotal"
    _endpoint = {"ip": "ip_addresses", "domain": "domains",
                 "md5": "files", "sha1": "files", "sha256": "files"}
    supported = frozenset(_endpoint)

    def __init__(self, api_key: str, timeout: float = 8.0) -> None:
        self.client = httpx.Client(
            base_url="https://www.virustotal.com/api/v3", timeout=timeout,
            headers={"x-apikey": api_key},
        )

    def supports(self, indicator: Indicator) -> bool:
        if indicator.kind == "ip":
            return NetworkScope.is_public(indicator.value)
        return indicator.kind in self.supported

    def lookup(self, indicator: Indicator) -> list[IntelHit]:
        response = self.client.get(f"/{self._endpoint[indicator.kind]}/{indicator.value}")
        if response.status_code == 404:
            return []
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        if malicious + suspicious == 0:
            return []
        # A handful of engines flagging something is already significant.
        score = min(100, int(40 + 60 * (malicious + 0.5 * suspicious) / max(total * 0.3, 1)))
        label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        return [IntelHit(
            provider=self.name, indicator=indicator.value, indicator_type=indicator.kind,
            score=score, tags=[label] if label else [],
            description=f"{malicious}/{total} engines malicious",
        )]


class CachedProvider(IntelProvider):
    """Adds caching and error isolation around a remote provider."""

    def __init__(self, inner: IntelProvider, cache: IntelCache) -> None:
        self.inner = inner
        self.cache = cache
        self.name = inner.name
        self.errors = 0

    def supports(self, indicator: Indicator) -> bool:
        return self.inner.supports(indicator)

    def lookup(self, indicator: Indicator) -> list[IntelHit]:
        cached = self.cache.get(self.name, indicator.value)
        if cached is not None:
            return [IntelHit(**item) for item in cached]
        try:
            hits = self.inner.lookup(indicator)
        except (httpx.HTTPError, ValueError) as exc:
            self.errors += 1
            log.warning("%s lookup for %s failed: %s", self.name, indicator.value, exc)
            return []
        self.cache.put(self.name, indicator.value, [h.model_dump() for h in hits])
        return hits
