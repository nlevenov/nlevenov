"""Asset inventory lookup - the same alert matters more on a domain controller."""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from ..models import Alert, AssetInfo


class AssetInventory:
    def __init__(self, assets: list[dict[str, Any]] | None = None) -> None:
        self._by_network: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, AssetInfo]] = []
        self._by_host: list[tuple[str, AssetInfo]] = []
        for entry in assets or []:
            info = AssetInfo(
                name=entry["name"],
                criticality=int(entry.get("criticality", 2)),
                owner=entry.get("owner", ""),
                tags=list(entry.get("tags", [])),
            )
            for net in entry.get("ips", []):
                self._by_network.append((ipaddress.ip_network(net, strict=False), info))
            for pattern in entry.get("hostnames", []):
                self._by_host.append((pattern.lower(), info))
        # Most specific network first, so a /32 overrides the /24 it lives in.
        self._by_network.sort(key=lambda item: item[0].prefixlen, reverse=True)

    @classmethod
    def from_file(cls, path: str | Path) -> AssetInventory:
        path = Path(path)
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(data.get("assets", []))

    def lookup_ip(self, value: str | None) -> AssetInfo | None:
        if not value:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        for network, info in self._by_network:
            if address.version == network.version and address in network:
                return info
        return None

    def lookup_host(self, hostname: str | None) -> AssetInfo | None:
        if not hostname:
            return None
        hostname = hostname.lower()
        for pattern, info in self._by_host:
            if fnmatch.fnmatch(hostname, pattern):
                return info
        return None

    def resolve(self, alert: Alert) -> AssetInfo | None:
        """Pick the most critical asset involved in the alert."""
        candidates = [
            self.lookup_host(alert.hostname),
            self.lookup_ip(alert.dst_ip),
            self.lookup_ip(alert.src_ip),
        ]
        found = [c for c in candidates if c is not None]
        return max(found, key=lambda a: a.criticality) if found else None
