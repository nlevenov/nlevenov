"""Extract observables (IOCs) from a normalized alert."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..models import Alert

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str  # ip | domain | url | md5 | sha1 | sha256

    @property
    def is_hash(self) -> bool:
        return self.kind in _HASH_TYPES.values()


class NetworkScope:
    """Knows which addresses belong to the organisation."""

    def __init__(self, internal_networks: list[str]) -> None:
        self.networks = [ipaddress.ip_network(net, strict=False) for net in internal_networks]

    def is_internal(self, value: str | None) -> bool:
        if not value:
            return False
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in net for net in self.networks)

    @staticmethod
    def is_public(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.is_global


def hash_kind(value: str) -> str | None:
    if _HEX.match(value):
        return _HASH_TYPES.get(len(value))
    return None


def extract_indicators(alert: Alert, scope: NetworkScope) -> list[Indicator]:
    found: dict[str, Indicator] = {}

    for ip in (alert.src_ip, alert.dst_ip):
        if ip and not scope.is_internal(ip):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            found[ip] = Indicator(ip, "ip")

    if alert.domain:
        domain = alert.domain.lower().rstrip(".")
        found[domain] = Indicator(domain, "domain")
    if alert.url:
        found[alert.url] = Indicator(alert.url, "url")
        host = urlparse(alert.url).hostname
        if host and host not in found:
            try:
                ipaddress.ip_address(host)
                found[host] = Indicator(host, "ip")
            except ValueError:
                found[host] = Indicator(host.lower(), "domain")
    if alert.file_hash:
        value = alert.file_hash.lower()
        kind = hash_kind(value)
        if kind:
            found[value] = Indicator(value, kind)

    return list(found.values())
