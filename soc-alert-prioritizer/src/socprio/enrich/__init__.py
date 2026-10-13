"""Enrichment: threat intelligence and asset context."""

from __future__ import annotations

from ..config import Settings
from ..models import Alert
from .assets import AssetInventory
from .cache import IntelCache
from .indicators import NetworkScope, extract_indicators
from .providers import (
    AbuseIpdbProvider,
    CachedProvider,
    IntelProvider,
    LocalFeedProvider,
    MispProvider,
    VirusTotalProvider,
)


class Enricher:
    def __init__(self, providers: list[IntelProvider], assets: AssetInventory,
                 scope: NetworkScope) -> None:
        self.providers = providers
        self.assets = assets
        self.scope = scope

    @classmethod
    def from_settings(cls, settings: Settings) -> Enricher:
        intel = settings.intel
        providers: list[IntelProvider] = [LocalFeedProvider(intel.feeds_dir)]
        remote: list[IntelProvider] = []
        if intel.misp.enabled and intel.misp.url and intel.misp.api_key:
            remote.append(MispProvider(intel.misp.url, intel.misp.api_key,
                                       intel.misp.verify_tls, intel.timeout_seconds))
        if intel.abuseipdb.enabled and intel.abuseipdb.api_key:
            remote.append(AbuseIpdbProvider(intel.abuseipdb.api_key, intel.timeout_seconds))
        if intel.virustotal.enabled and intel.virustotal.api_key:
            remote.append(VirusTotalProvider(intel.virustotal.api_key, intel.timeout_seconds))
        if remote:
            cache = IntelCache(settings.database, intel.cache_ttl_hours)
            providers += [CachedProvider(p, cache) for p in remote]
        return cls(providers, AssetInventory.from_file(settings.assets_path),
                   NetworkScope(settings.internal_networks))

    def enrich(self, alert: Alert) -> Alert:
        hits = []
        for indicator in extract_indicators(alert, self.scope):
            for provider in self.providers:
                if provider.supports(indicator):
                    hits.extend(provider.lookup(indicator))
        alert.intel = hits
        alert.asset = self.assets.resolve(alert)
        return alert


__all__ = ["AssetInventory", "Enricher", "NetworkScope"]
