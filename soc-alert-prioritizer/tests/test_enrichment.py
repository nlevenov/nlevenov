import httpx

from socprio.enrich import Enricher
from socprio.enrich.assets import AssetInventory
from socprio.enrich.cache import IntelCache
from socprio.enrich.indicators import Indicator, NetworkScope, extract_indicators
from socprio.enrich.providers import (
    AbuseIpdbProvider,
    CachedProvider,
    IntelProvider,
    LocalFeedProvider,
    VirusTotalProvider,
)

from helpers import BAD_HASH, make_alert

SCOPE = NetworkScope(["10.0.0.0/8"])


def test_internal_ips_are_not_indicators():
    alert = make_alert(domain="Evil.Test.", url="https://203.0.113.99/x",
                       file_hash=BAD_HASH.upper())
    values = {(i.value, i.kind) for i in extract_indicators(alert, SCOPE)}
    assert ("10.0.10.25", "ip") not in values
    assert ("203.0.113.10", "ip") in values
    assert ("evil.test", "domain") in values
    assert ("203.0.113.99", "ip") in values
    assert (BAD_HASH, "sha256") in values


def test_local_feed_exact_cidr_and_subdomain(settings):
    feed = LocalFeedProvider(settings.intel.feeds_dir)
    assert sorted(feed.loaded_files) == ["test_feed.csv", "tor_exit_nodes.txt"]
    assert feed.lookup(Indicator("203.0.113.10", "ip"))[0].tags == ["c2", "botnet"]
    assert feed.lookup(Indicator("203.0.113.70", "ip"))[0].score == 70
    assert feed.lookup(Indicator("login.evil.test", "domain"))[0].indicator == "login.evil.test"
    assert feed.lookup(Indicator("198.51.100.66", "ip"))[0].tags == ["tor-exit-nodes"]
    assert feed.lookup(Indicator("192.0.2.1", "ip")) == []


def test_asset_inventory_prefers_most_specific_and_most_critical():
    inventory = AssetInventory([
        {"name": "servers", "criticality": 3, "ips": ["10.0.1.0/24"]},
        {"name": "db", "criticality": 5, "ips": ["10.0.1.20/32"]},
        {"name": "laptops", "criticality": 2, "hostnames": ["wks-*"]},
    ])
    assert inventory.lookup_ip("10.0.1.20").name == "db"
    assert inventory.lookup_ip("10.0.1.21").name == "servers"
    assert inventory.lookup_host("WKS-001").name == "laptops"
    alert = make_alert(src_ip="10.0.10.5", dst_ip="10.0.1.20", hostname="wks-001")
    assert inventory.resolve(alert).name == "db"


def test_enricher_attaches_intel_and_asset(settings):
    enricher = Enricher.from_settings(settings)
    alert = enricher.enrich(make_alert(dst_ip="203.0.113.10", src_ip="10.0.1.30"))
    assert alert.max_intel_score == 85
    assert alert.asset is not None and alert.asset.name == "Public web server"


class _Boom(IntelProvider):
    name = "boom"
    calls = 0

    def lookup(self, indicator):
        self.calls += 1
        raise httpx.ConnectError("down")


def test_cached_provider_isolates_failures():
    inner = _Boom()
    provider = CachedProvider(inner, IntelCache(":memory:"))
    assert provider.lookup(Indicator("203.0.113.1", "ip")) == []
    assert provider.errors == 1


def test_cached_provider_caches_results():
    class Counting(IntelProvider):
        name = "counting"
        calls = 0

        def lookup(self, indicator):
            self.calls += 1
            return []

    inner = Counting()
    provider = CachedProvider(inner, IntelCache(":memory:"))
    provider.lookup(Indicator("203.0.113.1", "ip"))
    provider.lookup(Indicator("203.0.113.1", "ip"))
    assert inner.calls == 1


def _mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.test")


def test_abuseipdb_mapping():
    provider = AbuseIpdbProvider("key")
    provider.client = _mock_client(lambda request: httpx.Response(200, json={"data": {
        "abuseConfidenceScore": 97, "totalReports": 312, "isTor": True,
        "isp": "Example ISP", "countryCode": "NL"}}))
    hits = provider.lookup(Indicator("203.0.113.5", "ip"))
    assert hits[0].score == 97 and hits[0].tags == ["tor"]
    assert not provider.supports(Indicator("10.0.0.1", "ip"))


def test_virustotal_mapping_and_not_found():
    def handler(request):
        if request.url.path.endswith("/unknown"):
            return httpx.Response(404)
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 2, "harmless": 20,
                                    "undetected": 10},
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"}}}})

    provider = VirusTotalProvider("key")
    provider.client = _mock_client(handler)
    hits = provider.lookup(Indicator(BAD_HASH, "sha256"))
    assert hits[0].score == 100 and hits[0].tags == ["trojan.emotet"]
    assert provider.lookup(Indicator("unknown", "domain")) == []
