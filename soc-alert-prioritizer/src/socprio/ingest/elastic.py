"""Pull alerts from an Elasticsearch / OpenSearch index.

Uses the plain REST API through httpx so no version-specific client library is
required. Documents are mapped with the generic parser, which already knows the
Elastic Common Schema field names (source.ip, rule.name, event.severity, ...).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

import httpx

from ..config import ElasticSettings
from ..models import Alert
from .parsers import parse_generic


class ElasticCollector:
    page_size = 500

    def __init__(self, settings: ElasticSettings, timeout: float = 15.0) -> None:
        auth = (settings.username, settings.password) if settings.username else None
        self.settings = settings
        self.client = httpx.Client(
            base_url=settings.url.rstrip("/"), auth=auth, verify=settings.verify_tls,
            timeout=timeout,
        )

    def fetch(self, since: datetime, until: datetime | None = None,
              query: str | None = None) -> Iterator[Alert]:
        until = until or datetime.now(timezone.utc)
        must: list[dict] = [{"range": {"@timestamp": {"gte": since.isoformat(),
                                                       "lte": until.isoformat()}}}]
        if query:
            must.append({"query_string": {"query": query}})
        body = {
            "size": self.page_size,
            "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
            "query": {"bool": {"must": must}},
        }
        search_after = None
        while True:
            if search_after:
                body["search_after"] = search_after
            response = self.client.post(f"/{self.settings.index}/_search", json=body)
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            if not hits:
                return
            for hit in hits:
                alert = parse_generic(hit.get("_source", {}), source="Elasticsearch")
                if alert is not None:
                    alert.raw.setdefault("_id", hit.get("_id"))
                    yield alert
            search_after = hits[-1].get("sort")
            if len(hits) < self.page_size or not search_after:
                return

    def close(self) -> None:
        self.client.close()
