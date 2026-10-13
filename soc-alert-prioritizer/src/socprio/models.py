"""Core data model shared by every stage of the pipeline."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# Upper bounds for free-text fields. Log content is attacker-influenced, so
# nothing from it is stored unbounded.
MAX_TEXT = {"signature": 1024, "url": 2048, "domain": 253, "hostname": 255,
            "username": 256, "source": 128, "alert_type": 64, "protocol": 16,
            "file_hash": 128}
# Sensors with a broken clock (or forged events) must not pin an alert to
# the top of "most recent" forever.
MAX_CLOCK_SKEW = timedelta(hours=1)


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Status(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    MONITORING = "monitoring"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class Verdict(str, Enum):
    """Analyst verdict. Feeds back into model training."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"


class IntelHit(BaseModel):
    provider: str
    indicator: str
    indicator_type: str
    score: int = Field(ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    description: str = ""


class AssetInfo(BaseModel):
    name: str
    criticality: int = Field(default=2, ge=1, le=5)
    owner: str = ""
    tags: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    # --- normalized event fields -------------------------------------------
    timestamp: datetime
    source: str
    alert_type: str = "Unknown"
    signature: str = ""
    severity: float = Field(default=5.0, ge=0, le=10)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    hostname: str | None = None
    username: str | None = None
    domain: str | None = None
    url: str | None = None
    file_hash: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    # --- added by the pipeline ---------------------------------------------
    id: str = ""
    fingerprint: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    occurrences: int = 1
    intel: list[IntelHit] = Field(default_factory=list)
    asset: AssetInfo | None = None
    rule_hits: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    ml_probability: float | None = None
    risk_score: int = 0
    priority: Priority = Priority.LOW
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    status: Status = Status.NEW
    verdict: Verdict | None = None
    notes: str = ""

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _valid_ip(cls, value: Any) -> str | None:
        """Keep only real IP addresses; the original value survives in ``raw``."""
        if value is None or value == "":
            return None
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            return None

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def _valid_port(cls, value: Any) -> int | None:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        return port if 0 <= port <= 65535 else None

    @field_validator(*MAX_TEXT, mode="before")
    @classmethod
    def _bounded_text(cls, value: Any, info: Any) -> Any:
        if isinstance(value, str):
            value = "".join(ch for ch in value if ch.isprintable())
            return value[:MAX_TEXT[info.field_name]]
        return value

    def model_post_init(self, __context: Any) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if self.timestamp > now + MAX_CLOCK_SKEW:
            self.raw.setdefault("original_timestamp", self.timestamp.isoformat())
            self.timestamp = now
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if self.first_seen is None:
            self.first_seen = self.timestamp
        if self.last_seen is None:
            self.last_seen = self.timestamp

    def compute_fingerprint(self) -> str:
        """Alerts sharing a fingerprint are treated as repeats of the same activity."""
        key = "|".join(
            str(part or "")
            for part in (self.source, self.signature or self.alert_type, self.src_ip, self.dst_ip)
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def max_intel_score(self) -> int:
        return max((hit.score for hit in self.intel), default=0)

    @property
    def intel_tags(self) -> list[str]:
        return sorted({tag for hit in self.intel for tag in hit.tags})

    @property
    def asset_criticality(self) -> int:
        return self.asset.criticality if self.asset else 2
