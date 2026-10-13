"""Settings loaded from YAML with ${ENV_VAR} expansion.

Lookup order for the config file:
  1. explicit path passed to ``load_settings``
  2. ``SOCPRIO_CONFIG`` environment variable
  3. ``config/settings.yaml`` relative to the working directory
Anything missing falls back to the defaults below, so the tool runs with no
config at all.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


@dataclass
class ScoringSettings:
    # Weights of the base factors. They are re-normalized at runtime, so they
    # do not have to add up to 100, and a missing factor (no model) drops out.
    weights: dict[str, float] = field(
        default_factory=lambda: {"severity": 35, "asset": 20, "ml": 45}
    )
    # Share of the remaining headroom a 100/100 intel verdict closes.
    intel_weight: float = 0.7
    volume_bonus_max: float = 10.0
    thresholds: dict[str, int] = field(
        default_factory=lambda: {"critical": 80, "high": 60, "medium": 40}
    )


@dataclass
class MispSettings:
    enabled: bool = False
    url: str = ""
    api_key: str = ""
    verify_tls: bool = True


@dataclass
class ApiProviderSettings:
    enabled: bool = False
    api_key: str = ""


@dataclass
class IntelSettings:
    feeds_dir: str = "feeds"
    cache_ttl_hours: int = 24
    timeout_seconds: float = 8.0
    misp: MispSettings = field(default_factory=MispSettings)
    abuseipdb: ApiProviderSettings = field(default_factory=ApiProviderSettings)
    virustotal: ApiProviderSettings = field(default_factory=ApiProviderSettings)


@dataclass
class NotifySettings:
    webhook_url: str = ""
    min_priority: str = "critical"


@dataclass
class ElasticSettings:
    url: str = "http://localhost:9200"
    index: str = "alerts-*"
    username: str = ""
    password: str = ""
    verify_tls: bool = True


@dataclass
class Settings:
    database: str = "var/socprio.db"
    model_path: str = "models/classifier.joblib"
    rules_path: str = "config/rules.yaml"
    assets_path: str = "config/assets.yaml"
    internal_networks: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )
    dedup_window_minutes: int = 30
    api_key: str = ""
    # HMAC key for the model file. Loading a joblib file executes code, so a
    # model whose signature does not verify is refused.
    model_signing_key: str = ""
    # Host headers the web app answers to. Empty = loopback only without an
    # API key, any host with one. Set it when serving behind a proxy.
    allowed_hosts: list[str] = field(default_factory=list)
    scoring: ScoringSettings = field(default_factory=ScoringSettings)
    intel: IntelSettings = field(default_factory=IntelSettings)
    notify: NotifySettings = field(default_factory=NotifySettings)
    elastic: ElasticSettings = field(default_factory=ElasticSettings)


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _coerce(value: str, type_name: str) -> Any:
    """Env-expanded values arrive as strings; convert them to the declared type."""
    if type_name == "bool":
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    return value


def _build(cls: type, data: dict[str, Any]) -> Any:
    kwargs = {}
    known = {f.name: f for f in fields(cls)}
    for key, value in (data or {}).items():
        if key not in known:
            raise ValueError(f"unknown setting '{key}' in section {cls.__name__}")
        default = known[key].default_factory() if callable(known[key].default_factory) else None
        if is_dataclass(default) and isinstance(value, dict):
            value = _build(type(default), value)
        elif isinstance(value, str):
            value = _coerce(value, str(known[key].type))
        kwargs[key] = value
    return cls(**kwargs)


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    candidate = path or os.environ.get("SOCPRIO_CONFIG") or "config/settings.yaml"
    config_path = Path(candidate)
    if not config_path.exists():
        if path:
            raise FileNotFoundError(config_path)
        return Settings()
    with config_path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    settings = _build(Settings, _expand_env(raw))
    if os.environ.get("SOCPRIO_DATABASE"):
        settings.database = os.environ["SOCPRIO_DATABASE"]
    return settings
