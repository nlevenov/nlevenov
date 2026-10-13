"""Declarative triage rules (YAML).

A rule looks like::

    - id: R010
      name: Known-bad indicator on a critical asset
      match: all                 # all | any
      conditions:
        - {field: intel_score, op: gte, value: 70}
        - {field: asset_criticality, op: gte, value: 4}
      score: 25                  # added to the risk score (may be negative)
      tags: [escalate]
      set_type: Malware          # optional: override alert_type
      auto_close: false          # optional: close as known noise

Rules are evaluated in file order and every matching rule applies.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..enrich.indicators import NetworkScope
from ..models import Alert, Status
from .context import alert_context


def _in_cidr(value: Any, networks: Any) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    nets = networks if isinstance(networks, list) else [networks]
    return any(address in ipaddress.ip_network(n, strict=False) for n in nets)


def _contains(value: Any, needle: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(str(needle).lower() == str(v).lower() for v in value)
    return str(needle).lower() in str(value).lower()


OPERATORS = {
    "eq": lambda v, x: v == x,
    "ne": lambda v, x: v != x,
    "gt": lambda v, x: v is not None and v > x,
    "gte": lambda v, x: v is not None and v >= x,
    "lt": lambda v, x: v is not None and v < x,
    "lte": lambda v, x: v is not None and v <= x,
    "in": lambda v, x: v in x,
    "not_in": lambda v, x: v not in x,
    "contains": _contains,
    "not_contains": lambda v, x: not _contains(v, x),
    "regex": lambda v, x: v is not None and re.search(x, str(v), re.I) is not None,
    "cidr": _in_cidr,
    "not_cidr": lambda v, x: v is not None and not _in_cidr(v, x),
    "exists": lambda v, x: (v not in (None, "", [])) == bool(x),
}


@dataclass
class Condition:
    field: str
    op: str
    value: Any = True

    def __post_init__(self) -> None:
        if self.op not in OPERATORS:
            raise ValueError(f"unknown operator '{self.op}' (valid: {', '.join(OPERATORS)})")
        if self.op == "regex":
            re.compile(self.value)

    def evaluate(self, ctx: dict[str, Any]) -> bool:
        if self.field not in ctx:
            raise KeyError(f"unknown field '{self.field}' in rule condition")
        return OPERATORS[self.op](ctx[self.field], self.value)


@dataclass
class Rule:
    id: str
    name: str
    conditions: list[Condition]
    match: str = "all"
    score: int = 0
    tags: list[str] = field(default_factory=list)
    set_type: str | None = None
    auto_close: bool = False
    enabled: bool = True

    def matches(self, ctx: dict[str, Any]) -> bool:
        results = (c.evaluate(ctx) for c in self.conditions)
        return all(results) if self.match == "all" else any(results)


@dataclass
class RuleResult:
    score: int = 0
    hits: list[str] = field(default_factory=list)


class RuleEngine:
    def __init__(self, rules: list[Rule], scope: NetworkScope) -> None:
        self.rules = [r for r in rules if r.enabled]
        self.scope = scope

    @classmethod
    def from_file(cls, path: str | Path, scope: NetworkScope) -> RuleEngine:
        path = Path(path)
        if not path.exists():
            return cls([], scope)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(parse_rules(data.get("rules", [])), scope)

    def apply(self, alert: Alert) -> RuleResult:
        result = RuleResult()
        ctx = alert_context(alert, self.scope)
        for rule in self.rules:
            if not rule.matches(ctx):
                continue
            result.score += rule.score
            result.hits.append(f"{rule.id}: {rule.name}")
            for tag in rule.tags:
                if tag not in alert.tags:
                    alert.tags.append(tag)
            if rule.set_type:
                alert.alert_type = rule.set_type
                ctx["alert_type"] = rule.set_type
            if rule.auto_close:
                alert.status = Status.CLOSED
                if "auto-closed" not in alert.tags:
                    alert.tags.append("auto-closed")
        alert.rule_hits = result.hits
        return result


def parse_rules(raw_rules: list[dict[str, Any]]) -> list[Rule]:
    rules, seen = [], set()
    for raw in raw_rules:
        if raw["id"] in seen:
            raise ValueError(f"duplicate rule id {raw['id']}")
        seen.add(raw["id"])
        match = raw.get("match", "all")
        if match not in ("all", "any"):
            raise ValueError(f"rule {raw['id']}: match must be 'all' or 'any'")
        rules.append(Rule(
            id=raw["id"],
            name=raw["name"],
            conditions=[Condition(**c) for c in raw.get("conditions", [])],
            match=match,
            score=int(raw.get("score", 0)),
            tags=list(raw.get("tags", [])),
            set_type=raw.get("set_type"),
            auto_close=bool(raw.get("auto_close", False)),
            enabled=bool(raw.get("enabled", True)),
        ))
    return rules
