import pytest

from socprio.analysis.rules import Condition, RuleEngine, parse_rules
from socprio.analysis.scoring import RiskScorer
from socprio.config import ScoringSettings
from socprio.enrich.indicators import NetworkScope
from socprio.models import AssetInfo, IntelHit, Priority, Status

from helpers import make_alert

SCOPE = NetworkScope(["10.0.0.0/8"])


def _engine(*rules):
    return RuleEngine(parse_rules(list(rules)), SCOPE)


def test_rule_all_vs_any():
    conditions = [{"field": "severity", "op": "gte", "value": 9},
                  {"field": "alert_type", "op": "eq", "value": "Malware"}]
    alert = make_alert(severity=5)
    assert _engine({"id": "A", "name": "all", "conditions": conditions, "score": 5}) \
        .apply(alert).score == 0
    assert _engine({"id": "B", "name": "any", "match": "any", "conditions": conditions,
                    "score": 5}).apply(alert).score == 5


def test_rule_actions_tag_retype_and_autoclose():
    engine = _engine({
        "id": "R1", "name": "scanner", "score": -30, "auto_close": True, "tags": ["scanner"],
        "set_type": "Port Scan",
        "conditions": [{"field": "src_ip", "op": "cidr", "value": ["10.0.5.0/24"]}],
    })
    alert = make_alert(src_ip="10.0.5.5")
    result = engine.apply(alert)
    assert result.score == -30
    assert alert.status == Status.CLOSED
    assert alert.alert_type == "Port Scan"
    assert alert.tags == ["scanner", "auto-closed"]
    assert alert.rule_hits == ["R1: scanner"]


@pytest.mark.parametrize("op,value,field_value,expected", [
    ("regex", "beacon|c2", "Trojan Beacon", True),
    ("contains", "c2", ["c2", "botnet"], True),
    ("contains", "c", ["c2"], False),
    ("not_cidr", "10.0.0.0/8", "203.0.113.1", True),
    ("in", ["tcp", "udp"], "icmp", False),
    ("exists", True, None, False),
    ("gte", 5, None, False),
])
def test_operators(op, value, field_value, expected):
    assert Condition("x", op, value).evaluate({"x": field_value}) is expected


def test_invalid_rules_are_rejected():
    with pytest.raises(ValueError):
        Condition("x", "approximately", 1)
    with pytest.raises(ValueError):
        parse_rules([{"id": "A", "name": "a"}, {"id": "A", "name": "b"}])
    with pytest.raises(KeyError):
        _engine({"id": "A", "name": "a", "conditions": [{"field": "nope", "op": "eq"}]}) \
            .apply(make_alert())


def test_shipped_rules_file_loads():
    from conftest import ROOT

    engine = RuleEngine.from_file(ROOT / "config" / "rules.yaml", SCOPE)
    assert len(engine.rules) >= 10
    alert = make_alert(alert_type="Brute Force", occurrences=25, username="root")
    hits = engine.apply(alert).hits
    assert any(h.startswith("R004") for h in hits) and any(h.startswith("R005") for h in hits)


def test_score_without_model_renormalizes_weights():
    scorer = RiskScorer()
    alert = make_alert(severity=8)
    alert.asset = AssetInfo(name="dc", criticality=5)
    scorer.score(alert)
    # severity 0.8 * 35/55 + asset 1.0 * 20/55
    assert alert.risk_score == 87
    assert set(alert.score_breakdown) == {"severity", "asset"}
    assert alert.priority == Priority.CRITICAL


def test_score_breakdown_adds_up_and_clamps():
    scorer = RiskScorer()
    alert = make_alert(severity=2, occurrences=1)
    alert.ml_probability = 0.1
    scorer.score(alert, rule_adjustment=-50)
    assert alert.risk_score == 0
    assert alert.priority == Priority.LOW

    alert = make_alert(severity=6, occurrences=16)
    alert.ml_probability = 0.5
    scorer.score(alert, rule_adjustment=5)
    assert alert.score_breakdown["volume"] == 10.0
    assert alert.risk_score == round(sum(alert.score_breakdown.values()))


def test_agreeing_providers_raise_intel_factor():
    one = make_alert()
    one.intel = [IntelHit(provider="a", indicator="x", indicator_type="ip", score=60)]
    two = make_alert()
    two.intel = one.intel + [IntelHit(provider="b", indicator="x", indicator_type="ip", score=50)]
    assert RiskScorer.intel_factor(two) > RiskScorer.intel_factor(one)


def test_intel_only_ever_raises_the_score():
    scorer = RiskScorer()
    plain = scorer.score(make_alert(severity=5)).risk_score
    weak = make_alert(severity=5)
    weak.intel = [IntelHit(provider="a", indicator="x", indicator_type="ip", score=20)]
    strong = make_alert(severity=5)
    strong.intel = [IntelHit(provider="a", indicator="x", indicator_type="ip", score=95)]
    assert plain < scorer.score(weak).risk_score < scorer.score(strong).risk_score


def test_thresholds_must_be_ordered():
    with pytest.raises(ValueError):
        RiskScorer(ScoringSettings(thresholds={"critical": 50, "high": 60, "medium": 40}))
