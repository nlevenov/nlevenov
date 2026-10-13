"""Risk scoring.

1. A base score is a weighted blend of normalized factors (each 0..1):

       severity  vendor severity / 10
       asset     business criticality of the affected asset
       ml        model probability that the alert is a true positive

   Factors that are unavailable (no model trained yet) drop out and the
   remaining weights are re-normalized, so the scale stays 0-100.

2. Threat intelligence is applied as an uplift that closes part of the gap
   between the base score and 100:

       score = base + (100 - base) * intel_weight * intel_factor

   Intel can only raise a score. A missing match is not evidence that an
   alert is benign - feeds never cover everything - so an alert without
   matches is not penalized.

3. A volume bonus for repeated activity and the triage-rule adjustments are
   added on top, and the result is clamped to 0-100.

Every contribution is stored in ``score_breakdown`` so an analyst can see why
an alert landed where it did.
"""

from __future__ import annotations

import math

from ..config import ScoringSettings
from ..models import Alert, Priority


class RiskScorer:
    def __init__(self, settings: ScoringSettings | None = None) -> None:
        self.settings = settings or ScoringSettings()
        thresholds = self.settings.thresholds
        if not thresholds["critical"] > thresholds["high"] > thresholds["medium"]:
            raise ValueError("priority thresholds must be strictly decreasing")

    def factors(self, alert: Alert) -> dict[str, float]:
        factors = {
            "severity": alert.severity / 10,
            "asset": (alert.asset_criticality - 1) / 4,
        }
        if alert.ml_probability is not None:
            factors["ml"] = alert.ml_probability
        return factors

    @staticmethod
    def intel_factor(alert: Alert) -> float:
        if not alert.intel:
            return 0.0
        base = alert.max_intel_score / 100
        providers = len({hit.provider for hit in alert.intel})
        # independent sources confirming the same verdict raise confidence
        return min(1.0, base + 0.05 * (providers - 1))

    def score(self, alert: Alert, rule_adjustment: int = 0) -> Alert:
        factors = self.factors(alert)
        weights = {k: v for k, v in self.settings.weights.items() if k in factors}
        total_weight = sum(weights.values()) or 1.0

        breakdown = {
            name: round(100 * weights[name] / total_weight * factors[name], 1)
            for name in weights
        }
        base = sum(breakdown.values())
        intel = (100 - base) * self.settings.intel_weight * self.intel_factor(alert)
        if intel:
            breakdown["intel"] = round(intel, 1)
        volume = min(self.settings.volume_bonus_max, 2.5 * math.log2(max(alert.occurrences, 1)))
        if volume:
            breakdown["volume"] = round(volume, 1)
        if rule_adjustment:
            breakdown["rules"] = float(rule_adjustment)

        alert.risk_score = int(round(max(0.0, min(100.0, sum(breakdown.values())))))
        alert.score_breakdown = breakdown
        alert.priority = self.priority_for(alert.risk_score)
        return alert

    def priority_for(self, score: int) -> Priority:
        thresholds = self.settings.thresholds
        if score >= thresholds["critical"]:
            return Priority.CRITICAL
        if score >= thresholds["high"]:
            return Priority.HIGH
        if score >= thresholds["medium"]:
            return Priority.MEDIUM
        return Priority.LOW
