"""Supervised model that estimates P(true positive) for an alert.

The model learns from analyst verdicts: every alert closed as a true or false
positive becomes a training sample, so prioritization improves with use.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from ..enrich.indicators import NetworkScope
from ..models import Alert
from .context import alert_context

log = logging.getLogger(__name__)

FEATURE_VERSION = 2
NUMERIC = [
    "severity", "intel_score", "intel_hits", "intel_providers", "asset_criticality",
    "log_occurrences", "src_internal", "dst_internal", "sensitive_port", "off_hours",
    "privileged_user", "has_hash", "has_domain", "hour",
]
CATEGORICAL = ["alert_type", "source", "protocol"]
TEXT = "signature"


def build_frame(alerts: list[Alert], scope: NetworkScope) -> pd.DataFrame:
    rows = []
    for alert in alerts:
        ctx = alert_context(alert, scope)
        rows.append({
            **{k: float(ctx[k]) for k in (
                "severity", "intel_score", "intel_hits", "intel_providers",
                "asset_criticality", "src_internal", "dst_internal", "sensitive_port",
                "off_hours", "privileged_user", "hour")},
            "log_occurrences": math.log1p(alert.occurrences),
            "has_hash": float(bool(alert.file_hash)),
            "has_domain": float(bool(alert.domain)),
            "alert_type": alert.alert_type or "Unknown",
            "source": alert.source or "unknown",
            "protocol": alert.protocol or "none",
            "signature": alert.signature or "",
        })
    return pd.DataFrame(rows, columns=NUMERIC + CATEGORICAL + [TEXT])


def _new_pipeline(seed: int) -> Pipeline:
    features = ColumnTransformer([
        ("num", "passthrough", NUMERIC),
        ("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=3), CATEGORICAL),
        ("txt", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=3000,
                                sublinear_tf=True), TEXT),
    ])
    model = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=seed,
    )
    return Pipeline([("features", features), ("model", model)])


@dataclass
class TrainReport:
    samples: int
    positives: int
    precision: float
    recall: float
    f1: float
    roc_auc: float

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class AlertClassifier:
    def __init__(self, pipeline: Pipeline, scope: NetworkScope,
                 metadata: dict[str, Any] | None = None) -> None:
        self.pipeline = pipeline
        self.scope = scope
        self.metadata = metadata or {}

    # ------------------------------------------------------------------ train
    @classmethod
    def train(cls, alerts: list[Alert], labels: list[bool], scope: NetworkScope,
              seed: int = 42, holdout: float = 0.2) -> tuple[AlertClassifier, TrainReport]:
        if len(alerts) != len(labels):
            raise ValueError("alerts and labels must have the same length")
        y = np.asarray(labels, dtype=int)
        if len(set(y)) < 2:
            raise ValueError("training data needs both true and false positives")
        if len(alerts) < 50:
            raise ValueError(f"need at least 50 labelled alerts to train (got {len(alerts)})")

        frame = build_frame(alerts, scope)
        x_train, x_test, y_train, y_test = train_test_split(
            frame, y, test_size=holdout, stratify=y, random_state=seed,
        )
        pipeline = _new_pipeline(seed).fit(x_train, y_train)
        proba = pipeline.predict_proba(x_test)[:, 1]
        pred = (proba >= 0.5).astype(int)
        report = TrainReport(
            samples=len(y), positives=int(y.sum()),
            precision=round(float(precision_score(y_test, pred, zero_division=0)), 4),
            recall=round(float(recall_score(y_test, pred, zero_division=0)), 4),
            f1=round(float(f1_score(y_test, pred, zero_division=0)), 4),
            roc_auc=round(float(roc_auc_score(y_test, proba)), 4),
        )
        # Refit on everything once the holdout score is known.
        pipeline = _new_pipeline(seed).fit(frame, y)
        metadata = {
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "feature_version": FEATURE_VERSION,
            "sklearn_version": sklearn.__version__,
            "holdout": report.as_dict(),
        }
        return cls(pipeline, scope, metadata), report

    # ---------------------------------------------------------------- predict
    def predict_proba(self, alerts: list[Alert]) -> list[float]:
        if not alerts:
            return []
        frame = build_frame(alerts, self.scope)
        return [round(float(p), 4) for p in self.pipeline.predict_proba(frame)[:, 1]]

    def top_features(self, n: int = 15) -> list[tuple[str, float]]:
        names = self.pipeline.named_steps["features"].get_feature_names_out()
        importances = self.pipeline.named_steps["model"].feature_importances_
        order = np.argsort(importances)[::-1][:n]
        return [(str(names[i]).split("__", 1)[-1], round(float(importances[i]), 4))
                for i in order]

    # ------------------------------------------------------------ persistence
    # joblib files are pickles: loading one runs arbitrary code. Every saved
    # model gets a detached signature and nothing is unpickled unless it
    # verifies. With a signing key the signature is an HMAC, which also stops
    # an attacker who can write to the model directory; without one it is a
    # plain SHA-256 that only catches corruption and accidental swaps.

    @staticmethod
    def _digest(data: bytes, signing_key: str) -> tuple[str, str]:
        if signing_key:
            return "hmac-sha256", hmac.new(signing_key.encode(), data, hashlib.sha256).hexdigest()
        return "sha256", hashlib.sha256(data).hexdigest()

    def save(self, path: str | Path, signing_key: str = "") -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = io.BytesIO()
        joblib.dump({"pipeline": self.pipeline, "metadata": self.metadata}, buffer)
        data = buffer.getvalue()
        algorithm, digest = self._digest(data, signing_key)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)  # atomic: a running server never sees half a file
        _signature_path(path).write_text(
            json.dumps({"algorithm": algorithm, "digest": digest}), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, scope: NetworkScope,
             signing_key: str = "") -> AlertClassifier | None:
        path = Path(path)
        if not path.exists():
            return None
        data = path.read_bytes()
        try:
            signature = json.loads(_signature_path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.error("model %s has no valid signature file; refusing to load it", path)
            return None
        expected_algorithm, expected = cls._digest(data, signing_key)
        if signature.get("algorithm") != expected_algorithm or not hmac.compare_digest(
                str(signature.get("digest", "")), expected):
            log.error("signature check failed for model %s; refusing to load it", path)
            return None

        bundle = joblib.load(io.BytesIO(data))
        metadata = bundle.get("metadata", {})
        if metadata.get("feature_version") != FEATURE_VERSION:
            log.warning("model at %s was built with an older feature set; retrain it", path)
            return None
        if metadata.get("sklearn_version") != sklearn.__version__:
            log.warning("model trained with scikit-learn %s, running %s",
                        metadata.get("sklearn_version"), sklearn.__version__)
        return cls(bundle["pipeline"], scope, metadata)


def _signature_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sig")
