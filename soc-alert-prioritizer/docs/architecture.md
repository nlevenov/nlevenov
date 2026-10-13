# Architecture

## Data model

Every source is normalized into one `Alert` model
([`models.py`](../src/socprio/models.py)): timestamp, source, alert type,
signature, vendor severity (0-10), network 5-tuple, host, user, domain, URL,
file hash and the untouched raw event. Pipeline stages then add enrichment,
rule hits, model probability, score breakdown, priority and triage state.

The alert *fingerprint* is a hash of source, signature, source IP and
destination IP. Alerts that share a fingerprint inside the dedup window are
treated as the same activity.

## Pipeline

`Pipeline.process()` ([`pipeline.py`](../src/socprio/pipeline.py)) works on
batches so the model is called once per batch:

1. **Deduplicate.** Events are sorted by time and grouped by fingerprint. A
   group continues an open alert from the database if the last sighting is
   within `dedup_window_minutes`; otherwise it starts a new alert. Alerts that
   a rule auto-closed keep absorbing repeats, alerts closed by an analyst do
   not - new activity after a human decision is a new incident.
2. **Enrich.** Indicators are extracted (external IPs, domains, URLs and
   their hosts, hashes). Internal addresses are never looked up externally.
   Each provider returns `IntelHit`s scored 0-100. Remote providers sit
   behind `CachedProvider`, which caches results in SQLite and swallows
   network errors so an outage degrades enrichment instead of stopping the
   pipeline. The asset inventory picks the most critical asset involved.
3. **Rules.** The rule engine evaluates YAML rules against a flat context
   ([`analysis/context.py`](../src/socprio/analysis/context.py)) that also
   contains derived fields such as `off_hours`, `privileged_user` and
   `intel_tags`. Rules adjust the score, tag, re-classify or auto-close.
4. **Classify.** If a model is available it predicts P(true positive).
5. **Score.** See below.
6. **Store and notify.** Alerts are upserted into SQLite. A notification is
   sent only when an alert reaches the notification priority for the first
   time or escalates, never for every repeat.

## Scoring

```
base  = sum(w_i * f_i) / sum(w_i)       f in {severity, asset, ml}
intel = (100 - base) * intel_weight * intel_factor
score = clamp(base + intel + volume + rules, 0, 100)
```

* `intel_factor` is the highest provider score / 100, plus 0.05 for each
  additional provider that agrees.
* `volume` is `2.5 * log2(occurrences)`, capped at 10.
* With no trained model the ML factor drops out and the remaining weights are
  re-normalized.

The breakdown of every term is stored with the alert and shown in the
dashboard, so a score is never a black box.

## Machine learning

Features ([`analysis/ml.py`](../src/socprio/analysis/ml.py)):

| Group | Features |
|-------|----------|
| Numeric | severity, intel score / hit count / provider count, asset criticality, log(occurrences), internal source / destination, sensitive port, off-hours, privileged user, has hash, has domain, hour |
| Categorical (one-hot) | alert type, source product, protocol |
| Text (TF-IDF, 1-2 grams) | signature |

The model is a `RandomForestClassifier` with balanced class weights inside a
scikit-learn `Pipeline`, so feature extraction and model are saved together
with joblib. Training reports precision, recall, F1 and ROC-AUC on a
stratified hold-out set before refitting on all data. The saved bundle
records the feature-set version and scikit-learn version; an incompatible
model is ignored with a warning rather than producing wrong scores.

Labels come from three places:

* `label` fields in labelled files (synthetic data, exports from a case
  management system),
* CIC-IDS flow labels via `--cicids`,
* analyst verdicts in the dashboard (`train --from-db` or
  `POST /api/model/retrain`).

## Storage

SQLite in WAL mode with indexes on fingerprint, priority/status and time.
Nested structures (intel hits, asset, breakdown, raw event) are stored as
JSON columns. Statistics for the dashboard and reports are computed with
pandas from a narrow projection of the table.

## Security notes

* Secrets are only read from environment variables via `${VAR}` expansion.
* Write endpoints require `X-API-Key` when an API key is configured; the
  comparison is constant-time.
* All dynamic values in the dashboard are HTML-escaped; Jinja2 autoescaping
  is on for server-rendered pages.
* The container runs as an unprivileged user.
