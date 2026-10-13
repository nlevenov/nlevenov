"""Command line interface: ``socprio <command>``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .config import Settings, load_settings
from .ingest import FORMATS, parse_file, parse_record
from .models import Alert, Priority

_COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[92m"}
_RESET = "\033[0m"


def _color(text: str, priority: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{_COLORS.get(priority, '')}{text}{_RESET}"


def _parse_duration(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if not match:
        raise argparse.ArgumentTypeError("use a duration like 30m, 12h or 7d")
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{units[match.group(2)]: int(match.group(1))})


def print_alerts(alerts: list[Alert], limit: int = 20) -> None:
    header = f"{'Time (UTC)':<19}  {'Alert type':<20}  {'Source IP':<15}  {'Score':>5}  Priority"
    print(header)
    print("-" * len(header))
    for alert in alerts[:limit]:
        print(f"{alert.last_seen:%Y-%m-%d %H:%M:%S}  {alert.alert_type[:20]:<20}  "
              f"{(alert.src_ip or '-')[:15]:<15}  {alert.risk_score:>5}  "
              f"{_color(alert.priority.value.upper(), alert.priority.value)}")


def _summary(result) -> None:
    p = result.by_priority
    print(f"received {result.received} events -> {result.created} new alerts, "
          f"{result.merged} merged as repeats")
    print("priority: " + "  ".join(_color(f"{k}={p[k]}", k) for k in p))
    if result.notified:
        print(f"notifications sent: {result.notified}")


# ---------------------------------------------------------------- commands

def cmd_ingest(args: argparse.Namespace, settings: Settings) -> int:
    from .pipeline import Pipeline

    pipeline = Pipeline.from_settings(settings)
    total_skipped = 0
    for path in args.paths:
        alerts, skipped = parse_file(path, args.format)
        total_skipped += skipped
        result = pipeline.process(alerts)
        print(f"[{path}]")
        _summary(result)
        if args.show:
            print()
            print_alerts(result.alerts, args.show)
    pipeline.close()
    if total_skipped:
        print(f"skipped {total_skipped} records that were not alerts or could not be parsed")
    return 0


def _raise_interrupt(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def cmd_watch(args: argparse.Namespace, settings: Settings) -> int:
    """Follow a log file like ``tail -F`` and process new lines in small batches."""
    from .pipeline import Pipeline

    if args.format in ("auto", "csv"):
        print("watch needs an explicit line-based --format (cef, suricata, json, authlog)")
        return 2
    pipeline = Pipeline.from_settings(settings)
    path = Path(args.path)
    min_rank = Priority(args.min_priority).rank
    print(f"watching {path} ({args.format}), flushing every {args.interval}s - Ctrl+C to stop")

    # SIGTERM (docker stop, systemd) should flush like Ctrl+C does.
    signal.signal(signal.SIGTERM, _raise_interrupt)

    position = 0 if args.from_start or not path.exists() else path.stat().st_size
    inode = path.stat().st_ino if path.exists() else None
    buffer: list[Alert] = []
    last_flush = time.monotonic()

    def flush() -> None:
        nonlocal buffer, last_flush
        result = pipeline.process(buffer)
        buffer = []
        last_flush = time.monotonic()
        for alert in result.alerts:
            if alert.priority.rank < min_rank:
                continue
            label = _color(f"{alert.priority.value.upper():<8}", alert.priority.value)
            print(f"{alert.last_seen:%H:%M:%S}  {label}  {alert.risk_score:>3}  "
                  f"{alert.alert_type:<18} {alert.src_ip or '-':<15} "
                  f"{alert.signature[:60]}", flush=True)

    try:
        while True:
            if path.exists():
                stat = path.stat()
                if stat.st_ino != inode or stat.st_size < position:  # rotated or truncated
                    inode, position = stat.st_ino, 0
                # binary mode: offsets are byte counts even with invalid UTF-8
                with path.open("rb") as fh:
                    fh.seek(position)
                    for raw_line in fh:
                        if not raw_line.endswith(b"\n"):
                            break  # partial write, pick it up next round
                        position += len(raw_line)
                        alert = parse_record(raw_line.decode("utf-8", "replace"), args.format)
                        if alert:
                            buffer.append(alert)
            if buffer and (time.monotonic() - last_flush >= args.interval or len(buffer) >= 500):
                flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        if buffer:
            flush()
        print("\nstopped")
    finally:
        pipeline.close()
    return 0


def cmd_elastic(args: argparse.Namespace, settings: Settings) -> int:
    import httpx

    from .ingest.elastic import ElasticCollector
    from .pipeline import Pipeline

    if args.index:
        settings.elastic.index = args.index
    collector = ElasticCollector(settings.elastic)
    since = datetime.now(timezone.utc) - args.since
    try:
        alerts = list(collector.fetch(since, query=args.query))
    except httpx.HTTPError as exc:
        print(f"could not query {settings.elastic.url}: {exc}")
        return 1
    finally:
        collector.close()
    pipeline = Pipeline.from_settings(settings)
    result = pipeline.process(alerts)
    pipeline.close()
    _summary(result)
    return 0


def cmd_generate(args: argparse.Namespace, settings: Settings) -> int:
    from .simulate import generate, write_jsonl, write_sample_feed

    records = generate(args.count, seed=args.seed, hours=args.hours)
    write_jsonl(records, args.out)
    positives = sum(r["label"] == "true_positive" for r in records)
    print(f"wrote {len(records)} labelled events to {args.out} ({positives} true positives)")
    if args.feed:
        Path(args.feed).parent.mkdir(parents=True, exist_ok=True)
        write_sample_feed(args.feed)
        print(f"wrote matching threat feed to {args.feed}")
    return 0


def _load_labelled(args: argparse.Namespace) -> tuple[list[Alert], dict[str, bool] | None]:
    if args.cicids:
        from .ingest.datasets import load_cicids

        pairs = load_cicids(args.cicids, limit=args.limit)
        return [a for a, _ in pairs], {a.fingerprint: y for a, y in pairs}
    alerts, _ = parse_file(args.data, args.format)
    return alerts, None


def cmd_train(args: argparse.Namespace, settings: Settings) -> int:
    from .analysis.ml import AlertClassifier
    from .enrich.indicators import NetworkScope
    from .evaluation import train_from_alerts
    from .storage import AlertStore

    if args.from_db:
        store = AlertStore(settings.database)
        alerts, labels = store.labelled()
        classifier, report = AlertClassifier.train(alerts, labels,
                                                   NetworkScope(settings.internal_networks))
    else:
        if not (args.data or args.cicids):
            print("pass --data FILE, --cicids FILE or --from-db")
            return 2
        alerts, labels = _load_labelled(args)
        classifier, report = train_from_alerts(alerts, settings, labels)
    classifier.save(settings.model_path, signing_key=settings.model_signing_key)
    print(f"model saved to {settings.model_path}")
    print(json.dumps(report.as_dict(), indent=2))
    print("most influential features:")
    for name, weight in classifier.top_features(10):
        print(f"  {weight:6.3f}  {name}")
    return 0


def cmd_evaluate(args: argparse.Namespace, settings: Settings) -> int:
    from .evaluation import benchmark

    alerts, labels = _load_labelled(args)
    if labels is not None:  # CIC-IDS: write the label onto the alert itself
        for alert in alerts:
            alert.raw["label"] = "true_positive" if labels[alert.fingerprint] else "benign"
    alerts.sort(key=lambda a: a.timestamp)
    cut = int(len(alerts) * args.split)
    report = benchmark(alerts[:cut], alerts[cut:], settings, k=args.k)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print(f"time-based split: {cut} events for training, {len(alerts) - cut} for testing")
    print(f"test set: {report['test_alerts']} alerts after dedup, "
          f"{report['test_positives']} true positives\n")
    header = f"{'strategy':<30} {'flagged':>8} {'precision':>10} {'recall':>8} {'f1':>7} " \
             f"{'p@' + str(report['k']):>7}"
    print(header)
    print("-" * len(header))
    for s in report["strategies"]:
        print(f"{s['name']:<30} {s['flagged']:>8} {s['precision']:>10.3f} {s['recall']:>8.3f} "
              f"{s['f1']:>7.3f} {s['precision_at_k']:>7.3f}")
    return 0


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from .api import create_app
    from .api.security import validate_api_key
    from .pipeline import Pipeline

    try:
        validate_api_key(settings.api_key)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    if args.host not in LOOPBACK_HOSTS and not settings.api_key:
        print(f"error: refusing to serve on {args.host} without authentication. "
              "Set SOCPRIO_API_KEY (and allowed_hosts) or bind to 127.0.0.1.")
        return 2

    pipeline = Pipeline.from_settings(settings, dashboard_url=args.public_url or "")
    try:
        uvicorn.run(create_app(settings, pipeline), host=args.host, port=args.port,
                    log_level="info", proxy_headers=args.behind_proxy,
                    forwarded_allow_ips="*" if args.behind_proxy else None,
                    server_header=False)
    finally:
        pipeline.close()
    return 0


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    from .reports import export_csv, write_html_report
    from .storage import AlertStore

    store = AlertStore(settings.database)
    out = Path(args.out)
    if out.suffix == ".csv":
        count = export_csv(store, out, args.hours)
        print(f"exported {count} alerts to {out}")
    else:
        write_html_report(store, out, args.hours)
        print(f"report written to {out}")
    return 0


def cmd_top(args: argparse.Namespace, settings: Settings) -> int:
    from .storage import OPEN_STATUSES, AlertStore

    store = AlertStore(settings.database)
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    alerts, total = store.query(status=None if args.all else list(OPEN_STATUSES), since=since,
                                limit=args.limit)
    print_alerts(alerts, args.limit)
    print(f"\nshowing {len(alerts)} of {total}")
    return 0


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    """Generate data, train a model, ingest a fresh day of alerts and serve the UI."""
    from .evaluation import train_from_alerts
    from .ingest.parsers import parse_generic
    from .pipeline import Pipeline
    from .simulate import generate, write_sample_feed

    feed = Path(settings.intel.feeds_dir) / "sample_feed.csv"
    if not feed.exists():
        feed.parent.mkdir(parents=True, exist_ok=True)
        write_sample_feed(feed)

    history = [a for r in generate(6000, seed=11, hours=24 * 14,
                                   end=datetime.now(timezone.utc) - timedelta(days=1))
               if (a := parse_generic(r))]
    print(f"training on {len(history)} historical events...")
    classifier, report = train_from_alerts(history, settings)
    classifier.save(settings.model_path, signing_key=settings.model_signing_key)
    print(f"model ready: f1={report.f1} roc_auc={report.roc_auc}")

    today = [a for r in generate(args.count, seed=int(time.time()) % 10_000)
             if (a := parse_generic(r))]
    for alert in today:
        alert.raw.pop("label", None)
        alert.raw.pop("scenario", None)
    pipeline = Pipeline.from_settings(settings)
    result = pipeline.process(today)
    pipeline.close()
    _summary(result)
    print()
    print_alerts(result.alerts, 10)
    if args.no_serve:
        return 0
    print()
    return cmd_serve(args, settings)


# ------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="socprio",
                                     description="Prioritize SOC alerts with threat intel and ML.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", help="path to settings.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="parse and score one or more log files")
    p.add_argument("paths", nargs="+")
    p.add_argument("-f", "--format", choices=FORMATS, default="auto")
    p.add_argument("--show", type=int, default=10, metavar="N", help="print the top N alerts")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("watch", help="follow a log file and score alerts in real time")
    p.add_argument("path")
    p.add_argument("-f", "--format", choices=FORMATS, required=True)
    p.add_argument("--interval", type=float, default=2.0, help="seconds between batches")
    p.add_argument("--from-start", action="store_true", help="process existing content first")
    p.add_argument("--min-priority", choices=[x.value for x in Priority], default="medium")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("elastic", help="pull alerts from Elasticsearch / OpenSearch")
    p.add_argument("--since", type=_parse_duration, default=timedelta(hours=1))
    p.add_argument("--index")
    p.add_argument("--query", help="Lucene query string to narrow the search")
    p.set_defaults(func=cmd_elastic)

    p = sub.add_parser("generate", help="create labelled synthetic alerts")
    p.add_argument("-n", "--count", type=int, default=2000)
    p.add_argument("-o", "--out", default="data/sample/alerts.jsonl")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--feed", help="also write a matching threat feed CSV here")
    p.set_defaults(func=cmd_generate)

    for name, func, helptext in (("train", cmd_train, "train the true-positive classifier"),
                                 ("evaluate", cmd_evaluate,
                                  "benchmark rule-based vs ML prioritization")):
        p = sub.add_parser(name, help=helptext)
        src = p.add_mutually_exclusive_group()
        src.add_argument("--data", help="labelled alerts (records need a 'label' field)")
        src.add_argument("--cicids", help="CIC-IDS2017/2018 CSV file")
        if name == "train":
            src.add_argument("--from-db", action="store_true",
                             help="use analyst verdicts stored in the database")
        p.add_argument("-f", "--format", choices=FORMATS, default="auto")
        p.add_argument("--limit", type=int, help="max rows to read from a CIC-IDS file")
        p.set_defaults(func=func)
    eval_parser = sub.choices["evaluate"]
    eval_parser.add_argument("--split", type=float, default=0.7,
                             help="fraction of events (oldest first) used for training")
    eval_parser.add_argument("-k", type=int, default=50, help="cut-off for precision@k")
    eval_parser.add_argument("--json", action="store_true")

    p = sub.add_parser("serve", help="run the API and dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--public-url", help="external URL used for links in notifications")
    p.add_argument("--behind-proxy", action="store_true",
                   help="trust X-Forwarded-* headers from a TLS-terminating reverse proxy")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("report", help="write an HTML or CSV report")
    p.add_argument("-o", "--out", default="reports/soc-report.html")
    p.add_argument("--hours", type=int, default=24)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("top", help="print the highest-risk open alerts")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--all", action="store_true", help="include closed alerts")
    p.set_defaults(func=cmd_top)

    p = sub.add_parser("demo", help="end-to-end demo with synthetic data")
    p.add_argument("-n", "--count", type=int, default=1500)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--public-url")
    p.add_argument("--behind-proxy", action="store_true")
    p.add_argument("--no-serve", action="store_true")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = load_settings(args.config)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: invalid configuration: {exc}")
        return 2
    if args.command == "evaluate" and not (args.data or args.cicids):
        print("pass --data FILE or --cicids FILE")
        return 2
    return args.func(args, settings)


if __name__ == "__main__":
    sys.exit(main())
