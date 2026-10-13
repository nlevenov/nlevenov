"""Shift reports: a standalone HTML file with plotly charts, and CSV export."""

from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.io as pio

from .storage import AlertStore

PRIORITY_COLORS = {"critical": "#e5484d", "high": "#f76b15", "medium": "#ffc53d", "low": "#46a758"}
PRIORITY_ORDER = ["critical", "high", "medium", "low"]


def export_csv(store: AlertStore, path: str | Path, hours: int = 24) -> int:
    frame = store.frame(datetime.now(timezone.utc) - timedelta(hours=hours))
    frame.sort_values("risk_score", ascending=False).to_csv(path, index=False)
    return len(frame)


def build_html_report(store: AlertStore, hours: int = 24) -> str:
    now = datetime.now(timezone.utc)
    frame = store.frame(now - timedelta(hours=hours))
    stats = store.stats(hours)
    title = f"SOC Alert Report - last {hours}h"

    if frame.empty:
        charts = "<p>No alerts in this window.</p>"
        table = ""
    else:
        frame["priority"] = pd.Categorical(frame["priority"], PRIORITY_ORDER, ordered=True)
        donut = px.pie(
            frame, names="priority", hole=0.55, color="priority",
            color_discrete_map=PRIORITY_COLORS, category_orders={"priority": PRIORITY_ORDER},
            title="Alerts by priority",
        )
        hourly = (frame.set_index("last_seen").groupby("priority", observed=False)
                  .resample("1h")["id"].count().rename("alerts").reset_index())
        timeline = px.bar(
            hourly, x="last_seen", y="alerts", color="priority",
            color_discrete_map=PRIORITY_COLORS, category_orders={"priority": PRIORITY_ORDER},
            title="Alerts per hour",
        )
        types = (frame.groupby("alert_type", as_index=False)
                 .agg(alerts=("id", "count"), mean_score=("risk_score", "mean"))
                 .sort_values("alerts"))
        by_type = px.bar(types, x="alerts", y="alert_type", orientation="h",
                         color="mean_score", color_continuous_scale="OrRd",
                         title="Alert types (colour = mean risk score)")
        figures = [donut, timeline, by_type]
        for fig in figures:
            fig.update_layout(template="plotly_white", margin={"t": 50, "l": 10, "r": 10})
        charts = "".join(
            pio.to_html(fig, full_html=False, include_plotlyjs="cdn" if i == 0 else False)
            for i, fig in enumerate(figures)
        )
        top = frame.sort_values("risk_score", ascending=False).head(25)
        table_rows = "".join(
            "<tr>"
            f"<td>{r.last_seen:%Y-%m-%d %H:%M}</td><td>{html.escape(r.alert_type)}</td>"
            f"<td>{html.escape(str(r.signature or ''))}</td><td>{r.src_ip or ''}</td>"
            f"<td>{r.dst_ip or ''}</td><td>{r.occurrences}</td><td>{r.risk_score}</td>"
            f"<td class='p-{r.priority}'>{r.priority}</td><td>{r.status}</td>"
            "</tr>"
            for r in top.itertuples()
        )
        table = (
            "<h2>Top 25 alerts</h2><table><thead><tr><th>Last seen (UTC)</th><th>Type</th>"
            "<th>Signature</th><th>Source</th><th>Destination</th><th>Count</th><th>Score</th>"
            f"<th>Priority</th><th>Status</th></tr></thead><tbody>{table_rows}</tbody></table>"
        )

    p = stats["by_priority"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:32px;color:#1c2024}}
 .kpis{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0 24px}}
 .kpi{{border:1px solid #e0e1e6;border-radius:8px;padding:12px 18px;min-width:120px}}
 .kpi b{{display:block;font-size:26px}}
 table{{border-collapse:collapse;width:100%;font-size:14px}}
 th,td{{border-bottom:1px solid #e0e1e6;padding:6px 8px;text-align:left}}
 .p-critical{{color:#e5484d;font-weight:600}} .p-high{{color:#f76b15;font-weight:600}}
 .p-medium{{color:#b8860b}} .p-low{{color:#46a758}}
</style></head><body>
<h1>{title}</h1>
<p>Generated {now:%Y-%m-%d %H:%M} UTC</p>
<div class="kpis">
 <div class="kpi">Raw events<b>{stats['events']}</b></div>
 <div class="kpi">Alerts after dedup<b>{stats['total']}</b></div>
 <div class="kpi">Critical<b>{p['critical']}</b></div>
 <div class="kpi">High<b>{p['high']}</b></div>
 <div class="kpi">Noise reduction<b>{stats['noise_reduction'] * 100:.1f}%</b></div>
</div>
{charts}
{table}
</body></html>"""


def write_html_report(store: AlertStore, path: str | Path, hours: int = 24) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_html_report(store, hours), encoding="utf-8")
    return path
