"""REST API and analyst dashboard."""

from __future__ import annotations

import io
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import plotly
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .. import __version__
from ..analysis.ml import AlertClassifier
from ..config import Settings, load_settings
from ..ingest import iter_parse, parse_record
from ..models import Alert, Status, Verdict
from ..pipeline import Pipeline
from ..playbooks import playbook_for
from ..reports import build_html_report

HERE = Path(__file__).parent
# Serve the plotly.js bundle shipped inside the plotly wheel, so the dashboard
# also works on isolated SOC networks without CDN access.
PLOTLY_JS = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[Alert]


class AlertUpdate(BaseModel):
    status: Status | None = None
    verdict: Verdict | None = None
    notes: str | None = Field(default=None, max_length=5000)


class IngestRequest(BaseModel):
    format: Literal["json", "suricata", "cef", "authlog"] = "json"
    events: list[dict[str, Any] | str] = Field(min_length=1, max_length=10_000)


def create_app(settings: Settings | None = None, pipeline: Pipeline | None = None) -> FastAPI:
    settings = settings or load_settings()
    pipeline = pipeline or Pipeline.from_settings(settings)
    store = pipeline.store

    app = FastAPI(title="SOC Alert Prioritizer", version=__version__,
                  description="Alert triage API: ingest, enrich, score and review alerts.")
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    app.state.pipeline = pipeline

    def require_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
        if settings.api_key and not (
            x_api_key and secrets.compare_digest(x_api_key, settings.api_key)
        ):
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    def get_alert_or_404(alert_id: str) -> Alert:
        alert = store.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
        return alert

    # ------------------------------------------------------------ pages
    @app.get("/vendor/plotly.min.js", include_in_schema=False)
    def plotly_js() -> FileResponse:
        return FileResponse(PLOTLY_JS, media_type="application/javascript",
                            headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "dashboard.html", {
            "version": __version__, "model": pipeline.classifier is not None,
        })

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse, include_in_schema=False)
    def alert_page(request: Request, alert_id: str) -> HTMLResponse:
        alert = get_alert_or_404(alert_id)
        related, _ = store.query(search=alert.src_ip, sort="recent", limit=11) \
            if alert.src_ip else ([], 0)
        return templates.TemplateResponse(request, "alert.html", {
            "alert": alert, "playbook": playbook_for(alert.alert_type),
            "related": [a for a in related if a.id != alert.id][:10],
            "statuses": list(Status), "verdicts": list(Verdict),
            "api_key_required": bool(settings.api_key),
        })

    # -------------------------------------------------------------- API
    @app.get("/health", tags=["system"])
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__,
                "model_loaded": pipeline.classifier is not None}

    @app.get("/api/alerts", response_model=AlertPage, tags=["alerts"])
    def list_alerts(
        priority: Annotated[list[str] | None, Query()] = None,
        status: Annotated[list[str] | None, Query()] = None,
        alert_type: str | None = None,
        q: str | None = Query(default=None, max_length=200),
        hours: int | None = Query(default=None, ge=1, le=24 * 365),
        sort: Literal["risk", "recent", "oldest"] = "risk",
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> AlertPage:
        since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
        items, total = store.query(priority=priority, status=status, alert_type=alert_type,
                                   search=q, since=since, sort=sort, limit=limit, offset=offset)
        return AlertPage(total=total, limit=limit, offset=offset, items=items)

    @app.get("/api/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
    def get_alert(alert_id: str) -> Alert:
        return get_alert_or_404(alert_id)

    @app.patch("/api/alerts/{alert_id}", response_model=Alert, tags=["alerts"],
               dependencies=[Depends(require_key)])
    def update_alert(alert_id: str, update: AlertUpdate) -> Alert:
        get_alert_or_404(alert_id)
        status = update.status
        # a verdict closes the alert unless the analyst says otherwise
        if update.verdict is not None and status is None:
            status = Status.FALSE_POSITIVE if update.verdict != Verdict.TRUE_POSITIVE \
                else Status.CLOSED
        return store.update(alert_id, status=status, verdict=update.verdict,
                            notes=update.notes)  # type: ignore[return-value]

    @app.post("/api/ingest", tags=["ingest"], dependencies=[Depends(require_key)])
    def ingest(request: IngestRequest) -> dict[str, Any]:
        if request.format in ("json", "suricata"):
            records = [e for e in request.events if isinstance(e, dict)]
            alerts = list(iter_parse(records, request.format))
        else:
            alerts = [a for e in request.events if isinstance(e, str)
                      if (a := parse_record(e, request.format)) is not None]
        result = pipeline.process(alerts)
        return {**result.summary(), "skipped": len(request.events) - len(alerts),
                "ids": [a.id for a in result.alerts]}

    @app.get("/api/stats", tags=["reports"])
    def stats(hours: int = Query(default=24, ge=1, le=24 * 90)) -> dict[str, Any]:
        return store.stats(hours)

    @app.get("/api/report.csv", tags=["reports"])
    def report_csv(hours: int = Query(default=24, ge=1, le=24 * 90)) -> StreamingResponse:
        frame = store.frame(datetime.now(timezone.utc) - timedelta(hours=hours))
        buffer = io.StringIO()
        frame.sort_values("risk_score", ascending=False).to_csv(buffer, index=False)
        buffer.seek(0)
        filename = f"soc-alerts-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
        return StreamingResponse(
            iter([buffer.getvalue()]), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.get("/api/report.html", response_class=HTMLResponse, tags=["reports"])
    def report_html(hours: int = Query(default=24, ge=1, le=24 * 90)) -> HTMLResponse:
        return HTMLResponse(build_html_report(store, hours))

    @app.get("/api/model", tags=["model"])
    def model_info() -> dict[str, Any]:
        if pipeline.classifier is None:
            return {"loaded": False}
        return {"loaded": True, **pipeline.classifier.metadata,
                "top_features": pipeline.classifier.top_features(10)}

    @app.post("/api/model/retrain", tags=["model"], dependencies=[Depends(require_key)])
    def retrain() -> dict[str, Any]:
        alerts, labels = store.labelled()
        try:
            classifier, report = AlertClassifier.train(alerts, labels, pipeline.enricher.scope)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        classifier.save(settings.model_path)
        pipeline.classifier = classifier
        return {"trained": True, **report.as_dict()}

    return app
