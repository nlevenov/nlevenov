"""REST API and analyst dashboard."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs

import plotly
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..analysis.ml import AlertClassifier
from ..config import Settings, load_settings
from ..ingest import iter_parse, parse_record
from ..models import Alert, Priority, Status, Verdict
from ..pipeline import Pipeline
from ..playbooks import playbook_for
from ..reports import build_html_report, to_safe_csv
from .security import (
    SESSION_COOKIE,
    FailureLimiter,
    HardeningMiddleware,
    SessionSigner,
    same_origin,
    validate_api_key,
)

log = logging.getLogger(__name__)

HERE = Path(__file__).parent
# Serve the plotly.js bundle shipped inside the plotly wheel, so the dashboard
# also works on isolated SOC networks without CDN access.
PLOTLY_JS = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_EVENT_TEXT = 64 * 1024


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
    events: list[dict[str, Any] | Annotated[str, Field(max_length=MAX_EVENT_TEXT)]] = Field(
        min_length=1, max_length=10_000)


class _LoginRequired(Exception):
    pass


def create_app(settings: Settings | None = None, pipeline: Pipeline | None = None) -> FastAPI:
    settings = settings or load_settings()
    validate_api_key(settings.api_key)
    pipeline = pipeline or Pipeline.from_settings(settings)
    store = pipeline.store
    auth_enabled = bool(settings.api_key)
    signer = SessionSigner(settings.api_key) if auth_enabled else None
    limiter = FailureLimiter()

    app = FastAPI(title="SOC Alert Prioritizer", version=__version__,
                  description="Alert triage API: ingest, enrich, score and review alerts.")
    app.add_middleware(HardeningMiddleware)
    # Without an API key the app is only safe on loopback. Pinning the Host
    # header also defeats DNS-rebinding attacks from a malicious web page.
    allowed_hosts = settings.allowed_hosts or (
        ["*"] if auth_enabled else ["127.0.0.1", "localhost", "::1", "[::1]"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["auth_enabled"] = auth_enabled
    app.state.pipeline = pipeline

    # ------------------------------------------------------------- auth
    def client_id(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def check_key(request: Request, candidate: str | None) -> bool:
        client = client_id(request)
        if limiter.blocked(client):
            raise HTTPException(status_code=429, detail="too many failed attempts, try later")
        if candidate and secrets.compare_digest(candidate.encode(), settings.api_key.encode()):
            limiter.reset(client)
            return True
        if candidate:
            limiter.failure(client)
            log.warning("failed authentication from %s", client)
        return False

    def require_auth(request: Request) -> None:
        # Browsers always send Origin on cross-site writes; scripts and
        # forwarders send none. This blocks CSRF even with auth disabled.
        origin = request.headers.get("origin")
        if request.method in UNSAFE_METHODS and origin and not same_origin(
                origin, request.headers.get("host")):
            raise HTTPException(status_code=403, detail="cross-origin request rejected")
        if not auth_enabled:
            return
        if check_key(request, request.headers.get("x-api-key")):
            return
        if signer and signer.verify(request.cookies.get(SESSION_COOKIE)):
            if request.method in UNSAFE_METHODS and not same_origin(
                origin or request.headers.get("referer"), request.headers.get("host")
            ):
                raise HTTPException(status_code=403, detail="cross-origin request rejected")
            return
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="authentication required",
                                headers={"WWW-Authenticate": "API-Key"})
        raise _LoginRequired

    @app.exception_handler(_LoginRequired)
    async def _redirect_to_login(request: Request, exc: _LoginRequired) -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    Auth = Depends(require_auth)

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page(request: Request) -> Response:
        if not auth_enabled:
            return RedirectResponse("/", status_code=303)
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login", include_in_schema=False)
    async def login(request: Request) -> Response:
        if not auth_enabled or signer is None:
            return RedirectResponse("/", status_code=303)
        if not same_origin(request.headers.get("origin") or request.headers.get("referer"),
                           request.headers.get("host")):
            raise HTTPException(status_code=403, detail="cross-origin request rejected")
        form = parse_qs((await request.body()).decode("utf-8", "replace"))
        if not check_key(request, (form.get("api_key") or [""])[0]):
            return templates.TemplateResponse(request, "login.html",
                                              {"error": "Invalid API key."}, status_code=401)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(SESSION_COOKIE, signer.issue(), max_age=signer.ttl, httponly=True,
                            samesite="strict", secure=request.url.scheme == "https")
        return response

    @app.post("/logout", include_in_schema=False)
    def logout() -> Response:
        response = RedirectResponse("/login" if auth_enabled else "/", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    def get_alert_or_404(alert_id: str) -> Alert:
        alert = store.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert

    # ------------------------------------------------------------ pages
    @app.get("/vendor/plotly.min.js", include_in_schema=False)
    def plotly_js() -> FileResponse:
        return FileResponse(PLOTLY_JS, media_type="application/javascript",
                            headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/", response_class=HTMLResponse, include_in_schema=False, dependencies=[Auth])
    def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "dashboard.html", {
            "version": __version__, "model": pipeline.classifier is not None,
        })

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse, include_in_schema=False,
             dependencies=[Auth])
    def alert_page(request: Request, alert_id: str) -> HTMLResponse:
        alert = get_alert_or_404(alert_id)
        related: list[Alert] = []
        if alert.src_ip:
            related, _ = store.query(src_ip=alert.src_ip, sort="recent", limit=11)
        return templates.TemplateResponse(request, "alert.html", {
            "alert": alert, "playbook": playbook_for(alert.alert_type),
            "related": [a for a in related if a.id != alert.id][:10],
            "statuses": list(Status), "verdicts": list(Verdict),
        })

    # -------------------------------------------------------------- API
    @app.get("/health", tags=["system"])
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/alerts", response_model=AlertPage, tags=["alerts"], dependencies=[Auth])
    def list_alerts(
        priority: Annotated[list[Priority] | None, Query()] = None,
        status: Annotated[list[Status] | None, Query()] = None,
        alert_type: str | None = Query(default=None, max_length=64),
        q: str | None = Query(default=None, max_length=200),
        hours: int | None = Query(default=None, ge=1, le=24 * 365),
        sort: Literal["risk", "recent", "oldest"] = "risk",
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1_000_000),
    ) -> AlertPage:
        since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
        items, total = store.query(
            priority=[p.value for p in priority] if priority else None,
            status=[s.value for s in status] if status else None,
            alert_type=alert_type, search=q, since=since, sort=sort, limit=limit, offset=offset)
        return AlertPage(total=total, limit=limit, offset=offset, items=items)

    @app.get("/api/alerts/{alert_id}", response_model=Alert, tags=["alerts"],
             dependencies=[Auth])
    def get_alert(alert_id: str) -> Alert:
        return get_alert_or_404(alert_id)

    @app.patch("/api/alerts/{alert_id}", response_model=Alert, tags=["alerts"],
               dependencies=[Auth])
    def update_alert(alert_id: str, update: AlertUpdate) -> Alert:
        get_alert_or_404(alert_id)
        status = update.status
        # a verdict closes the alert unless the analyst says otherwise
        if update.verdict is not None and status is None:
            status = Status.FALSE_POSITIVE if update.verdict != Verdict.TRUE_POSITIVE \
                else Status.CLOSED
        updated = store.update(alert_id, status=status, verdict=update.verdict,
                               notes=update.notes)
        if updated is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return updated

    @app.post("/api/ingest", tags=["ingest"], dependencies=[Auth])
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

    @app.get("/api/stats", tags=["reports"], dependencies=[Auth])
    def stats(hours: int = Query(default=24, ge=1, le=24 * 90)) -> dict[str, Any]:
        return store.stats(hours)

    @app.get("/api/report.csv", tags=["reports"], dependencies=[Auth])
    def report_csv(hours: int = Query(default=24, ge=1, le=24 * 90)) -> Response:
        frame = store.frame(datetime.now(timezone.utc) - timedelta(hours=hours))
        filename = f"soc-alerts-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
        return Response(
            to_safe_csv(frame), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/report.html", response_class=HTMLResponse, tags=["reports"],
             dependencies=[Auth])
    def report_html(hours: int = Query(default=24, ge=1, le=24 * 90)) -> HTMLResponse:
        return HTMLResponse(build_html_report(store, hours, plotly_src="/vendor/plotly.min.js"))

    @app.get("/api/model", tags=["model"], dependencies=[Auth])
    def model_info() -> dict[str, Any]:
        if pipeline.classifier is None:
            return {"loaded": False}
        return {"loaded": True, **pipeline.classifier.metadata,
                "top_features": pipeline.classifier.top_features(10)}

    @app.post("/api/model/retrain", tags=["model"], dependencies=[Auth])
    def retrain() -> dict[str, Any]:
        alerts, labels = store.labelled()
        try:
            classifier, report = AlertClassifier.train(alerts, labels, pipeline.enricher.scope)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        classifier.save(settings.model_path, signing_key=settings.model_signing_key)
        pipeline.classifier = classifier
        return {"trained": True, **report.as_dict()}

    return app
