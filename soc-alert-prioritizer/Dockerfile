# ---- build stage: compile wheels, nothing of this ends up in the runtime image
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

# ---- runtime stage
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin socprio

COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels socprio && rm -rf /wheels

WORKDIR /app
COPY --chown=root:root config ./config
COPY --chown=root:root feeds ./feeds
COPY --chown=root:root data ./data
RUN mkdir -p var models reports && chown socprio:socprio var models reports

USER socprio
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Binding to 0.0.0.0 requires SOCPRIO_API_KEY; the app refuses to start without it.
CMD ["socprio", "serve", "--host", "0.0.0.0", "--port", "8000"]
