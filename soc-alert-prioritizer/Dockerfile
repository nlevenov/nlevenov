FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

COPY config ./config
COPY feeds ./feeds
COPY data ./data

RUN useradd --create-home --uid 10001 socprio \
    && mkdir -p var models reports \
    && chown -R socprio:socprio /app
USER socprio

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["socprio", "serve", "--host", "0.0.0.0", "--port", "8000"]
