# Build context: the repository root (the example installs the SDK it ships with).
FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml README.md LICENSE /sdk/
COPY src /sdk/src
RUN pip install "/sdk[fastapi]" "uvicorn>=0.30,<1" \
    && rm -rf /sdk

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin reference
WORKDIR /srv
COPY examples/certification/app ./app
COPY examples/certification/public ./public
USER reference
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:3000/healthz', timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "app.main"]
