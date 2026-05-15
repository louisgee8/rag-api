# syntax=docker/dockerfile:1.7

# =====================================================================
# Stage 1: builder
# Installs Python deps in a venv. We do this in a separate stage so the
# final image doesn't carry around build tools (gcc, headers, apt cache).
# Smaller image = smaller attack surface = faster pulls.
# =====================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Build deps needed to compile some Python wheels (psycopg, etc.).
# `--no-install-recommends` skips suggested-but-not-required packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a venv. We'll copy this whole folder to the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# COPY requirements first, install second.
# Docker caches layers — if requirements.txt doesn't change, this whole
# pip install layer is reused on every rebuild. Saves minutes.
COPY requirements.txt .
# BuildKit cache mount: pip wheels persist across builds in a buildkit-managed
# cache, NOT in the image. Layer is still cache-busted when requirements.txt
# changes, but pip can reuse already-downloaded wheels = much faster reinstall.
# Image stays slim (no /root/.cache/pip baked in) because the cache mount is
# build-time only.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -r requirements.txt


# =====================================================================
# Stage 2: runtime
# Slim final image. No build tools, no apt cache, runs as non-root.
# =====================================================================
FROM python:3.11-slim AS runtime

# Sec+ least-privilege: never run as root in a container.
# A compromised app process should not be able to write to /etc.
RUN groupadd --system app && \
    useradd --system --gid app --home-dir /app --shell /sbin/nologin app

WORKDIR /app

# Pull the pre-built venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy only the app code + admin scripts. Owned by the non-root user.
# scripts/ is included so admin CLIs (e.g. scripts/issue_key.py) can run via
# `docker compose exec api python -m scripts.issue_key`. Tests/ and migrations/
# are deliberately NOT included — tests run from the host, migrations are
# bind-mounted into the db container.
COPY --chown=app:app app/ ./app/
COPY --chown=app:app scripts/ ./scripts/

# Pre-create the HuggingFace cache dir owned by `app`. Without this, the
# non-root user can't mkdir under /app (which is root-owned from WORKDIR),
# and sentence-transformers crashes on first model download.
# HF_HOME tells transformers/sentence-transformers where to cache models.
RUN mkdir -p /app/.cache/huggingface && chown -R app:app /app
ENV HF_HOME=/app/.cache/huggingface

USER app

EXPOSE 8000

# Healthcheck uses Python stdlib so we don't need curl in the image.
# Docker marks the container "unhealthy" if /health fails 3x in a row.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0) if urllib.request.urlopen('http://localhost:8000/health').status==200 else sys.exit(1)" \
    || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
