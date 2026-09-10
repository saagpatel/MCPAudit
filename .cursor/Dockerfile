FROM python:3.11.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never

# Keep the runtime and package manager explicit. Git is required by the
# repository's PEP 517 provenance backend during editable installation.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes git ca-certificates \
    && python -m pip install --no-cache-dir --disable-pip-version-check "uv==0.12.12" \
    && rm -rf /var/lib/apt/lists/*
