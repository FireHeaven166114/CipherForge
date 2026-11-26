# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# The service runs as an unprivileged user with no login shell.
RUN groupadd --system --gid 10001 cipherforge \
 && useradd --system --uid 10001 --gid cipherforge --home-dir /app --shell /usr/sbin/nologin cipherforge

WORKDIR /app

# Dependencies first so this layer is cached until requirements.txt changes.
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY --chown=cipherforge:cipherforge alembic.ini ./
COPY --chown=cipherforge:cipherforge alembic ./alembic
COPY --chown=cipherforge:cipherforge app ./app

# Encrypted shared files live here. docker-compose.yml mounts a named volume on this path; creating
# it first with the right owner lets the unprivileged user write to the volume.
RUN mkdir -p /app/data/encrypted-files \
 && chown -R cipherforge:cipherforge /app/data \
 && chmod 700 /app/data/encrypted-files

USER cipherforge
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# Migrations run as a separate step (see docker-compose.yml); the API only serves requests.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
