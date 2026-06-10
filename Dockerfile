FROM python:3.12.13-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
COPY requirements.lock /tmp/requirements.lock
RUN /opt/venv/bin/python -m pip install \
    --require-hashes \
    --requirement /tmp/requirements.lock

FROM python:3.12.13-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d AS runtime

ARG VCS_REF=unknown
ARG SOURCE_URL=unknown

LABEL org.opencontainers.image.title="SITBank banking application" \
      org.opencontainers.image.description="Hardened Flask and Gunicorn runtime" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${SOURCE_URL}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade \
        gpgv \
        libgnutls30 \
        libssl3 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sitbank \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin sitbank \
    && install -d -o 10001 -g 10001 -m 0750 /app

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 migrations ./migrations
COPY --chown=10001:10001 config.py wsgi.py ./

USER 10001:10001

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 \
    CMD ["python", "-c", "import urllib.request; request=urllib.request.Request('http://127.0.0.1:5000/health/ready', headers={'X-Forwarded-Proto':'https'}); urllib.request.urlopen(request, timeout=4).read()"]

CMD ["python", "-m", "gunicorn", "--workers", "3", "--bind", "127.0.0.1:5000", "--access-logfile", "-", "--error-logfile", "-", "--timeout", "30", "--graceful-timeout", "30", "wsgi:app"]
