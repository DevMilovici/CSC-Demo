# syntax=docker/dockerfile:1
#
# Two images from one file, sharing the dependency layer:
#   docker build --target server -t csc-demo-server .   # remote signing service (CSC API + OAuth)
#   docker build --target webapp -t csc-demo-webapp .   # signature application (web UI)
# compose.yaml builds both.

FROM python:3.14-slim AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore
WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install -r requirements.txt -c constraints.txt
RUN useradd --system --uid 10001 --no-create-home --home-dir /app app


# --------------------------------------------------------------------------- CSC server
FROM base AS server
COPY server/*.py server/
# CA key, credential keys and certificates. Mount a volume here so they survive updates.
RUN mkdir /data && chown app:app /data
ENV CSC_HOST=0.0.0.0 CSC_PORT=8080 CSC_DATA_DIR=/data
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["python", "-c", "import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:8080/csc/v2/info', data=b'{}', headers={'Content-Type': 'application/json'}), timeout=4)"]
CMD ["python", "server/csc_server.py"]


# --------------------------------------------------------------------------- web app
FROM base AS webapp
COPY webapp/app.py webapp/
COPY webapp/static/ webapp/static/
ENV WEBAPP_HOST=0.0.0.0 WEBAPP_PORT=8000
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/', timeout=4)"]
CMD ["python", "webapp/app.py"]
