FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gpg ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ── Elastic (auditbeat + filebeat) ────────────────────────────────────────────
RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
      | gpg --dearmor > /usr/share/keyrings/elastic-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/elastic-keyring.gpg] \
https://artifacts.elastic.co/packages/9.x/apt stable main" \
      > /etc/apt/sources.list.d/elastic-9.x.list

# ── osquery ────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg \
      | gpg --dearmor > /usr/share/keyrings/osquery-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-keyring.gpg] \
https://pkg.osquery.io/deb deb main" \
      > /etc/apt/sources.list.d/osquery.list

# ── скачать .deb без установки ─────────────────────────────────────────────────
# Версии пинируются через build args; передайте нужные при сборке:
#   docker build --build-arg ELASTIC_VERSION=9.4.1 --build-arg OSQUERY_VERSION=5.23.0 .
ARG ELASTIC_VERSION=9.4.1
ARG OSQUERY_VERSION=5.23.0

RUN apt-get update && \
    mkdir /packages && \
    cd /packages && \
    apt-get download \
      auditbeat=${ELASTIC_VERSION} \
      filebeat=${ELASTIC_VERSION} \
      "osquery=${OSQUERY_VERSION}" && \
    echo "=== Скачано ===" && ls -lh /packages/
