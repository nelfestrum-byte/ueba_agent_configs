ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gpg ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ── osquery ────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg \
      | gpg --dearmor > /usr/share/keyrings/osquery-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-keyring.gpg] \
https://pkg.osquery.io/deb deb main" \
      > /etc/apt/sources.list.d/osquery.list

# ── fluent-bit ─────────────────────────────────────────────────────────────────
ARG FLUENT_BIT_VERSION=5.0.5
ARG OSQUERY_VERSION=5.23.0

RUN apt-get update && \
    mkdir /packages && \
    cd /packages && \
    curl -fsSLO "https://releases.fluentbit.io/${FLUENT_BIT_VERSION}/fluent-bit_${FLUENT_BIT_VERSION}_amd64.deb" && \
    apt-get download "osquery=${OSQUERY_VERSION}" && \
    echo "=== Скачано ===" && ls -lh /packages/
