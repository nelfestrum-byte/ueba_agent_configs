FROM debian:trixie-slim

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
# Если trixie-сборки нет — пересоберите с: --build-arg FB_DIST=bookworm
ARG FB_DIST=trixie
RUN curl -fsSL https://packages.fluentbit.io/fluentbit.key \
      | gpg --dearmor > /usr/share/keyrings/fluent-bit-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/fluent-bit-keyring.gpg] \
https://packages.fluentbit.io/debian/${FB_DIST} ${FB_DIST} main" \
      > /etc/apt/sources.list.d/fluent-bit.list

# ── скачать .deb без установки ─────────────────────────────────────────────────
RUN apt-get update && \
    mkdir /packages && \
    cd /packages && \
    apt-get download osquery fluent-bit && \
    echo "=== Скачано ===" && ls -lh /packages/
