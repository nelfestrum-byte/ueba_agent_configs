FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV LOGSTASH_HOST=logstash
ENV OPENSEARCH_HOST=opensearch

# ── Системные зависимости ──────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates gnupg lsb-release \
    openssh-server openssh-client \
    auditd audispd-plugins \
    python3 python3-pip \
    netcat-openbsd nmap \
    iproute2 net-tools iputils-ping \
    procps psmisc lsof \
    git vim nano \
    cron \
    jq \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# ── osquery ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
       > /etc/apt/sources.list.d/osquery.list \
    && apt-get update \
    && apt-get install -y osquery \
    && rm -rf /var/lib/apt/lists/*

# ── fluent-bit ─────────────────────────────────────────────────────────────
RUN curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor -o /usr/share/keyrings/fluentbit.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/fluentbit.gpg] https://packages.fluentbit.io/debian/bookworm bookworm main" \
       > /etc/apt/sources.list.d/fluent-bit.list \
    && apt-get update \
    && apt-get install -y fluent-bit \
    && rm -rf /var/lib/apt/lists/*

# ── Python зависимости для эмулятора ───────────────────────────────────────
RUN pip3 install --no-cache-dir requests --break-system-packages

# ── Директории ────────────────────────────────────────────────────────────
RUN mkdir -p \
    /var/log/osquery \
    /var/log/fluent-bit \
    /var/lib/fluent-bit \
    /etc/osquery \
    /scripts \
    /var/run/sshd

# ── SSH настройка (для эмуляции логинов) ──────────────────────────────────
RUN echo 'root:testpass123' | chpasswd \
    && useradd -m -s /bin/bash testuser \
    && echo 'testuser:testpass123' | chpasswd \
    && useradd -m -s /bin/bash devuser \
    && echo 'devuser:testpass123' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ── entrypoint ────────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
