#!/bin/bash
set -e

echo "[entrypoint] Starting UEBA Debian Agent..."

# ── Ждём Logstash ──────────────────────────────────────────────────────────
echo "[entrypoint] Waiting for Logstash at ${LOGSTASH_HOST}:5048..."
for i in $(seq 1 30); do
    if nc -z "${LOGSTASH_HOST}" 5048 2>/dev/null; then
        echo "[entrypoint] Logstash is ready"
        break
    fi
    echo "[entrypoint] Attempt ${i}/30, waiting 5s..."
    sleep 5
done

# ── auditd ─────────────────────────────────────────────────────────────────
echo "[entrypoint] Starting auditd..."
# Применяем правила
if [ -f /etc/audit/rules.d/ueba.rules ]; then
    cp /etc/audit/rules.d/ueba.rules /etc/audit/rules.d/ueba.rules.applied
fi
auditd -n &
sleep 2
auditctl -R /etc/audit/rules.d/ueba.rules 2>/dev/null || echo "[entrypoint] auditctl: rules may not all apply in container"

# ── rsyslog (нужен для /var/log/auth.log — sshd пишет через него) ─────────────
echo "[entrypoint] Starting rsyslog..."
rsyslogd

# ── sshd ───────────────────────────────────────────────────────────────────
echo "[entrypoint] Starting sshd..."
/usr/sbin/sshd

# ── osquery ────────────────────────────────────────────────────────────────
echo "[entrypoint] Starting osquery..."
# --daemonize=true возвращает ненулевой exit code в Docker → set -e убивает скрипт.
# Запускаем в foreground-режиме явно через &.
osqueryd \
    --config_path=/etc/osquery/osquery.conf \
    --logger_path=/var/log/osquery \
    --pidfile=/var/run/osqueryd.pid \
    --daemonize=false \
    --disable_logging=false \
    --utc \
    --host_identifier=hostname \
    2>/var/log/osquery/osqueryd.stderr.log &

# Ждём появления лог-файла
for i in $(seq 1 20); do
    if [ -f /var/log/osquery/osqueryd.results.log ]; then
        echo "[entrypoint] osquery log found"
        break
    fi
    sleep 3
done

# ── fluent-bit ─────────────────────────────────────────────────────────────
echo "[entrypoint] Starting fluent-bit..."
/opt/fluent-bit/bin/fluent-bit \
    -c /etc/fluent-bit/fluent-bit.conf \
    > /var/log/fluent-bit/fluent-bit.log 2>&1 &

sleep 3
echo "[entrypoint] All agents started"
echo ""
echo "=========================================="
echo "  UEBA Debian Agent ready"
echo "  Hostname: $(hostname)"
echo "  Logstash: ${LOGSTASH_HOST}"
echo ""
echo "  Run emulator:"
echo "  bash /scripts/emulator.sh --scenario normal"
echo "  bash /scripts/emulator.sh --scenario anomaly"
echo "  bash /scripts/emulator.sh --scenario attack"
echo "=========================================="

# Запускаем нормальный фоновый шум
bash /scripts/emulator.sh --scenario normal --background &

# Держим контейнер живым — touch гарантирует, что файл существует до первого результата
touch /var/log/osquery/osqueryd.results.log
tail -f /var/log/osquery/osqueryd.results.log
