#!/usr/bin/env bash
# Отправить семпл osquery diff-события (new_listening_ports) на порт 5048 Logstash.
# Порт 5048 — tcp input, codec => json_lines.
#
# Требуется: nc (netcat) или socat
# Использование: bash dev_stand/scripts/send-osquery.sh [logstash_host] [port]

HOST="${1:-localhost}"
PORT="${2:-5048}"

# Семпл: osquery diff — появился новый слушающий порт 4444 (подозрительно)
PAYLOAD=$(cat <<'EOF'
{"name":"new_listening_ports","action":"added","columns":{"pid":"5678","port":"4444","protocol":"6","address":"0.0.0.0","path":"/tmp/backdoor"},"decorations":{"hostname":"dev-host-01","osquery_version":"5.22.1"},"@timestamp":"2026-05-12T10:10:00.000Z","tags":["osquery"]}
EOF
)

echo "Отправка osquery diff-события на ${HOST}:${PORT}..."
echo "${PAYLOAD}" | nc -q1 "${HOST}" "${PORT}" 2>/dev/null \
  || echo "${PAYLOAD}" | socat - "TCP:${HOST}:${PORT}" 2>/dev/null \
  || { echo "Ошибка: nc и socat недоступны"; exit 1; }
echo "Отправлено. Проверьте: GET /config-events-*/_search?size=1 в Dashboards Dev Tools"
