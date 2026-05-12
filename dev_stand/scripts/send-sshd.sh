#!/usr/bin/env bash
# Отправить семпл sshd-события (успешный логин) на порт 5047 Logstash.
# Порт 5047 — tcp input, codec => json_lines.
#
# Требуется: nc (netcat) или socat
# Использование: bash dev_stand/scripts/send-sshd.sh [logstash_host] [port]

HOST="${1:-localhost}"
PORT="${2:-5047}"

# Семпл: sshd Accepted password (формат systemd journal JSON)
PAYLOAD=$(cat <<'EOF'
{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for testuser from 10.0.0.55 port 54321 ssh2","_HOSTNAME":"dev-host-01","@timestamp":"2026-05-12T10:05:00.000Z","tags":["sshd"]}
EOF
)

echo "Отправка sshd-события на ${HOST}:${PORT}..."
echo "${PAYLOAD}" | nc -q1 "${HOST}" "${PORT}" 2>/dev/null \
  || echo "${PAYLOAD}" | socat - "TCP:${HOST}:${PORT}" 2>/dev/null \
  || { echo "Ошибка: nc и socat недоступны"; exit 1; }
echo "Отправлено. Проверьте: GET /auth-events-*/_search?size=1 в Dashboards Dev Tools"
