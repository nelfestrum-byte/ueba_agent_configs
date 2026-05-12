#!/usr/bin/env bash
# Отправить семпл auditd-события (execve syscall) на порт 5045 Logstash.
# Порт 5045 — tcp input, codec => json_lines.
#
# Требуется: nc (netcat) или socat
# Использование: bash dev_stand/scripts/send-auditd.sh [logstash_host] [port]

HOST="${1:-localhost}"
PORT="${2:-5045}"

# Семпл: auditd SYSCALL type=59 (execve) — запуск /usr/bin/ls от имени root
PAYLOAD=$(cat <<'EOF'
{"type":"SYSCALL","syscall":"59","exe":"/usr/bin/ls","pid":"1234","ppid":"100","uid":"0","gid":"0","auid":"1000","comm":"ls","hostname":"dev-host-01","@timestamp":"2026-05-12T10:00:00.000Z","tags":["auditd"]}
EOF
)

echo "Отправка auditd-события на ${HOST}:${PORT}..."
echo "${PAYLOAD}" | nc -q1 "${HOST}" "${PORT}" 2>/dev/null \
  || echo "${PAYLOAD}" | socat - "TCP:${HOST}:${PORT}" 2>/dev/null \
  || { echo "Ошибка: nc и socat недоступны"; exit 1; }
echo "Отправлено. Проверьте: GET /process-events-*/_search?size=1 в Dashboards Dev Tools"
