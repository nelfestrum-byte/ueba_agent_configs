#!/usr/bin/env bash
# Отправить семпл sshd-события (успешный логин) на порт 5048 Logstash.
# Порт 5048 — fluent-bit system-auth TCP input, codec => json_lines.
#
# Payload имитирует то, что fluent-bit отправляет ПОСЛЕ всех фильтров:
#   systemd INPUT → modify (rename journald fields) → sshd_enrich.lua → record_modifier
# Т.е. это ECS-обогащённый JSON, не сырой journald.
#
# Требуется: nc (netcat) или socat
# Использование: bash dev_stand/scripts/send-sshd.sh [logstash_host] [port]

HOST="${1:-localhost}"
PORT="${2:-5048}"

# Семпл: sshd Accepted password — то, что fluent-bit шлёт в Logstash после enrich
PAYLOAD=$(cat <<'EOF'
{"@timestamp":"2026-05-22T10:05:00.000Z","ecs.version":"8.11","event.dataset":"system.auth","event.module":"system","event.kind":"event","event.category":"authentication","event.action":"ssh_login","event.type":"start","event.outcome":"success","process.name":"sshd","process.pid":12345,"host.name":"dev-host-01","host.os.type":"linux","host.os.family":"linux","tags":["system-auth","fluent-bit","linux"],"user.name":"testuser","related.user":["testuser"],"source.ip":"10.0.0.55","source.port":54321,"related.ip":["10.0.0.55"],"message":"Accepted password for testuser from 10.0.0.55 port 54321 ssh2","agent.name":"fluent-bit","agent.type":"filebeat-compat","data_stream.type":"logs","data_stream.dataset":"system.auth","data_stream.namespace":"security"}
EOF
)

echo "Отправка sshd-события на ${HOST}:${PORT}..."
echo "${PAYLOAD}" | nc -q1 "${HOST}" "${PORT}" 2>/dev/null \
  || echo "${PAYLOAD}" | socat - "TCP:${HOST}:${PORT}" 2>/dev/null \
  || { echo "Ошибка: nc и socat недоступны"; exit 1; }
echo "Отправлено. Проверьте: GET /system-auth-*/_search?size=1 в Dashboards Dev Tools"
