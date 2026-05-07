#!/bin/bash
# =============================================================================
# emulator.sh — эмулятор поведения пользователя для UEBA стенда
#
# Использование:
#   bash /scripts/emulator.sh --scenario normal     # фоновый шум
#   bash /scripts/emulator.sh --scenario anomaly    # аномальные события
#   bash /scripts/emulator.sh --scenario attack     # цепочка атаки
#   bash /scripts/emulator.sh --scenario all        # все сценарии по очереди
#   bash /scripts/emulator.sh --scenario normal --background  # фоновый режим
#   bash /scripts/emulator.sh --scenario anomaly --repeat 5  # повторить N раз
# =============================================================================

set -euo pipefail

SCENARIO="normal"
BACKGROUND=false
REPEAT=1
DELAY_BETWEEN=2   # секунды между действиями

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

log()    { echo -e "${CYAN}[$(date '+%H:%M:%S')] [EMU]${NC} $*"; }
ok()     { echo -e "${GREEN}[$(date '+%H:%M:%S')] [OK ]${NC} $*"; }
warn()   { echo -e "${YELLOW}[$(date '+%H:%M:%S')] [WRN]${NC} $*"; }
bad()    { echo -e "${RED}[$(date '+%H:%M:%S')] [BAD]${NC} $*"; }
action() { echo -e "${PURPLE}[$(date '+%H:%M:%S')] [ACT]${NC} $*"; }

# Разбор аргументов
while [[ $# -gt 0 ]]; do
    case $1 in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --background) BACKGROUND=true; shift ;;
        --repeat) REPEAT="$2"; shift 2 ;;
        --delay) DELAY_BETWEEN="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

pause() { sleep "${DELAY_BETWEEN}"; }

# =============================================================================
# УТИЛИТЫ
# =============================================================================

# Безопасное выполнение команды с логированием
run() {
    local desc="$1"; shift
    action "$desc"
    eval "$@" 2>/dev/null || true
    pause
}

# Создать временный файл и выполнить из него
exec_from_path() {
    local path="$1"
    local cmd="$2"
    mkdir -p "$(dirname "$path")"
    echo "#!/bin/bash" > "$path"
    echo "$cmd" >> "$path"
    chmod +x "$path"
    bash "$path" 2>/dev/null || true
    rm -f "$path"
}

# =============================================================================
# СЦЕНАРИЙ: NORMAL — типичная активность разработчика
# Создаёт baseline для AD детекторов
# =============================================================================
scenario_normal() {
    log "=== NORMAL: типичная активность разработчика ==="

    # Рабочий цикл — повторяем чтобы набрать baseline
    local cycles=${1:-3}
    for i in $(seq 1 "$cycles"); do
        log "Цикл $i/$cycles"

        # Обычные системные команды
        run "Проверка системы"       "uname -a; uptime; free -m"
        run "Список процессов"       "ps aux | head -20"
        run "Сетевые соединения"     "ss -tlnp | head -10"
        run "Дисковое пространство"  "df -h"
        run "Загруженные модули"     "lsmod | head -10"
        run "Маршрутная таблица"     "ip route show"

        # Работа с файлами (типичная для разработчика)
        run "Создание рабочей директории" "mkdir -p /tmp/workspace/project"
        run "Запись файла"                "echo 'print(\"hello\")' > /tmp/workspace/project/test.py"
        run "Запуск Python скрипта"       "python3 /tmp/workspace/project/test.py"
        run "Проверка git"                "git --version; git config --global user.name 'Test User'"

        # Сетевая активность (типичные соединения)
        run "DNS резолюция"         "getent hosts localhost || true"
        run "Проверка локального порта" "nc -z localhost 22 && echo 'SSH port open' || true"

        # Управление пользователями (типичное чтение)
        run "Чтение /etc/passwd"    "wc -l /etc/passwd"
        run "Текущие пользователи"  "who; id"

        # Cron — чтение существующих задач
        run "Список cron задач"     "crontab -l 2>/dev/null || true; ls /etc/cron.d/"

        # Пауза между циклами — в фоновом режиме дольше
        if [ "$BACKGROUND" = "true" ]; then
            log "Пауза 60с перед следующим циклом (background mode)"
            sleep 60
        else
            sleep 5
        fi
    done

    ok "NORMAL сценарий завершён"
}

# =============================================================================
# СЦЕНАРИЙ: ANOMALY — аномальные но не явно вредоносные события
# Должен поднять score через AD + детерминированные правила
# =============================================================================
scenario_anomaly() {
    log "=== ANOMALY: аномальные действия ==="

    # 1. Вход в нерабочее время (is_offhours=true)
    # Записываем в auth.log напрямую чтобы simulated auditd поймал
    warn "Симуляция: SSH логин в ночное время"
    run "SSH сессия в нерабочее время (logger)" \
        "logger -p auth.info -t sshd 'Accepted password for testuser from 10.0.1.99 port 54321'"
    logger -p auth.warning -t sshd "session opened for user testuser by (uid=0)" 2>/dev/null || true
    pause

    # 2. Запуск процесса из /tmp (suspicious path)
    warn "Запуск процесса из /tmp"
    exec_from_path "/tmp/.hidden_script" "echo 'running from tmp'; sleep 1; uname -a"
    pause

    # 3. Запуск из /dev/shm (очень подозрительно)
    warn "Запуск процесса из /dev/shm"
    exec_from_path "/dev/shm/probe" "id; whoami; hostname"
    pause

    # 4. Открытие нового нетипичного порта
    warn "Открытие нового слушающего порта (4444)"
    run "Открыть порт 4444 на 5 секунд" \
        "nc -l -p 4444 &
         NC_PID=\$!
         sleep 5
         kill \$NC_PID 2>/dev/null || true"
    pause

    # 5. Добавление cron задачи
    warn "Добавление новой cron задачи"
    run "Добавить задачу в crontab" \
        "(crontab -l 2>/dev/null; echo '*/15 * * * * /tmp/check.sh') | crontab -"
    pause

    # 6. Добавление SSH ключа
    warn "Добавление нового SSH authorized_key"
    run "Добавить SSH ключ" \
        "mkdir -p /root/.ssh
         echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7test_anomaly_key_for_ueba_stand anomaly@test' >> /root/.ssh/authorized_keys"
    pause

    # 7. Аномальное количество процессов (запустить пачку)
    warn "Запуск большого числа процессов"
    run "Запустить 50 фоновых процессов" \
        "for i in \$(seq 1 50); do sleep 10 & done
         echo 'Spawned 50 processes'
         sleep 3
         kill \$(jobs -p) 2>/dev/null || true"
    pause

    # 8. Новое сетевое соединение на нестандартный адрес
    warn "Подключение к нестандартному адресу"
    run "Попытка подключения на нетипичный порт" \
        "nc -z -w 2 8.8.8.8 53 2>/dev/null || true
         nc -z -w 2 172.28.0.10 9200 2>/dev/null || true"
    pause

    # 9. Чтение /etc/shadow (попытка)
    warn "Попытка чтения /etc/shadow"
    run "Читаем /etc/shadow" \
        "cat /etc/shadow 2>/dev/null | wc -l || echo 'access denied'"
    pause

    # 10. Изменение /etc/hosts
    warn "Изменение /etc/hosts"
    run "Добавить запись в /etc/hosts" \
        "echo '10.0.0.1 malicious-c2.internal' >> /etc/hosts"
    # Откатываем
    sed -i '/malicious-c2.internal/d' /etc/hosts 2>/dev/null || true
    pause

    # Убираем созданные артефакты
    crontab -l 2>/dev/null | grep -v 'check.sh' | crontab - 2>/dev/null || true
    sed -i '/anomaly@test/d' /root/.ssh/authorized_keys 2>/dev/null || true

    ok "ANOMALY сценарий завершён — проверьте score в scoring service"
}

# =============================================================================
# СЦЕНАРИЙ: ATTACK — цепочка действий реальной атаки
# Имитирует: initial access → разведка → persistence → lateral movement
# =============================================================================
scenario_attack() {
    bad "=== ATTACK: цепочка атаки ==="
    bad "Внимание: это тестовый сценарий для стенда"

    # ── Фаза 1: Initial access ──────────────────────────────────────────────
    bad "--- Фаза 1: Initial Access ---"

    warn "Успешный логин с нового IP"
    logger -p auth.info -t sshd \
        "Accepted publickey for root from 192.168.100.200 port 43210 ssh2" 2>/dev/null || true
    pause

    # ── Фаза 2: Разведка (Reconnaissance) ─────────────────────────────────
    bad "--- Фаза 2: Разведка ---"

    run "whoami / id"           "whoami; id; groups"
    run "Информация об ОС"      "uname -a; cat /etc/os-release"
    run "Сетевая разведка"      "ip addr show; ip route show; ss -tlnp"
    run "Пользователи системы"  "cat /etc/passwd | grep -v nologin | grep -v false"
    run "sudo права"            "sudo -l 2>/dev/null || true"
    run "Запущенные процессы"   "ps aux"
    run "Cron задачи"           "crontab -l 2>/dev/null; ls -la /etc/cron*"
    run "SUID файлы (разведка)" "find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | head -10"
    run "SSH ключи"             "ls -la /root/.ssh/ 2>/dev/null || true"

    # ── Фаза 3: Persistence ────────────────────────────────────────────────
    bad "--- Фаза 3: Persistence ---"

    # Backdoor в /tmp
    warn "Создание бэкдора в /tmp"
    cat > /tmp/.sys_update << 'BACKDOOR'
#!/bin/bash
# Simulated backdoor for UEBA testing
while true; do
    sleep 300
    echo "beacon $(date)" >> /tmp/.beacons.log
done
BACKDOOR
    chmod +x /tmp/.sys_update
    /tmp/.sys_update &
    BACKDOOR_PID=$!
    log "Backdoor PID: $BACKDOOR_PID"
    pause

    # SSH ключ для персистентности
    warn "Добавление backdoor SSH ключа"
    mkdir -p /root/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB attack_persistence_key attacker@c2" \
        >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    pause

    # Cron для персистентности
    warn "Добавление cron persistence"
    (crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.sys_update >> /dev/null 2>&1") | crontab -
    pause

    # ── Фаза 4: Privilege Escalation ──────────────────────────────────────
    bad "--- Фаза 4: Privilege Escalation ---"

    run "Поиск SUID бинарей"    "find / -perm -4000 -type f 2>/dev/null | head -5"
    run "Чтение /etc/shadow"    "cat /etc/shadow 2>/dev/null | head -3 || echo 'permission denied'"
    run "Проверка sudo"         "sudo -l 2>/dev/null | head -5 || true"
    pause

    # ── Фаза 5: Lateral Movement / C2 ─────────────────────────────────────
    bad "--- Фаза 5: C2 Communication ---"

    # Открываем нестандартный порт для "C2"
    warn "Открытие C2 порта (4444)"
    nc -l -p 4444 &
    C2_PID=$!
    sleep 3

    # Попытки подключения к внешним адресам
    warn "Beacon к C2 серверу"
    run "Попытка C2 соединения" \
        "for host in 10.0.0.1 172.16.0.1 192.168.1.1; do
             nc -z -w 2 \$host 4444 2>/dev/null && echo \"Connected to \$host\" || true
         done"

    # Запуск из /dev/shm (в памяти)
    warn "Запуск payload из /dev/shm"
    exec_from_path "/dev/shm/.x86_elf" \
        "echo 'Payload executing from memory'; id; cat /etc/passwd | wc -l"
    pause

    # ── Фаза 6: Data Exfiltration (симуляция) ─────────────────────────────
    bad "--- Фаза 6: Simulated Data Collection ---"

    run "Сбор данных" \
        "find /etc -name '*.conf' 2>/dev/null | head -10 > /tmp/.loot.txt
         cat /etc/hosts >> /tmp/.loot.txt
         echo 'loot size:' \$(wc -l < /tmp/.loot.txt)"
    pause

    # ── Cleanup ────────────────────────────────────────────────────────────
    bad "--- Завершение: откат артефактов ---"

    kill "$BACKDOOR_PID" 2>/dev/null || true
    kill "$C2_PID"       2>/dev/null || true
    rm -f /tmp/.sys_update /tmp/.beacons.log /tmp/.loot.txt /dev/shm/.x86_elf
    crontab -l 2>/dev/null | grep -v 'sys_update' | crontab - 2>/dev/null || true
    sed -i '/attack_persistence_key/d' /root/.ssh/authorized_keys 2>/dev/null || true

    bad "ATTACK сценарий завершён"
    bad "Ожидаем высокий score (critical) в scoring service"
    bad "Проверьте алерт в TheHive"
}

# =============================================================================
# СЦЕНАРИЙ: BUILDUP — постепенное наращивание аномалий
# Для тестирования decay и накопления score
# =============================================================================
scenario_buildup() {
    log "=== BUILDUP: постепенное накопление score ==="

    log "Шаг 1: Нормальная активность (score должен быть низким)"
    scenario_normal 1

    log "Пауза 30с — ждём decay..."
    sleep 30

    log "Шаг 2: Первая аномалия (+небольшой score)"
    exec_from_path "/tmp/.probe1" "id"
    pause

    log "Пауза 20с..."
    sleep 20

    log "Шаг 3: Вторая аномалия (score растёт)"
    run "Новый порт" "nc -l -p 5555 & sleep 3; kill %1 2>/dev/null || true"
    pause

    log "Шаг 4: Третья аномалия (корреляционный бустер ≥3 метрик)"
    logger -p auth.info -t sshd \
        "Accepted password for testuser from 10.0.1.50 port 11111" 2>/dev/null || true
    exec_from_path "/var/tmp/.probe2" "uname -a"
    run "Добавление SSH ключа" \
        "echo 'ssh-rsa AAAAbuildup_key test@test' >> /root/.ssh/authorized_keys"
    pause

    # Откат
    sed -i '/buildup_key/d' /root/.ssh/authorized_keys 2>/dev/null || true
    rm -f /var/tmp/.probe2

    ok "BUILDUP завершён — наблюдайте за ростом score в реальном времени"
}

# =============================================================================
# ЗАПУСК
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       UEBA Emulator v1.0                 ║"
echo "║  Scenario: ${SCENARIO}$(printf '%*s' $((24-${#SCENARIO})) '')║"
echo "╚══════════════════════════════════════════╝"
echo ""

for i in $(seq 1 "$REPEAT"); do
    if [ "$REPEAT" -gt 1 ]; then
        log "=== Итерация $i/$REPEAT ==="
    fi

    case "$SCENARIO" in
        normal)  scenario_normal 3 ;;
        anomaly) scenario_anomaly ;;
        attack)  scenario_attack ;;
        buildup) scenario_buildup ;;
        all)
            scenario_normal 1
            sleep 10
            scenario_anomaly
            sleep 30
            scenario_attack
            ;;
        *)
            echo "Неизвестный сценарий: $SCENARIO"
            echo "Доступные: normal, anomaly, attack, buildup, all"
            exit 1
            ;;
    esac

    if [ "$REPEAT" -gt 1 ] && [ "$i" -lt "$REPEAT" ]; then
        log "Пауза 60с перед следующей итерацией..."
        sleep 60
    fi
done

echo ""
ok "Эмулятор завершил работу"
echo ""
echo "Что проверить в OpenSearch:"
echo "  GET host-metrics-*/_search      — метрики от osquery"
echo "  GET auth-events-*/_search       — события аутентификации"
echo "  GET process-events-*/_search    — события процессов"
echo "  GET config-events-*/_search     — конфигурационные изменения"
