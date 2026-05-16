Анализ проекта UEBA-stand
1. Оценка текущего подхода
Что сделано сильно
Архитектура сбора: разделение auditd → fluent-bit (Lua merge+enrich) → Logstash → OpenSearch концептуально верное и соответствует современной практике замены auditbeat (который конфликтует за netlink). Авторы fluent-operator и сообщество Falco используют ровно тот же паттерн — Lua-фильтр вместо цепочки multiline+grep Lua filter docs.

Объединение по serial в auditd_merge.lua — правильное решение проблемы «один event = N строк». Wall-clock timeout как fallback для auditd 4.x (нет EOE) — это та грабля, на которой массово спотыкаются (см. GitHub issues fluent-bit и Mint Security blog).

osquery — diff-only, disable_audit=true — корректно, нет двойного netlink-conflict. Тестовый плейбук tests/osquery/osquery-trigger.yml покрывает 13/23 таблицы — это уже выше среднего для OSS-стендов.

ECS 8.11 нормализация на стороне агента — даёт компактные пайплайны в Logstash и снимает нагрузку с центрального узла (горизонтальное масштабирование).

Слабые места и риски
#	Проблема	Файл/строка	Влияние
1	Нет process.entity_id / process.parent.entity_id — невозможно строить process tree в SIEM	auditd_enrich.lua:122	UEBA-скоринг без отцовско-дочерних связей деградирует
2	host.name вычисляется через io.popen("hostname -f") на старте — кэшируется, но fork+exec на каждый запуск fluent-bit. На больших флитах — шум в audit-логе самого себя	auditd_enrich.lua:65-76, osquery_enrich.lua:186-197	Косметика, но в auditd execve будет ловиться hostname от fluent-bit
3	Lua merge — глобальный stateful буфер: при рестарте fluent-bit все незакрытые serial теряются. Нет watchdog-метрики «buffer drops»	auditd_merge.lua:15-18	Потеря событий при reload
4	TCP без TLS на 5045/5047 — Format json_lines в plaintext через сеть	fluent-bit.conf:91-101	Перехват/инъекция. README признаёт это
5	Нет правил auditd для io_uring — современный (2024–2026) bypass-вектор. RingReaper и кучка PoC обходят и auditd, и Falco через io_uring_setup/enter Sysdig, ARMO	audit.rules	Слепая зона
6	Нет ptrace, process_vm_writev, memfd_create, bpf — стандартные вектора инъекций	audit.rules	Слепая зона
7	osquery.conf — все процессы interval: 30, process_open_files: 60 — на серверах с ~500 процессами это 30+ MB на хост в час. Watchdog ограничен 350 MB — есть запас, но без replicate-аномалий это шум	osquery.conf:50,140	Шум, расход места
8	Lua-скрипт читает в MITRE_TAGS закомментированный блок — мёртвый код auditd_enrich.lua:46-61	enrich	Технический долг
9	parsers.conf парсер auditd_user_msg определён, но нигде не используется	parsers.conf:13-16	Мёртвый код
10	Тесты — только osquery diff. Нет тестов для auditd merge-логики, ECS-enrichment, Lua-функций, integration на Logstash	tests/	Регрессии при правках Lua
11	Нет index templates / component templates для OpenSearch — типы полей process.args[], file.hash.* определяются динамически (это указано в README как известное ограничение)	logstash/	Конфликты типов
12	Filebeat — отдельная сущность только под SSH. CLAUDE.md помечает как «временный», но fluent-bit system.auth парсер тривиален	filebeat.yml.j2	Технический долг
13	В osquery_enrich.lua для processes используется cols["parent"] как process.parent.pid, но нет JOIN с processes parent — process.parent.name отсутствует, хотя запрос processes в osquery.conf уже его подтягивает (parent_name)	osquery_enrich.lua:273	Потеря данных
14	Нет sysmon-аналога для Linux (sysmonForLinux / Sysdig Falco) — auditd не видит DNS, TLS SNI, file hashes	архитектура	Полнота UEBA-features
2. Архитектурное расширение
A. Закрыть бреши в видимости
A1. Добавить правила auditd для современных вектор-байпасов (Singularity rootkit, Copy Fail CVE-2026-31431):


# io_uring (новый bypass-вектор — обязательно)
-a always,exit -F arch=b64 -S io_uring_setup,io_uring_enter,io_uring_register -F auid>=1000 -F auid!=-1 -k io_uring
# Process injection
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S process_vm_writev -k process_injection
# Fileless exec
-a always,exit -F arch=b64 -S memfd_create -k fileless_exec
# eBPF abuse
-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=-1 -k ebpf_use
# AF_ALG (Copy Fail)
-a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg
# Container-escape
-a always,exit -F arch=b64 -S unshare,setns -k container_escape
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mount_action
# Anti-forensics
-w /var/log/audit/ -p wa -k audit_log_tamper
-w /usr/sbin/auditctl -p x -k audit_tool_use
-w /usr/sbin/auditd -p x -k audit_tool_use
Следовать Neo23x0/auditd с одной оговоркой: фильтровать по auid>=1000 -F auid!=unset — это исключает kernel/systemd-юзеров и сокращает объём логов в 3–5×.

A2. Расширить osquery событиями (evented tables) — но в отдельном файле/деплое, чтобы не ломать существующий контракт disable_audit=true. Альтернатива — BPF backend osquery (--enable_bpf_events) на ядрах ≥ 5.10: даёт process_events, socket_events, bpf_process_events без netlink-конкуренции с auditd. См. Process Auditing osquery docs.

A3. DNS/TLS-видимость. Auditd не видит DNS-резолвы и SNI. Варианты:

Zeek (sensor режим, eBPF) — пишет conn.log/dns.log/ssl.log → fluent-bit → новый TCP-порт.
Suricata уже есть в pipeline (порт 5049) — добавить dns event_type в if "suricata" in [tags] блок Logstash.
A4. Закрыть SSH через fluent-bit. Filebeat сейчас единственная причина зависимости от Elastic-репозитория. Заменить на:


[INPUT]  tail /var/log/auth.log → parser sshd → enrich (ECS: event.category=authentication, source.ip из "Failed password from ...")
[OUTPUT] tcp 5048 → Logstash → filebeat-* (для совместимости) или ssh-* (новый индекс)
B. Корректность данных
B1. process.entity_id (детерминированный hash). Без него UEBA не построит process-tree. ECS-стандарт (Process fields) — это hash(host.id + pid + start_time). В Lua:


-- В auditd_enrich.lua после установки process.pid
if record["process.pid"] then
    local id_seed = (record["host.name"] or "") .. ":" ..
                    record["process.pid"] .. ":" ..
                    (record["@timestamp"] or "")
    record["process.entity_id"] = sha256_short(id_seed)  -- первые 16 hex
end
То же для process.parent.entity_id (потребует кэш PID→start_time, аналогично merge-буферу).

B2. Кэш host.name — читать /etc/hostname один раз через io.open вместо fork hostname -f:


local function get_hostname()
    if _hostname then return _hostname end
    local f = io.open("/proc/sys/kernel/hostname", "r")
    if f then _hostname = f:read("*l"):gsub("%s+$", ""); f:close() end
    return _hostname or "unknown"
end
B3. Persistence merge-буфера. Если есть риск потери — сериализовать buf в /var/lib/fluent-bit/audit-merge.state на SIGTERM (hook через [FILTER] lua не поддерживает, но можно — внешний sidecar или просто оставить как known-limitation в CLAUDE.md).

B4. Декорирование osquery_enrich.lua — пробросить parent_name/process_name в process.parent.name:


if cols["parent_name"] then record["process.parent.name"] = cols["parent_name"] end
C. Безопасность канала
mTLS Beats input (Logstash) вместо TCP json_lines. Fluent-bit output forward + filebeat-протокол совместимый Beats input. Стандарт для прода — см. предупреждение из README.

D. Index templates
Создать logstash/configs/templates/fluent-audit.json и fluent-osquery.json с явными keyword/ip/long для:

process.entity_id (keyword)
source.ip, destination.ip (ip)
process.args (keyword[])
file.hash.{md5,sha256} (keyword)
event.outcome, event.category, event.action (keyword, constant_keyword где можно)
Применять через template_overwrite в Logstash output или вручную _index_template в OpenSearch.

3. Количественное расширение покрытия
D.1. Auditd — добавить 7 keys (помимо A1)
Key	Syscalls/Watch	Зачем
unauthorized_access	-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -F auid>=1000	Brute-force file probing, recon
unauthorized_access	-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -F auid>=1000	То же, другой код
password_changes	-w /etc/shadow -p wa, -w /usr/bin/passwd -p x, -w /usr/bin/chage -p x	Уже есть /etc/shadow, добавить exec
keyring_access	-a always,exit -F arch=b64 -S add_key,request_key,keyctl	Theft of stored credentials
power_state	-a always,exit -F arch=b64 -S reboot	Anti-forensics
swap_modify	-a always,exit -F arch=b64 -S swapon,swapoff	LD_PRELOAD prep
container_runtime	-w /var/run/docker.sock -p rwa, -w /run/containerd/containerd.sock -p rwa	Docker socket abuse → host compromise
D.2. osquery — добавить ~10 запросов
Запрос	Интервал	Цель
shell_history	300	tracking interactive shells (bash_history, zsh_history rotation)
last (utmp)	300	сессии login/logout с источником
process_envs (для процессов с LD_PRELOAD, LD_AUDIT)	60	classic preload injection
chrome_extensions, firefox_addons	3600	малвара через расширения (актуально для workstations)
python_packages, npm_packages, pip_packages	7200	supply-chain (dependency confusion / typosquatting)
process_memory_map для нестандартных бинарей (p.path NOT LIKE '/usr/%')	300	shared object hijack
acpi_tables	86400	firmware tampering (low freq)
kernel_keys	600	посаженные kerberos/keychain ключи
deb_packages diff (без count)	3600	новые пакеты на хосте
bpf_process_events (если BPF backend включён)	event-driven	замена auditd по execve с PID-неймспейсом
Идею «zero rows during normal» взять из chainguard-dev/osquery-defense-kit — там 250+ запросов уже отстроены под этот формат.

D.3. Новые pipeline-источники
Источник	Порт	Индекс	Назначение UEBA
Zeek (conn/dns/ssl/files)	5050 (TCP json)	zeek-*	DNS-аномалии, beaconing, SNI heuristics
Sysmon for Linux (если решите)	5046 (уже зарезервирован для Windows)	sysmonlinux-*	дублирование auditd для cross-verification
osquery-events (BPF)	5051	osquery-events-*	низкоуровневые socket/process events
4. Новые тесты
Сейчас тесты — только tests/osquery/osquery-trigger.yml. Что добавить:

4.1. Unit-тесты Lua-функций (tests/lua/)

tests/lua/
  run.sh                          # запуск всех под busted/luaunit
  test_auditd_merge.lua           # серии записей с разными serial, EOE, timeout flush
  test_auditd_enrich.lua          # фикстуры raw → проверка ECS полей
  test_osquery_enrich.lua         # фикстуры osquery JSON → проверка mapping
  fixtures/
    execve_simple.txt             # SYSCALL+EXECVE+PATH+CWD+PROCTITLE
    execve_long_args.txt          # 64+ аргумента
    sshd_login.txt                # USER_LOGIN+USER_AUTH+CRED_ACQ
    sudo_command.txt              # USER_CMD+SYSCALL
    serial_split_across_files.txt # timeout-флаш
    no_eoe_auditd4.txt            # auditd 4.x без EOE
Запускать в CI через lua5.3 + busted (Docker-обёртка тривиальна). Покрытие — критично, потому что Lua merge — самый хрупкий узел системы, и регресс там тих и катастрофичен.

4.2. Integration-тесты pipeline (tests/pipeline/)

tests/pipeline/
  docker-compose.test.yml          # logstash + opensearch + fluent-bit
  fixtures/audit/                  # raw audit.log семплы
  fixtures/osquery/                # raw osquery results.log семплы
  fixtures/expected/               # ожидаемые JSON-документы в индексах
  run.sh                           # запуск, ожидание индексации, diff с expected
Сценарий: подложить семпл в /var/log/audit/audit.log → запустить fluent-bit → проверить в OpenSearch через _search, что документ содержит ожидаемые ECS-поля (assertion: event.category=="process", process.entity_id непустой и т.п.).

4.3. Auditd trigger plays (по аналогии с osquery-trigger.yml)
tests/auditd/auditd-trigger.yml — Ansible-плейбук с режимами apply/rollback:

Действие	Ожидаемый key
useradd osq-aud-test	user_changes
chmod u+s /tmp/testbin	binary_modification (нет ключа — добавить)
sudo -u nobody true	sudo_exec
ssh-keygen + добавление в authorized_keys	ssh_keys
iptables -I INPUT ...	(нет в auditd) → проверка osquery iptables
insmod /tmp/dummy.ko (поднять пустой модуль)	module_load
python3 -c "import socket; s=socket.socket(); s.bind(...); s.listen()"	socket_bind, socket_listen
touch /tmp/x; chmod 4755 /tmp/x	tmp_write
cp /usr/bin/ls /tmp/ls; /tmp/ls	suspicious_exec
date -s "..." (откатить!)	time_change
io_uring PoC (RingReaper-lite)	io_uring (новый)
python3 -c "import ctypes; ctypes.CDLL('libc.so.6').ptrace(...)"	process_injection
python3 -c "import os; fd=os.memfd_create('x',0); ..."	fileless_exec
Каждый таск → ассерт «искомый key появился в fluent-audit-* индексе за N секунд».

4.4. Property-based для merge-buffer
tests/property/merge_fuzz.py: генератор случайных перестановок auditd-строк с одним serial — проверять, что независимо от порядка пришедших записей итоговый merged-объект изоморфен. Это ловит race-conditions в Lua-буфере.

4.5. Lint / smoke в CI
ansible-playbook --syntax-check для всех playbook (есть в CLAUDE.md, но не в CI).
logstash -t -f logstash/configs/pipeline/ueba-main.conf (через Docker) для проверки синтаксиса.
fluent-bit --dry-run -c agents/configs/fluent-bit/fluent-bit.conf.
osqueryi --config_path=osquery.conf --config_check.
luacheck для всех .lua в agents/configs/fluent-bit/scripts/.
GitHub Actions workflow .github/workflows/lint.yml — закрывает регресс «правка Lua → fluent-bit падает в проде».

5. Приоритизация (что делать в первую очередь)
Приоритет	Задача	Стоимость	Эффект
P0	process.entity_id в Lua (B1)	1 час	Делает данные пригодными для UEBA
P0	Unit-тесты Lua merge + enrich (4.1)	1 день	Защита от регрессов в самом хрупком месте
P0	Auditd-правила: io_uring, ptrace, memfd_create, bpf (A1)	2 часа	Закрывает современные bypass-векторы
P1	mTLS Beats input для fluent-bit (C)	1 день	Безопасность канала
P1	Index templates ECS (D)	4 часа	Стабильность маппингов
P1	auditd-trigger.yml тестовый плейбук (4.3)	1 день	Симметрия с osquery-trigger.yml
P2	Заменить filebeat на fluent-bit ssh-pipeline (A4)	0.5 дня	Убрать Elastic apt-зависимость
P2	Zeek/Suricata DNS поток (A3)	2 дня	DNS-видимость для UEBA
P2	BPF backend osquery (A2)	1 день	Низкоуровневые события
P3	luacheck/dry-run в CI (4.5)	4 часа	Гигиена
P3	Property-based merge fuzz (4.4)	0.5 дня	Edge cases
Источники
Neo23x0/auditd Best Practice Configuration — эталонный auditd ruleset
Mint Security: optimizing Florian Roth auditd rules — как чистить высокочастотный шум
Linux auditd for Threat Detection — IzyKnows
chainguard-dev/osquery-defense-kit — 250+ production-ready запросов
palantir/osquery-configuration
osquery incident-response pack
osquery process auditing — BPF backend
Sysdig: Detecting io_uring abuse
ARMO: io_uring rootkit bypass
The Hacker News: io_uring PoC rootkit
ECS Process fields (entity_id)
Auditbeat exported fields
Fluent Bit Lua filter docs
Elastic Security ECS field reference