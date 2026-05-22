# HARDENING_PLAN — план улучшения UEBA-stand

Источник анализа: [conversation.md](conversation.md).
Формат: каждая задача — отдельный раздел с приоритетом, обоснованием, точками изменений и критерием готовности.

## Шкала приоритетов

- **P0** — критично для UEBA-скоринга или закрытие современного bypass-вектора. Делать в первую очередь.
- **P1** — стабильность, безопасность канала, гигиена данных.
- **P2** — расширение покрытия, замена временных компонентов.
- **P3** — CI/lint/fuzz, технический долг.
- **P4 (Extras)** — расширения за пределы core hardening (network-уровень, DNS/TLS-видимость). Не входят в основной план.

## Сводная таблица задач

| ID | Задача | Стоимость | Зависимости |
| --- | --- | --- | --- |
| P0-01 | `process.entity_id` и `process.parent.entity_id` в Lua-enrich | ~1 час | — |
| P0-02 | `user.session.id` — сквозной идентификатор сессии | ~2-3 часа | P0-01 (переиспользует `short_id()` и `btime`-кэш) |
| ~~P0-03~~ | ~~Замена filebeat на fluent-bit SSH-pipeline (индекс `system-auth-*`)~~ — **УДАЛЕНО** (дублирует auditd) | ~1 день | — |
| **P0-04** | **Auditd syscall rules: io_uring/ptrace/memfd_create/bpf/process_vm ✓ ВЫПОЛНЕНО 2026-05-22** | ~2-3 часа | учитывает P1-01 уточнения |
| **P1-01** | **Gap-анализ audit.rules против Neo23x0 ruleset (Tier A + Tier B) ✓ ВЫПОЛНЕНО 2026-05-22** | ~3-4 часа | — |
| **P1-02** | **ECS Index Templates для OpenSearch (2 шаблона) ✓ ВЫПОЛНЕНО 2026-05-22** | ~4 часа | после P0-01, P0-02 |
| P1-03 | mTLS канал fluent-bit → Logstash | ~1 день | — |
| P1-04 | `auditd-trigger.yml` — тестовый плейбук срабатываний правил | ~1 день | после P0-04, P1-01 |
| **P2-01** | **osquery BPF backend + docker_containers + container.entity_id — фундамент поведенческой модели контейнеров ✓ ВЫПОЛНЕНО 2026-05-21** | ~1.5 дня | cross-task с P0-04 (whitelist) |
| **P2-02** | **Расширение osquery-запросов (shell_history, process_envs, supply-chain и пр.) ✓ ВЫПОЛНЕНО 2026-05-21** | ~0.5 дня | опц. совмещать с P2-01 (.j2-template) |
| P3-01 | Unit-тесты Lua-скриптов (merge + enrich) — **отложено** | ~1 день | — |
| P3-02 | CI: luacheck + syntax-check + dry-run | ~4 часа | — |
| P3-03 | Property-based fuzz для merge-buffer | ~0.5 дня | требует P3-01 инфраструктуру |

---

## P0-01. `process.entity_id` и `process.parent.entity_id` в Lua-enrich

**Приоритет:** P0 (высокий)
**Стоимость:** ~1 час кода + 0.5 часа тестов
**Статус:** выполнено 2026-05-18

### Зачем
PID + PPID — переиспользуемые ядром идентификаторы. После смерти процесса PID может быть назначен другому процессу за минуты. Это приводит к трём проблемам в UEBA:

1. **Коллизия после PID reuse** — два разных процесса под одним PID склеиваются в SIEM в одну сессию пользователя.
2. **Ломается process tree** — `parent.pid` указывает на уже умерший процесс, чей PID занят другим бинарём; attribution цепочек атак становится ложной.
3. **Невозможна корреляция auditd ↔ osquery** — join по `pid` без `start_time` мусорный.

ECS-поле `process.entity_id` (стабильный hash из `host.id + pid + process.start`) решает все три. Без него скоринг-фичи "process tree depth", "fan-out", "короткоживущие процессы", "необычный родитель" деградируют от первой PID-коллизии.

### Что делать

**1. `agents/configs/fluent-bit/scripts/auditd_enrich.lua`**
- После установки `process.pid` и `@timestamp` вычислять `process.entity_id = short_hash(host.name + ":" + pid + ":" + start_ts)`.
- Заполнять `process.parent.entity_id` аналогично — но через LRU-кэш `pid → start_time`, обновляемый на каждом execve (для родителя нужен его `start_time`, а не текущего события).
- Хэш — fnv1a 64-bit в hex (16 символов), без внешних зависимостей.

**2. `agents/configs/fluent-bit/scripts/osquery_enrich.lua`**
- Для таблицы `processes` использовать родное поле `start_time` из строки osquery — без аппроксимации.
- `process.parent.entity_id` — тот же приём, через LRU-кэш либо JOIN на стороне osquery-запроса (предпочтительно: добавить `parent_start_time` в SELECT, если возможно).

**3. Кэш `pid → start_time`**
- В Lua-фильтре: простая таблица + counter-based eviction.
- Размер ~10 000 записей (≈50 MB RSS — некритично для fluent-bit).
- Сбрасывается при рестарте — это known limitation, аналогично merge-буферу.

### Точки изменений
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](agents/configs/fluent-bit/scripts/auditd_enrich.lua) — добавить функцию `short_id()`, LRU `parent_start_cache`, два новых поля в record.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](agents/configs/fluent-bit/scripts/osquery_enrich.lua) — то же для `processes`/`process_events`.
- [tests/lua/](tests/lua/) (будет создано отдельной задачей) — фикстуры с PID reuse и проверка устойчивости entity_id.

### Критерий готовности
- В индексе `fluent-audit-*` для каждого события с `process.pid` присутствует непустой `process.entity_id` (16 hex).
- Для процессов с `process.parent.pid` присутствует `process.parent.entity_id` в **≥ 95 %** случаев (до прогрева LRU-кэша часть событий будет без parent).
- Два независимых события одного процесса (например execve и его дочерний socket_event) дают **одинаковый** `process.entity_id`.
- После убийства процесса и переиспользования PID новым процессом — `process.entity_id` **разный**.

### Грабли

- `start_time` родителя ≠ `start_time` текущего события. Без LRU получится мусор.
- Точность `@timestamp` в auditd — секунды + миллисекунды из `audit(epoch.ms:serial)`. Этого достаточно для уникальности, но НЕ использовать секундное округление.
- В Lua 5.1 (fluent-bit использует именно его) нет оператора `~` для xor — нужен `bit.bxor()` или эквивалент через арифметику. Уточнить версию Lua в fluent-bit перед реализацией.

---

## P0-02. `user.session.id` — сквозной идентификатор сессии

**Приоритет:** P0 (ключевой примитив для UEBA-скоринга)
**Стоимость:** ~2-3 часа
**Статус:** выполнено 2026-05-18
**Зависимости:** P0-01 (переиспользует `short_id()` и `btime`-кэш)

### Зачем (P0-02)

UEBA-скоринг работает с «сессией» как единицей анализа: все действия пользователя от логина до выхода должны быть связаны одним идентификатором. Без этого поля:

1. **Нет базовой линии сессии** — невозможен baseline «типичная сессия пользователя X на хосте Y» (длина, процессы, сетевые соединения).
2. **Аномалия не атрибутируется сессии** — подъём привилегий + lateral movement + exfiltration в одном логине видны как три разрозненных события, а не как единый инцидент.
3. **Восстановление инцидента** — без `session_id` нельзя быстро выстроить полный граф действий конкретного логина.

Linux ядро уже решает задачу: при логине `pam_loginuid` присваивает сессии **audit session number** (`ses`). Это значение наследуется **всеми дочерними процессами** (хранится в `/proc/<pid>/sessionid`) и присутствует в каждой auditd-записи как поле `ses`. Нам остаётся сделать его глобально уникальным.

### Что делать (P0-02)

**Формула:**
```text
user.session.id = FNV-1a(host.name + ":" + btime + ":" + ses)  →  16 hex символов
```
Та же функция `short_id()`, что P0-01 использует для `process.entity_id`, — без новых зависимостей.

**1. `agents/configs/fluent-bit/scripts/auditd_enrich.lua`:**
- `ses` уже присутствует в merged-записи.
- Фильтр: пропустить если `ses == 0` (kernel tasks) или `ses == 4294967295` (0xFFFFFFFF, «unset»).
- Добавить `record["user.session.id"] = short_id(hostname .. ":" .. tostring(btime) .. ":" .. tostring(ses))`.
- `btime` уже кэширован для `process.entity_id` — переиспользовать без повторного чтения `/proc/stat`.

**2. `agents/configs/fluent-bit/scripts/osquery_enrich.lua`:**
- Для событий с `pid > 0`: читать `/proc/<pid>/sessionid` (аналогично `/proc/<pid>/stat`, уже реализовано).
- Та же формула → `user.session.id` совпадает с auditd для одной сессии.
- Если файл недоступен (процесс завершился) — пропустить поле без fallback.

### Точки изменений (P0-02)

- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua)
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua)
- [README_FOR_AI.md](../README_FOR_AI.md) — добавить `user.session.id` в таблицы полей разделов 3.3, 4.4 и в раздел 6.

### Критерий готовности (P0-02)

- В `fluent-audit-*` у события с `auditd.session > 0` присутствует `user.session.id` (16 hex).
- Два события от разных процессов одного логина (один `ses`) дают **одинаковый** `user.session.id`.
- После нового `ssh user@host` `user.session.id` меняется.
- В `fluent-osquery-*` для `processes`-событий присутствует `user.session.id`, совпадающий с auditd для того же процесса.
- Кросс-источниковый запрос в OpenSearch: `user.session.id: <id>` → события из обоих индексов.

### Грабли (P0-02)

- **`ses = 4294967295`** (`auid=unset`, kernel tasks): отфильтровать явно — иначе все неаттрибутированные события получат одинаковый `user.session.id`.
- **Cold start osquery**: `/proc/<pid>/sessionid` доступен пока процесс жив. Для завершившихся процессов в osquery diff поле просто отсутствует — это корректное поведение.
- **Нет прогрева кэша**: `ses` читается из каждого auditd-события напрямую; `/proc/<pid>/sessionid` для osquery доступен без LRU. В отличие от `process.parent.entity_id` — здесь нет проблемы cold start.
- **`btime` переиспользовать**: читается один раз при инициализации скрипта в P0-01 — не читать `/proc/stat` повторно.

---

## ~~P0-03. Замена filebeat на fluent-bit SSH-pipeline~~ — УДАЛЕНО

**Приоритет:** ~~P0~~ — задача закрыта
**Стоимость:** ~1 день
**Статус:** **УДАЛЕНО 2026-05-22** — функция была реализована и работала, но удалена как дублирующая данные auditd (аутентификация, sudo, сессии полностью покрываются auditd-правилами). Отдельный SSH-пайплайн не даёт дополнительной ценности для UEBA-скоринга.

**Последний коммит с работающей реализацией:** `960bdb2` (bugfix: ssh)
**Коммит удаления:** `6aeaf16` (delete SSH) — удалены: `sshd_enrich.lua`, блок INPUT/OUTPUT в `fluent-bit.conf`, parser `syslog_sshd`, TCP 5048 в Logstash, `opensearch/templates/filebeat-auth.json`, `dev_stand/scripts/send-sshd.sh`.

Для восстановления: `git show 960bdb2` покажет полное состояние всех файлов перед удалением.

### Зачем (P0-03)

- Убрать последнюю зависимость от Elastic apt-репозитория. После этого весь стек агентов — pure fluent-bit + auditd + osquery, никакой Elastic upstream.
- Унифицировать модель: единый ECS-enrich через Lua, общий стиль конфигов и метрик health.
- Снять необходимость поддержки `.deb` filebeat в [fetch-packages](agents/deploy/fetch-packages/).
- Один эндпойнт мониторинга (fluent-bit metrics на 2020/tcp) вместо двух.

### Что делать (P0-03)

**1. Новый Lua-enrich:** `agents/configs/fluent-bit/scripts/sshd_enrich.lua`. Распарсить распространённые форматы строк auth.log:

- `Failed password for [invalid user] X from IP port PORT ssh2` → `event.action=ssh_login_failed`, `outcome=failure`
- `Accepted password|publickey for X from IP port PORT` → `event.action=ssh_login`, `outcome=success`, `event.type=start`
- `session opened|closed for user X by (uid=N)` → `event.action=session_opened|session_closed`, `event.type=start|end`
- `Invalid user X from IP port PORT` → `event.action=invalid_user`, `outcome=failure`
- `Disconnected from authenticating user X IP port PORT [preauth]` → `event.action=ssh_disconnect_preauth`
- `Connection closed by [authenticating user X] IP port PORT [preauth]` → `event.action=ssh_connection_closed`
- PAM-failure (`PAM N more authentication failures`) → `event.action=pam_auth_failure`
- Остальные строки (sudo/su/CRON) — либо игнорировать, либо общая категоризация `event.category=authentication/iam`. Решить в момент имплементации, по реальному auth.log.

**ECS-маппинг:** `event.dataset=system.auth`, `event.module=system`, `event.category=["authentication"]`, `event.outcome`, `event.type`, `user.name`, `source.ip`, `source.port`, `process.name=sshd`, `related.user=[user.name]`, `related.ip=[source.ip]`, `host.name`, `host.os.type=linux`, `ecs.version=8.11`.

**2. Parser:** в [parsers.conf](agents/configs/fluent-bit/parsers.conf) добавить парсер `syslog_sshd` для извлечения `timestamp + hostname + program[pid] + message`.

**3. fluent-bit.conf:** новый блок INPUT (`tail /var/log/auth.log` + DB position file) → FILTER `lua sshd_enrich` → OUTPUT `tcp` на новый порт **5048**.

**4. Logstash pipeline:** в [ueba-main.conf](logstash/configs/pipeline/ueba-main.conf) добавить:

```text
input { tcp { port => 5048 codec => json_lines tags => ["system-auth","fluent-bit"] } }
```

и в output-секции маршрутизировать по тегу в индекс `system-auth-%{+YYYY.MM.dd}`.

**5. Ansible** [agents-deploy.yml](agents/deploy/agents-deploy.yml):

- Удалить все task'и установки/конфигурации filebeat.
- Добавить чистую purge-секцию: `systemctl stop filebeat`, `systemctl disable filebeat`, `apt purge -y filebeat`, удаление `/etc/filebeat/`, `/var/lib/filebeat/`, `/var/log/filebeat/`.
- Удалить filebeat из списка пакетов в [fetch-packages/fetch.ps1](agents/deploy/fetch-packages/fetch.ps1).

**6. Удалить из репо:**

- Каталог [agents/configs/filebeat/](agents/configs/filebeat/) целиком.

**7. Документация:**

- [CLAUDE.md](CLAUDE.md): убрать filebeat из таблицы агентов, заменить строку индекса `filebeat-*` на `system-auth-*` (новый pipeline), убрать упоминание "временный" про filebeat.
- README.md: обновить список источников.
- [dev_stand/scripts/send-sshd.sh](dev_stand/scripts/send-sshd.sh): обновить под новый формат (TCP 5048) либо удалить.

### Точки изменений (P0-03)

- **Новые файлы:** `agents/configs/fluent-bit/scripts/sshd_enrich.lua`.
- **Правки:** [agents/configs/fluent-bit/parsers.conf](agents/configs/fluent-bit/parsers.conf), [agents/configs/fluent-bit/fluent-bit.conf](agents/configs/fluent-bit/fluent-bit.conf), [logstash/configs/pipeline/ueba-main.conf](logstash/configs/pipeline/ueba-main.conf), [agents/deploy/agents-deploy.yml](agents/deploy/agents-deploy.yml), [agents/deploy/fetch-packages/fetch.ps1](agents/deploy/fetch-packages/fetch.ps1), [CLAUDE.md](CLAUDE.md), [README.md](README.md).
- **Удалить:** [agents/configs/filebeat/](agents/configs/filebeat/).

### Критерий готовности (P0-03)

- На test-хосте после прогона `agents-deploy.yml`: `dpkg -l | grep filebeat` пусто, `systemctl status filebeat` → `unit not found`.
- В fluent-bit `curl http://127.0.0.1:2020/api/v1/metrics` показывает ненулевой счётчик records у tail-input на auth.log.
- После `ssh user@host` (успех и неуспех с заведомо неверным паролем) в OpenSearch индексе `system-auth-*` появляются документы с заполненными `event.action`, `event.outcome`, `user.name`, `source.ip`, `source.port`.
- На beats 5044 (Logstash) больше нет входящего трафика от агентских хостов.
- Индекс `filebeat-*` перестал расти (последняя дата — момент миграции).

### Грабли (P0-03)

- **Права на auth.log:** обычно `640 root:adm`. fluent-bit user уже должен быть в группе `adm` для audit.log (см. CLAUDE.md), но проверить per-host.
- **journald-only дистрибутивы:** на Ubuntu 22.04+ auth.log может быть отключён в пользу journald. Решения: либо включить rsyslog для записи auth.log, либо использовать `[INPUT] systemd` в fluent-bit (другой парсер). Уточнить по факту целевого окружения.
- **Syslog timestamp без года** (`Jan 15 10:30:45`) — fluent-bit парсер должен обогатить текущим годом; вокруг 31 декабря/1 января возможна неоднозначность.
- **DB position для tail:** обязательно настроить `db /var/lib/fluent-bit/sshd.db`, иначе при рестарте дубли событий.
- **Beats 5044 input в Logstash оставить.** Общий relay для любых beats-агентов.
- **Регэкспы sshd-форматов** — auth.log forматы за годы менялись (Debian Buster vs Bookworm vs Ubuntu 22.04). Реальный набор форматов уточнить, прогнав на test-хосте `journalctl _SYSTEMD_UNIT=ssh.service | grep -E 'Failed|Accepted|Invalid|Disconnected'` и обновив enrich по факту.
- **Совместимость dashboards:** существующие саvedSearch/visualization в OpenSearch Dashboards, ссылающиеся на `filebeat-*`, перестанут видеть новые данные. Их нужно пересоздать на `system-auth-*` (либо настроить index alias `auth-* → filebeat-*, system-auth-*`, но это усложнение — рекомендую clean cut).

---

## P0-04. Auditd syscall rules: io_uring/ptrace/memfd_create/bpf/process_vm

**Приоритет:** P0 (закрытие современных bypass-векторов)
**Стоимость:** ~2-3 часа (правила + дополнение SYSCALLS таблицы в enrich + триггер на dev)
**Статус:** выполнено 2026-05-22
**Зависимости:** учитывает корректировки из P1-01 (брать только `io_uring_setup`, обе формы `process_vm_*`).

### Зачем (P0-04)

Закрывает 4 современных bypass-вектора, которые отсутствуют в текущем [audit.rules](agents/configs/auditd/audit.rules):

- **io_uring** — RingReaper и аналогичные PoC bypass'ят auditd через io_uring submission queue. auditd видит **только** сам факт `io_uring_setup` (не операции внутри) — но это уже значимый сигнал, т.к. на типичном prod-хосте io_uring почти не используется.
- **ptrace + process_vm_readv/writev** — process injection и чтение чужой памяти (T1055).
- **memfd_create** — fileless execution (T1620): загрузка бинаря в анонимный файловый дескриптор, exec без диска.
- **bpf** — атакующий eBPF (rootkit Singularity и аналоги) + сигнал о любой загрузке BPF-программы.

### Что делать (P0-04)

**1. Добавить в [audit.rules](agents/configs/auditd/audit.rules)** после блока "Подозрительные пути выполнения":

```text
# ── Современные bypass-векторы (P0-04) ───────────────────────────────────────
-a always,exit -F arch=b64 -S io_uring_setup -F auid>=1000 -F auid!=unset -k io_uring
-a always,exit -F arch=b64 -S ptrace -F auid>=1000 -F auid!=unset -k process_injection
-a always,exit -F arch=b64 -S process_vm_readv,process_vm_writev -F auid>=1000 -F auid!=unset -k process_injection
-a always,exit -F arch=b64 -S memfd_create -F auid>=1000 -F auid!=unset -k fileless_exec
-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=unset -k ebpf_use
```

**2. Дополнить таблицу `SYSCALLS` в [auditd_enrich.lua](agents/configs/fluent-bit/scripts/auditd_enrich.lua)** (строки 6-23):

```lua
["101"]="ptrace",
["310"]="process_vm_readv",
["311"]="process_vm_writev",
["319"]="memfd_create",
["321"]="bpf",
["425"]="io_uring_setup",
```

**3. Категоризация в enrich** (блок после строки ~176, по аналогии с существующими ветками):

```lua
elseif sc_name == "ptrace"
    or sc_name == "process_vm_readv"
    or sc_name == "process_vm_writev" then
    record["event.type"]     = "change"
    record["event.category"] = "process"
elseif sc_name == "memfd_create" then
    record["event.type"]     = "creation"
    record["event.category"] = "process"
elseif sc_name == "bpf" then
    record["event.type"]     = "info"
    record["event.category"] = "process"
elseif sc_name == "io_uring_setup" then
    record["event.type"]     = "info"
    record["event.category"] = "process"
end
```

### Точки изменений (P0-04)

- [agents/configs/auditd/audit.rules](agents/configs/auditd/audit.rules)
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](agents/configs/fluent-bit/scripts/auditd_enrich.lua)

### Критерий готовности (P0-04)

- `auditctl -l | grep -E 'io_uring|ptrace|memfd|bpf'` показывает все 5 правил.
- Триггер на dev-хосте: `python3 -c "import os; os.memfd_create('x', 0)"` → событие в `fluent-audit-*` с `event.action=memfd_create`, `auditd.key=fileless_exec`.
- Аналогичные триггеры для остальных ключей (см. P1-04 auditd-trigger.yml) дают корректные `event.action` и `event.category=process`.
- Объём `audit.log` после включения вырос не более чем на +2-3 % на типичном prod-сервере (на workstation возможен рост до +10 % из-за gdb/strace).

### Грабли (P0-04)

- **Feedback loop с osquery BPF backend (P2-01).** Когда P2-01 будет включён, osqueryd сам начнёт триггерить `-S bpf` audit-события на свою BPF-загрузку → fluent-bit → snowball. Решение: в audit-правиле для `bpf` добавить `-F exe!=/usr/bin/osqueryd` или фильтр по uid. **Заложить как cross-task требование к P2-01.**
- **Номера syscall'ов архитектуроспецифичны.** Указанные значения — x86_64. Для arm64 значения другие — но мы пока пишем `-F arch=b64`, который для arm64 матчит aarch64 — таблица номеров на arm64 не совпадёт. Если появятся arm64-хосты, придётся отдельно мапить.
- **memfd_create** иногда используется legitimate-софтом (systemd-userdb, Chrome IPC, glibc loader на новых ядрах). `-F auid>=1000` отсекает systemd, но Chrome пройдёт. На workstations ожидаем умеренный фон.
- **io_uring видим только setup, не операции.** Это known limitation — см. P1-01 уточнение от Neo23x0.

---

## P1-01. Gap-анализ audit.rules против Neo23x0 ruleset

**Приоритет:** P1 (стабильность покрытия)
**Стоимость:** ~3-4 часа (правила + enrich для новых syscall'ов + тест на шум на dev-стенде)
**Статус:** **выполнено 2026-05-22** — Tier A (12 правил) + Tier B (~14 правил + 2 syscall) добавлены в audit.rules; SYSCALLS таблица и категоризация в auditd_enrich.lua расширены.
**Источник:** [Neo23x0/auditd](https://github.com/Neo23x0/auditd) — Florian Roth, MIT, де-факто референс по auditd для threat detection.

### Подход

Не затаскиваем Neo23x0 целиком (заточен под threat hunting/IR, существенно шумнее нужного для UEBA). Используем как **источник для cherry-pick**: берём правила, закрывающие реальные слепые зоны нашего ruleset, отбрасываем избыточные/шумные.

### Что уже совпадает (по смыслу)

Наш `process_start ↔ Neo23x0 process_creation`, `cron_changes ↔ cron`, `time_change ↔ time+localtime`, `module_load/unload ↔ modules`, `module_changes ↔ modprobe`, `user_changes ↔ etcgroup+etcpasswd`, `pam_changes ↔ pam`, `sudo_changes ↔ actions`, `audit_config_change ↔ auditconfig+audispconfig`, `session_tracking ↔ session`, `socket_connect ↔ network_connect_4/6`, `systemd_changes ↔ systemd`, `socket_create ↔ network_socket_created`.

### Уточнение по P0-04 (io_uring/ptrace/memfd_create/bpf)

Neo23x0 подтверждает направление P0-04. Уточнения, которые P0-04 уже учитывает:

| Исходный черновик | Neo23x0 | Учтено в P0-04 |
| --- | --- | --- |
| `-S io_uring_setup,io_uring_enter,io_uring_register` | `-S io_uring_setup` только | Да — взят только `io_uring_setup`, `enter` создаёт тысячи событий на один setup |
| `-S process_vm_writev` | `-S process_vm_readv, process_vm_writev` | Да — обе формы добавлены |

### Gap-список: что добавить

**Tier A — высокий сигнал, добавить в первую очередь:**

| Key (предложение) | Правило (синтез) | Цель |
| --- | --- | --- |
| `audit_log_tamper` | `-w /var/log/audit/ -p wa` | Anti-forensics: попытки чистить audit-логи |
| `preload_inject` | `-w /etc/ld.so.preload -p wa` | Классический LD_PRELOAD persistence |
| `libpath_change` | `-w /etc/ld.so.conf -p wa`, `-w /etc/ld.so.conf.d/ -p wa` | Подмена путей shared libs |
| `container_escape` | `-a always,exit -F arch=b64 -S unshare,setns,pivot_root -F auid>=1000 -F auid!=unset` | Container/namespace escape |
| `mount_action` | `-a always,exit -F arch=b64 -S mount,umount2,move_mount,open_tree,fsopen,fsconfig,fsmount -F auid>=1000 -F auid!=unset` | Mount-based escapes (mount over /etc, /proc и пр.) |
| `kexec_hot_replace` | `-a always,exit -F arch=b64 -S kexec_file_load` | Горячая замена ядра |
| `userfaultfd_use` | `-a always,exit -F arch=b64 -S userfaultfd -F auid>=1000 -F auid!=unset` | Exploitation primitive (kernel race conditions) |
| `af_alg` | `-a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg` | Copy Fail CVE и аналогичные крипто-bypass |
| `swap_modify` | `-a always,exit -F arch=b64 -S swapon,swapoff` | LD_PRELOAD prep, persistence через swap |
| `power_state` | `-a always,exit -F arch=b64 -S reboot` | Anti-forensics: преднамеренный ребут |
| `timestomp` | `-a always,exit -F arch=b64 -S utimensat,utimes,futimesat -F auid>=1000 -F auid!=unset` | T1070.006 — подмена mtime/atime |
| `process_accounting_tamper` | `-a always,exit -F arch=b64 -S acct` | Отключение/включение process accounting |

**Tier B — средняя ценность, добавить во вторую очередь:**

| Key | Правило | Цель |
| --- | --- | --- |
| `env_change` | `-w /etc/environment -p wa` | Env-based persistence |
| `mac_policy_change` | `-w /etc/selinux/ -p wa`, `-w /etc/apparmor/ -p wa`, `-w /etc/apparmor.d/ -p wa` | Отключение SELinux/AppArmor |
| `shell_profile_change` | `-w /etc/profile.d/ -p wa`, `-w /etc/profile -p wa`, `-w /etc/bashrc -p wa` | Shell-based persistence |
| `init_change` | `-w /etc/inittab -p wa`, `-w /etc/init.d/ -p wa`, `-w /etc/rc.local -p wa` | Init persistence |
| `fstab_change` | `-w /etc/fstab -p wa` | Persistence через mount points |
| `udev_change` | `-w /etc/udev/rules.d/ -p wa` | Udev rule injection |
| `pkg_mgmt_change` | `-w /etc/apt/ -p wa`, `-w /etc/dnf/ -p wa`, `-w /etc/yum.repos.d/ -p wa` | Подмена pkg-репозиториев → supply chain |
| `firewall_change` | `-w /etc/nftables.conf -p wa`, `-w /etc/iptables/ -p wa` | Изменения firewall |
| `hostname_dns_change` | `-a always,exit -F arch=b64 -S sethostname,setdomainname`, `-w /etc/hosts -p wa`, `-w /etc/resolv.conf -p wa` | DNS spoofing prep |
| `issue_change` | `-w /etc/issue -p wa`, `-w /etc/issue.net -p wa` | Login banner tampering |
| `specialfile_create` | `-a always,exit -F arch=b64 -S mknod,mknodat -F auid>=1000 -F auid!=unset` | Создание device-файлов |
| `user_changes` расширить | `-w /etc/sssd/ -p wa`, `-w /etc/openldap/ -p wa`, `-w /etc/krb5.conf -p wa` | LDAP/Kerberos config |
| `pam_changes` расширить | `-w /etc/polkit-1/ -p wa` | Polkit rules |
| `sshd_config` расширить | `-w /etc/ssh/ -p wa` (целиком, не только sshd_config) | Все ssh-конфиги |

**Tier C — НЕ берём (обоснование):**

- `bin_writes`/`usr_writes`/`boot_writes` (запись в /bin, /usr, /boot) — большой overlap с нашим `binary_modification`, при этом существенно шумнее (любой `apt upgrade` затопит логи).
- `delete` (unlink/rename) — без `-F dir=` шум катастрофический.
- `Inter-Process_Communication` (msgctl/semctl/shmctl) — низкий signal-to-noise.
- `network_connect_4`/`6` раздельно — мы уже ловим оба через один `connect`.
- `falcon_sensor`/`crowdstrike_network` — CrowdStrike не используется.
- `docker`/`containers` — включать только при появлении хостов с Docker.
- `perm_mod` (chmod/chown/setxattr глобально) — без `-F dir=` объём огромный; если включать — только для критичных каталогов.

### Что менять в коде (P1-01)

**1. [audit.rules](agents/configs/auditd/audit.rules)** — добавить правила Tier A (12 ключей), затем Tier B (~14 ключей) после прогона на dev-стенде с проверкой объёма.

**2. [auditd_enrich.lua](agents/configs/fluent-bit/scripts/auditd_enrich.lua)** — дополнить таблицу `SYSCALLS` (строки 6-23) номерами новых syscall'ов:

```lua
["165"]="mount",        ["166"]="umount2",      ["169"]="reboot",
["233"]="acct",         ["246"]="kexec_load",   -- old
["272"]="unshare",      ["280"]="utimensat",
["282"]="userfaultfd",  ["308"]="setns",
["310"]="process_vm_readv", ["311"]="process_vm_writev",
["320"]="kexec_file_load",  ["133"]="mknod",   ["259"]="mknodat",
-- уже добавлено в P0-04:
["101"]="ptrace",       ["319"]="memfd_create", ["321"]="bpf",
["425"]="io_uring_setup",
```

И добавить категоризацию для них в блок на строках 176-202 (event.category/event.type по аналогии с существующими).

**3. Документация** — обновить CLAUDE.md, упомянуть Neo23x0 как референс для аудит-ruleset.

### Критерий готовности (P1-01)

- Все правила Tier A в `audit.rules`, прошли `augenrules --check` без ошибок.
- На dev-стенде после `auditctl -l` видно загруженные правила (`auditctl -l | wc -l` совпадает с ожидаемым числом).
- В индексе `fluent-audit-*` для срабатываний новых правил появляется заполненное `event.action` (не пустое и не "UNKNOWN").
- Объём `audit.log` на типичном хосте после Tier A вырос не более чем на **+10 %** относительно baseline (замер: 24 часа до/после).
- Триггер-плейбук `tests/auditd/auditd-trigger.yml` (см. отдельную задачу) даёт срабатывание по каждому новому ключу.

### Грабли (P1-01)

- `auid>=1000 -F auid!=unset` обязателен для всех syscall-правил, иначе systemd/kernel-инициированные вызовы (особенно `mount`, `unshare`, `memfd_create`) затопят логи.
- Watch на `/etc/ssh/` целиком (Tier B) — учесть, что fail2ban/ssh-agent могут писать в подкаталоги; проверить на dev-стенде.
- `pkg_mgmt_change` watch на `/etc/apt/` — `apt update` пишет в `/etc/apt/sources.list.d/`? Обычно нет (читает), но `apt-add-repository` пишет — это и есть целевой сигнал.
- `kexec_file_load` — на современных ядрах используется именно эта форма, не legacy `kexec_load` (syscall 246). Брать обе для совместимости.

---

## P1-02. ECS Index Templates для OpenSearch

**Приоритет:** P1 (стабильность маппингов)
**Стоимость:** ~4 часа (шаблоны + Ansible-task для PUT + проверка на dev-стенде)
**Статус:** **выполнено 2026-05-22** — 2 шаблона (fluent-audit v2.0, fluent-osquery v2.0); system-auth не создавался (P0-03 удалён). Ansible-таск PUT добавлен в logstash-deploy.yml.
**Зависимости:** после P0-01 (process.entity_id), после P0-02 (user.session.id). P0-03 удалён — system-auth шаблон не нужен.

### Зачем (P1-02)

Сейчас все индексы создаются с **dynamic mapping** — OpenSearch угадывает тип поля по первому документу. Три класса проблем, которые из этого вытекают:

1. **Type conflict ломает индекс.** `process.args` иногда массив `["sh","-c",...]`, иногда строка (после fallback в enrich) — второй вид валится с `mapper_parsing_exception`. Известное ограничение из README.
2. **Неправильные типы — теряется функциональность.** `source.ip` → `text` вместо `ip` (нет CIDR-фильтров, нет geo-enrich, нет dest-clustering). `file.hash.md5` → `text` + автоматический `.keyword` (двойной диск, full-text по хешу не нужен).
3. **Несогласованность между дневными индексами.** Каждый `fluent-audit-YYYY.MM.DD` создаётся отдельно — если в один день первое значение поля редкое или пустое, тип угадается иначе, чем вчера. Дашборды по multi-day начинают глючить.

Index templates закрывают всё это разом: один JSON на pattern фиксирует типы до появления первого документа.

### Что делать (P1-02)

**1. Создать 3 шаблона:**

- [logstash/configs/templates/fluent-audit.json](logstash/configs/templates/fluent-audit.json) — pattern `fluent-audit-*`, `event.module=auditd` constant_keyword.
- [logstash/configs/templates/fluent-osquery.json](logstash/configs/templates/fluent-osquery.json) — pattern `fluent-osquery-*`, `event.module=osquery` constant_keyword.
- [logstash/configs/templates/system-auth.json](logstash/configs/templates/system-auth.json) — pattern `system-auth-*`, `event.module=system` constant_keyword (после P0-03).

**2. Критичные поля под UEBA, которые обязательно должны быть явно типизированы:**

| Поле | Тип | Примечание |
| --- | --- | --- |
| `@timestamp` | `date` | базовый |
| `host.name`, `host.os.type`, `host.os.family` | `keyword` | оси агрегаций |
| `user.id`, `user.name`, `user.effective.id`, `user.effective.name` | `keyword` | главные оси UEBA |
| `process.pid`, `process.parent.pid`, `process.args_count` | `long` | range-фильтры |
| `process.entity_id`, `process.parent.entity_id` | `keyword` | process tree (из P0-01) |
| `process.name`, `process.executable`, `process.working_directory` | `keyword` | exact-match |
| `process.command_line` | `wildcard` | substring-поиск (OS-специфичный тип) |
| `process.args` | `keyword` (массив) | exact-match по аргументам |
| `source.ip`, `destination.ip`, `related.ip` | **`ip`** | CIDR, geo, dest-clustering |
| `source.port`, `destination.port` | `long` | range |
| `file.path`, `file.name`, `file.extension`, `file.inode`, `file.uid`, `file.gid` | `keyword` | exact-match |
| `file.hash.md5`, `file.hash.sha1`, `file.hash.sha256` | `keyword` | exact lookup |
| `event.category`, `event.action`, `event.outcome`, `event.type` | `keyword` | базовые оси фильтрации |
| `event.module`, `event.dataset`, `ecs.version` | **`constant_keyword`** | значение одно — экономия диска/CPU |
| `tags`, `related.user`, `related.hash` | `keyword` (массив) | агрегации |
| `auditd.session`, `auditd.data.syscall` | `keyword` | специфичные для auditd оси |

Для osquery-индекса дополнительно: `osquery.action` (`added`/`removed`) → `keyword`, `osquery.name` (имя запроса) → `keyword`, `osquery.numerics.*` → `long`.

**3. Применение через Ansible.**

Рекомендую вариант "PUT через API из Ansible-task", а не через `template => ...` в Logstash output. Причины: template живёт независимо от Logstash, переживает redeploy пайплайна, легче ревьюить и применять локально без рестарта индексации.

Добавить в [logstash/deploy/logstash-deploy.yml](logstash/deploy/logstash-deploy.yml) task (черновик):

```yaml
- name: Apply OpenSearch index templates
  ansible.builtin.uri:
    url: "{{ opensearch_url }}/_index_template/{{ item }}"
    method: PUT
    body_format: json
    body: "{{ lookup('file', 'templates/' + item + '.json') }}"
    user: "{{ opensearch_user }}"
    password: "{{ opensearch_password }}"
    force_basic_auth: yes
    validate_certs: yes
    ca_path: "{{ playbook_dir }}/files/opensearch-ca.pem"
    status_code: [200, 201]
  loop:
    - fluent-audit
    - fluent-osquery
    - system-auth
```

**4. Структура шаблона (черновик `fluent-audit.json`):**

```json
{
  "index_patterns": ["fluent-audit-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "dynamic": "true",
      "properties": {
        "@timestamp":           { "type": "date" },
        "ecs.version":          { "type": "constant_keyword" },
        "event.module":         { "type": "constant_keyword", "value": "auditd" },
        "event.dataset":        { "type": "constant_keyword", "value": "auditd" },
        "event.category":       { "type": "keyword" },
        "event.action":         { "type": "keyword" },
        "event.outcome":        { "type": "keyword" },
        "event.type":           { "type": "keyword" },
        "host.name":            { "type": "keyword" },
        "user.id":              { "type": "keyword" },
        "user.name":            { "type": "keyword" },
        "process.pid":          { "type": "long" },
        "process.parent.pid":   { "type": "long" },
        "process.entity_id":    { "type": "keyword" },
        "process.parent.entity_id": { "type": "keyword" },
        "process.args":         { "type": "keyword" },
        "process.command_line": { "type": "wildcard" },
        "source.ip":            { "type": "ip" },
        "source.port":          { "type": "long" },
        "destination.ip":       { "type": "ip" },
        "file.hash.md5":        { "type": "keyword" },
        "file.hash.sha256":     { "type": "keyword" },
        "tags":                 { "type": "keyword" },
        "related.user":         { "type": "keyword" },
        "related.ip":           { "type": "ip" }
      }
    }
  }
}
```

(полный набор полей — по таблице выше; черновик показывает структуру).

**5. Документация:** добавить в [CLAUDE.md](CLAUDE.md) раздел "Index templates" с описанием расположения и порядка применения.

### Точки изменений (P1-02)

- **Новые файлы:** `logstash/configs/templates/*.json` (4 шаблона).
- **Правки:** [logstash/deploy/logstash-deploy.yml](logstash/deploy/logstash-deploy.yml) (новый task PUT), [CLAUDE.md](CLAUDE.md).

### Критерий готовности (P1-02)

- На dev-стенде после `ansible-playbook logstash-deploy.yml` все 4 шаблона зарегистрированы в OpenSearch: `curl -s "$OS/_index_template?pretty" | jq '.index_templates[].name'` показывает все 4.
- Новый индекс `fluent-audit-<сегодня>` создан **после** регистрации шаблона. В его маппингах `source.ip` имеет тип `ip` (а не `text`): `curl "$OS/fluent-audit-*/_mapping" | jq '.[] | .mappings.properties."source.ip".type'` возвращает `"ip"`.
- Проверка экономии: размер свежего индекса с `constant_keyword` для `event.module`/`event.dataset` на 5-15 % меньше, чем без шаблона (точная цифра зависит от объёма).
- Симуляция type-conflict: отправить через `dev_stand/scripts/send-auditd.sh` сначала документ с `process.args` как массив, потом со строкой — оба индексируются без ошибки в logstash logs (шаблон форсит keyword-массив, fluent-bit/Logstash приводит к нему).

### Грабли (P1-02)

- **Шаблон НЕ применяется ретроактивно.** Существующие индексы остаются со старыми маппингами. Варианты: смириться (старые индексы умрут по retention) или сделать explicit reindex — отдельная задача, в этой не делаем.
- **`wildcard` field type** — доступен в OpenSearch (форк от Elasticsearch 7.10), но на старых версиях OpenSearch может отсутствовать. Если не работает — заменить на `keyword`, потерять substring-поиск по `process.command_line` (некритично).
- **`constant_keyword`** — есть в OpenSearch, но проверить на целевой версии. При несовместимости упасть на обычный `keyword` (потеря экономии диска, но без потери функциональности).
- **Приоритет шаблонов.** Если в кластере уже есть какой-нибудь системный шаблон с pattern `*`, нужно поставить `priority` нашим выше (200+) чтобы он выиграл при матчинге.
- **Динамические поля.** Ставим `"dynamic": "true"` (не `"strict"`), чтобы новые ECS-поля, которые мы не предусмотрели, всё равно попадали в индекс с auto-маппингом. `"strict"` опаснее — словит на любом нашем расширении enrich.

---

## P1-03. mTLS канал fluent-bit → Logstash

**Приоритет:** P1 (безопасность канала)
**Стоимость:** ~1 день (PKI + конфиги обеих сторон + Ansible-роли для распространения сертификатов)
**Статус:** не начато
**Зависимости:** имеет смысл делать после P0-03 (миграция filebeat) — все три TCP-входа (5045 audit, 5047 osquery, 5048 system-auth) к этому моменту будут стандартизованы, обернём TLS разом.

### Зачем (P1-03)

Сейчас fluent-bit отправляет события в Logstash через **plaintext TCP**:

- `5045` (audit ECS)
- `5047` (osquery ECS)
- `5048` (system-auth, после P0-03)

Что это значит на bare-metal флоте:

- **Перехват.** Любой узел в широковещательном сегменте/маршруте — читает события целиком (пользовательские имена, команды, IP-источники).
- **Инъекция.** TCP-input Logstash принимает любой JSON, который ему подсунут — атакующий, имеющий доступ к сети, может писать фейковые события в SIEM, маскируя реальные действия.
- **Нет аутентификации источника.** Logstash не различает "это fluent-bit с hostA" и "это кто-то ещё".

mTLS закрывает всё разом: шифрование + двусторонняя аутентификация (server-cert на Logstash + client-cert на каждом агенте).

### Что делать (P1-03)

**Вариант** — обернуть существующие TCP-input в Logstash в TLS, без смены протокола (`json_lines` остаётся). Это минимальное изменение пайплайна, без миграции на forward/beats protocol.

**1. PKI.** Если в инфраструктуре уже есть internal CA — использовать её. Иначе создать минимальный self-signed CA:

- Корневой CA-cert + key — хранится в `agents/deploy/files/ca/` (gitignored), резервная копия offline.
- Server-cert для Logstash хоста (CN = logstash hostname, SAN с IP).
- Client-certs per-host для агентов (CN = agent hostname). Генерация через Ansible-task на стороне deployer'а или через дочерний vault-keystore.

**2. Logstash side.** В [logstash/configs/pipeline/ueba-main.conf](logstash/configs/pipeline/ueba-main.conf) к каждому `tcp` input добавить:

```text
input {
  tcp {
    port => 5045
    codec => json_lines
    ssl_enabled => true
    ssl_certificate => "/etc/logstash/certs/server.crt"
    ssl_key => "/etc/logstash/certs/server.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_verify_mode => "force_peer"
    tags => ["fluent-bit", "auditd"]
  }
}
```

То же для 5047 и 5048 (после P0-03).

**3. fluent-bit side.** В [agents/configs/fluent-bit/fluent-bit.conf](agents/configs/fluent-bit/fluent-bit.conf) к каждому `[OUTPUT] tcp` добавить:

```ini
[OUTPUT]
    Name              tcp
    Match             audit.*
    Host              ${LOGSTASH_HOST}
    Port              5045
    Format            json_lines
    tls               on
    tls.verify        on
    tls.ca_file       /etc/fluent-bit/certs/ca.crt
    tls.crt_file      /etc/fluent-bit/certs/client.crt
    tls.key_file      /etc/fluent-bit/certs/client.key
```

**4. Распространение сертификатов через Ansible:**

- [logstash/deploy/logstash-deploy.yml](logstash/deploy/logstash-deploy.yml) — скопировать server.crt/key + ca.crt в `/etc/logstash/certs/`, выставить права `640 logstash:logstash`.
- [agents/deploy/agents-deploy.yml](agents/deploy/agents-deploy.yml) — для каждого хоста скопировать `client-<inventory_hostname>.crt/key` + `ca.crt` в `/etc/fluent-bit/certs/`, права `640 fluent-bit:fluent-bit`. Перезагрузить fluent-bit.

**5. Документация в [CLAUDE.md](CLAUDE.md):** добавить раздел "TLS / PKI", описать процедуру выпуска сертификата при добавлении нового хоста.

### Точки изменений (P1-03)

- [logstash/configs/pipeline/ueba-main.conf](logstash/configs/pipeline/ueba-main.conf) — SSL-параметры на 3 TCP-input.
- [agents/configs/fluent-bit/fluent-bit.conf](agents/configs/fluent-bit/fluent-bit.conf) — TLS на 3 OUTPUT.
- [logstash/deploy/logstash-deploy.yml](logstash/deploy/logstash-deploy.yml), [agents/deploy/agents-deploy.yml](agents/deploy/agents-deploy.yml) — деплой сертификатов.
- Новые: `agents/deploy/files/ca/` (gitignored), `agents/deploy/files/clients/` (per-host, gitignored).
- [CLAUDE.md](CLAUDE.md).
- [.gitignore](.gitignore) — добавить пути с приватными ключами.

### Критерий готовности (P1-03)

- `tcpdump -i any -A 'port 5045'` на агентском хосте: видимы только TLS-handshake байты и бинарный payload, plaintext JSON отсутствует.
- `openssl s_client -connect logstash:5045 -CAfile ca.crt -cert client.crt -key client.key` подключается; без cert — Logstash отвергает соединение в логах (`SSL alert`).
- В индексах `fluent-audit-*`, `fluent-osquery-*`, `system-auth-*` продолжают появляться события (smoke).
- В fluent-bit metrics `output_errors_total{name="tcp"}` остаётся 0.

### Грабли (P1-03)

- **Ротация сертификатов.** fluent-bit не перезагружает TLS-материал на лету. После замены cert — `systemctl reload fluent-bit` либо restart. Заложить в Ansible-роль.
- **Время хостов.** Без NTP TLS handshake падает на validity period. Проверять `chrony`/`systemd-timesyncd` на агентских хостах как pre-flight.
- **Logstash в Docker.** Volume-mount `/etc/logstash/certs/` в контейнер; права внутри — проверить UID, под которым работает logstash-процесс (обычно 1000).
- **Privacy of CA private key.** Корневой CA-key хранится **только** в Ansible Vault или вне репозитория. В git не должен попадать никогда. Жёсткий `.gitignore` + pre-commit hook.
- **Mixed-state переход.** Во время раскатки часть агентов TLS, часть plain — Logstash на одном порту не умеет оба режима. Решение: либо одновременный rollout всех агентов (Ansible parallel), либо временно второй порт `5045-tls` параллельно с `5045-plain`, потом снос plain.

---

## P1-04. auditd-trigger.yml — тестовый плейбук срабатываний правил

**Приоритет:** P1 (защита от регрессов в правилах + enrich)
**Стоимость:** ~1 день
**Статус:** не начато
**Зависимости:** делать **после** P0-04 и P1-01 (Tier A), чтобы покрыть все ключи разом, а не делать в два этапа.

### Зачем (P1-04)

По аналогии с уже существующим [tests/osquery/osquery-trigger.yml](tests/osquery/osquery-trigger.yml). Плейбук с apply/rollback тегами, который запускает действия, гарантированно триггерящие каждое auditd-правило, и проверяет наличие документа в `fluent-audit-*` с ожидаемым `auditd.key`.

Это **end-to-end smoke**: правило в audit.rules → kernel → audit.log → fluent-bit merge → enrich → Logstash → OpenSearch → ECS-документ. Без него любая правка в audit.rules или enrich — игра в "проверим в проде, чтоли".

### Что делать (P1-04)

Создать `tests/auditd/auditd-trigger.yml` с таск-блоками. Минимальный набор триггеров на каждый существующий ключ:

| Действие | Ожидаемый ключ |
| --- | --- |
| `useradd test-aud && userdel test-aud` | `user_changes` |
| `sudo -u nobody true` | `sudo_exec` |
| `ssh-keygen -y -f /tmp/k`, добавить в `/root/.ssh/authorized_keys` | `ssh_keys` |
| `insmod /tmp/dummy.ko` (минимальный dummy-модуль) | `module_load` |
| `python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)"` | `socket_bind`, `socket_listen` |
| `touch /tmp/x; chmod 4755 /tmp/x` | `tmp_write` |
| `cp /usr/bin/ls /tmp/ls; /tmp/ls` | `suspicious_exec` |
| `python3 -c "import os; os.memfd_create('x', 0)"` | `fileless_exec` (P0-04) |
| C-loader для `ptrace(PTRACE_TRACEME, ...)` | `process_injection` (P0-04) |
| C-loader для `bpf(BPF_PROG_LOAD, ...)` | `ebpf_use` (P0-04) |
| C-loader для `io_uring_setup` | `io_uring` (P0-04) |
| Триггеры под Tier A из P1-01 | каждый соответствующий ключ |

**Структура плейбука:**

- Tag `apply` — выполняет триггеры последовательно.
- Tag `assert` — ждёт N секунд (propagation), затем через OpenSearch `_search` проверяет наличие документов с ожидаемыми ключами за окно N+5 секунд.
- Tag `rollback` — чистит созданное (удаляет тестового пользователя, файлы, выгружает модуль).
- C-loaders для ptrace/bpf/io_uring — лежат в `tests/auditd/fixtures/` как готовые бинарники либо собираются на месте через `gcc`.

### Точки изменений (P1-04)

- Новый каталог `tests/auditd/` с `auditd-trigger.yml` и `fixtures/`.
- Возможно — общий helper для OpenSearch assertion (можно вынести как Ansible-роль `tests/_lib/`).

### Критерий готовности (P1-04)

- `ansible-playbook tests/auditd/auditd-trigger.yml --tags apply,assert` на dev-стенде: все assertion-таски зелёные за <60 секунд.
- `--tags rollback` чисто откатывает (повторный запуск idempotent — не падает на отсутствии тестового user'а).
- В CI (если будет, см. P3-02): плейбук гоняется на эфемерном test-хосте после любых правок в `audit.rules` или `auditd_enrich.lua`.

### Грабли (P1-04)

- **Race condition propagation.** Между триггером и проверкой OpenSearch нужно ~5-10 секунд: audit.log → fluent-bit merge (2 сек timeout) → Logstash batch → OpenSearch refresh (1 сек). Заложить `wait_for` или явный `sleep 10`.
- **ptrace и bpf через Python ctypes** часто не работают как ожидается из-за seccomp-фильтров или kernel-restrictions. Лучше отдельный C-loader (короткий, компилируется в плейбуке `gcc -x c - -o ... <<EOF`).
- **Idempotent rollback.** Если плейбук падает на N-м таске, rollback должен сработать чисто и не валиться на отсутствии созданных артефактов. Использовать `failed_when: false` для cleanup-операций.
- **Module loading.** Загрузка любого .ko требует unsigned-load разрешения. На kernel lockdown=integrity или secure boot — упадёт. Документировать в требованиях к тестовому хосту.
- **Удаление test-user'а** — если он что-то залогинит во время теста (открытая ssh-сессия), userdel падает. Использовать `userdel -f`.

---

## P2-01. osquery BPF backend + container.entity_id — фундамент поведенческой модели контейнеров

**Приоритет:** P2 → повышен до следующей итерации (необходим для CONTAINER_BEHAVIOR_PLAN)
**Стоимость:** ~1.5 дня (templatize конфига + docker_containers query + container_cache в enrich + Ansible per-host + dev-тест)
**Статус:** **выполнено 2026-05-21**
**Родительский документ:** [CONTAINER_BEHAVIOR_PLAN.md](../CONTAINER_BEHAVIOR_PLAN.md) — Направление 1
**Зависимости:** независима, но при появлении будущей задачи syscall-rules (правило auditd `-S bpf`) — обязательная связка через whitelist osqueryd, иначе feedback loop. P0-03 существует (с багами) — при починке нужен whitelist `-F exe!=/usr/bin/osqueryd`.

### Зачем (P2-01)

Активирует в osquery event-driven таблицы `bpf_process_events` и `bpf_socket_events` через флаг `--enable_bpf_events=true`, добавляет `docker_containers` diff-запрос и формирует `container.entity_id` — стабильный ключ сущности для UEBA-скоринга. Что это даёт:

- **Container-aware видимость** на docker-хостах — eBPF читает namespace'ы, auditd плоский по хосту. На docker-хостах без BPF половина процессов внутри контейнеров частично теряется в attribution.
- **Independent second source** для execve и network — кросс-сверка с auditd. Расхождения двух источников сами по себе сигнал.
- **Более точный `process.start_time`** (kernel monotonic clock) — улучшает стабильность `process.entity_id` из P0-01.
- **Не конфликтует с auditd** (в отличие от старого audit-netlink backend osquery, который у нас отключён через `disable_audit=true`).

**Чего НЕ делает:** не закрывает io_uring (eBPF тоже его не видит), не заменяет auditd (BPF backend ловит только process+socket, не file/PAM/network-config), не "бесплатно" — добавит ~5-10% к объёму osquery-событий на busy-хостах.

### Ключевое требование: переключение per-host

BPF backend нужен **на docker-хостах** (контейнерная видимость), но избыточен и затратен **на рабочих станциях** (там процессов много, контейнеров нет, overhead не оправдан). Поэтому фича включается через Ansible-переменную, и деплой агентов должен уметь выбирать профиль.

**Модель:**

- Дефолт по флоту: `osquery_bpf_events_enabled: false` в [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml).
- В [agents/deploy/inventory.ini](agents/deploy/inventory.ini) ввести группу `[docker_hosts]` со своей секцией vars или отдельным `group_vars/docker_hosts.yml`, где переопределить `osquery_bpf_events_enabled: true`.
- Рабочки попадают в любую другую группу (например `[workstations]`) — наследуют дефолт `false`.
- Pre-flight в плейбуке: если `osquery_bpf_events_enabled=true`, но `ansible_kernel < 5.10` — fail с понятным сообщением.

Это и есть та самая опция при деплое.

### Что делать (P2-01)

**1. Templatize osquery-конфиг.**
Переименовать [agents/configs/osquery/osquery.conf](agents/configs/osquery/osquery.conf) → `osquery.conf.j2` (Jinja2). Существующие диффовые запросы оставить как есть. Добавить условный блок:

```jinja
"options": {
  ...
  {% if osquery_bpf_events_enabled %}
  "enable_bpf_events": "true",
  "bpf_buffer_storage_size": "1024",
  "bpf_perf_event_array_exp": "14",
  {% endif %}
  ...
},
"schedule": {
  ...
  {% if osquery_bpf_events_enabled %}
  "bpf_processes": {
    "query": "SELECT * FROM bpf_process_events;",
    "interval": 10,
    "removed": false,
    "description": "Event-driven process creation/exit via eBPF"
  },
  "bpf_sockets": {
    "query": "SELECT * FROM bpf_socket_events;",
    "interval": 10,
    "removed": false,
    "description": "Event-driven socket bind/connect/accept via eBPF"
  }
  {% endif %}
}
```

(`{% if %}` блоки в JSON корректны только если шаблон рендерится в валидный JSON — следить за trailing-запятыми, проверить рендер через `ansible -m template --check`).

**2. Ansible-переменные и группы.**
В [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml) добавить дефолт `osquery_bpf_events_enabled: false`.
В [agents/deploy/group_vars/all.yml.example](agents/deploy/group_vars/all.yml.example) показать пример переопределения для docker-группы.
Создать `agents/deploy/group_vars/docker_hosts.yml` с `osquery_bpf_events_enabled: true` (этот файл в репо, реальные хосты пишутся уже в inventory).
[agents/deploy/inventory.ini](agents/deploy/inventory.ini) — в комментарии показать структуру `[docker_hosts]` / `[workstations]`.

**3. Pre-flight в плейбуке.**
В [agents/deploy/agents-deploy.yml](agents/deploy/agents-deploy.yml) добавить task с `ansible.builtin.fail` если `osquery_bpf_events_enabled and ansible_kernel is version('5.10', '<')`.

**4. Enrich.**
В [agents/configs/fluent-bit/scripts/osquery_enrich.lua](agents/configs/fluent-bit/scripts/osquery_enrich.lua) добавить ветки маппинга для новых таблиц. Схемы отличаются от обычной `processes`:

- `bpf_process_events`: `tid`, `pid`, `parent`, `path`, `cmdline`, `uid`, `gid`, `ntime` (kernel time), `exit_code`, `probe_error`, `cgroup`, `cid` (container id).
- `bpf_socket_events`: `pid`, `tid`, `family`, `protocol`, `local_address`, `remote_address`, `local_port`, `remote_port`, `action` (bind/connect/accept).

ECS-маппинг: `event.module=osquery`, `event.dataset=osquery.bpf_process_events` / `osquery.bpf_socket_events`, `event.category=process` / `network`, `event.type=start`/`end`, plus стандартные `process.*`/`network.*`/`source.*`/`destination.*`. Если есть `cid` (container id) — заполнять `container.id`.

**5. Документация.**
[CLAUDE.md](CLAUDE.md): обновить таблицу осquery, упомянуть `bpf_*` таблицы, **явно прописать матрицу группа→флаг**, требование к ядру (5.10+).

### Точки изменений (P2-01)

- **Переименовать:** `agents/configs/osquery/osquery.conf` → `osquery.conf.j2`.
- **Правки:** [agents/configs/fluent-bit/scripts/osquery_enrich.lua](agents/configs/fluent-bit/scripts/osquery_enrich.lua) (новые ветки + `container_cache`), [agents/deploy/agents-deploy.yml](agents/deploy/agents-deploy.yml), [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml), [agents/deploy/group_vars/all.yml.example](agents/deploy/group_vars/all.yml.example), [agents/deploy/inventory.ini](agents/deploy/inventory.ini), [CLAUDE.md](CLAUDE.md).
- **Новые файлы:** `agents/deploy/group_vars/docker_hosts.yml`.
- **Обновить:** [CONTAINER_BEHAVIOR_PLAN.md](../CONTAINER_BEHAVIOR_PLAN.md) (статус Недели 1), [README_FOR_AI.md](../README_FOR_AI.md) (раздел 4.5 + ECS-extensions).

### Критерий готовности (P2-01)

- На docker-test-хосте (с `osquery_bpf_events_enabled=true`, ядро ≥5.10): `osqueryctl config_check` проходит; `osqueryi --enable_bpf_events --json "SELECT count(*) FROM bpf_process_events"` возвращает ненулевой счётчик; в индексе `fluent-osquery-*` появляются документы с `event.dataset=osquery.bpf_process_events`.
- BPF-документы внутри контейнерных процессов имеют непустые `container.id`, `container.name`, `container.entity_id`.
- `docker_containers` diff-документы появляются при запуске/остановке контейнера; `container.image.name` (не `container.image`) заполнено корректно.
- На workstation-test-хосте (с дефолтным `false`): отсутствует флаг `--enable_bpf_events` в рендере конфига; в индексе `fluent-osquery-*` НЕТ документов с `bpf_*` dataset'ом; CPU osqueryd не изменился относительно baseline.
- Pre-flight срабатывает: при попытке прогнать плейбук с `osquery_bpf_events_enabled=true` против хоста с ядром 4.x — плейбук падает с понятным сообщением до изменения конфига.
- В CLAUDE.md явно указано: docker → BPF on, workstations → BPF off.

### Грабли (P2-01)

- **Версия ядра.** Стабильно 5.15+. На 5.10 BTF может быть собран в дистрибутиве без полного CO-RE — проверить наличие `/sys/kernel/btf/vmlinux` до включения.
- **Версия osquery.** BPF backend требует osquery ≥ 4.6 (стабильно с 5.0). В [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml) есть пин-версия — проверить, что мы выше порога.
- **Capabilities.** osqueryd запускается под root, что покрывает CAP_BPF/CAP_PERFMON. Если в будущем понадобится non-root osqueryd — потребуются явные caps.
- **Feedback loop с audit-правилом `-S bpf` из P0-04.** osqueryd сам триггерит audit-события на BPF-загрузку → fluent-bit → snowball. Обязательно: в audit-правиле P0-04 для `bpf` добавить `-F exe!=/usr/bin/osqueryd` либо whitelist по uid. Без этого зацикливание гарантировано на старте osqueryd.
- **Объём.** Скедул интервал 10 сек — баланс между latency и объёмом. На очень busy-хостах (CI runners, kubelet-nodes с ~500 short-lived процессов/мин) может понадобиться увеличить `bpf_buffer_storage_size` или поднять интервал до 30 сек.
- **Templatize конфига — риск trailing-запятых в JSON.** После `{% endif %}` в JSON легко получить `,}` или `}{` — обязательно прогнать `python -m json.tool` на рендере перед прод-деплоем (или использовать `validate: 'python3 -c "import json; json.load(open(\"%s\"))"'` в Ansible template-task).
- **`cgroup`/`cid` поля.** В BPF-таблицах есть container_id, но он сырой (full sha256 cgroup-path). Для корректного `container.id` ECS — обрезать до 12-символьного префикса.

---

## P2-02. Расширение osquery-запросов

**Приоритет:** P2 (полнота покрытия для UEBA)
**Стоимость:** ~0.5 дня
**Статус:** выполнено 2026-05-21
**Зависимости:** опционально совмещать с P2-01 (если конфиг уже templatized в .j2 — расширения добавлять в общий шаблон с условиями per-profile).

### Зачем (P2-02)

Текущий [osquery.conf](agents/configs/osquery/osquery.conf) покрывает базовые таблицы (`processes`, `listening_ports`, `users`, `kernel_modules`, `services`, `crontab`, `authorized_keys`). Из исходного анализа есть ещё ~10 высокосигнальных таблиц, не использованных, которые добавляют значимое покрытие для UEBA — особенно для supply-chain, preload injection и workstation-специфичной малвары.

### Что делать (P2-02)

Добавить в [osquery.conf](agents/configs/osquery/osquery.conf) (или в `osquery.conf.j2` после P2-01) следующие scheduled-запросы:

| Запрос | Интервал, сек | Профиль | UEBA-feature |
| --- | --- | --- | --- |
| `shell_history` (bash_history, zsh_history) | 300 | server+ws | sequence-аномалии в командной строке |
| `last` (utmp/wtmp) | 300 | server+ws | login/logout sessions с источником |
| `process_envs` для процессов с `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH` | 60 | server+ws | classic preload injection |
| `chrome_extensions`, `firefox_addons` | 3600 | **ws only** | малвара через расширения |
| `python_packages`, `npm_packages`, `pip_packages` | 7200 | server+ws | supply-chain (typosquatting, dep confusion) |
| `process_memory_map` (фильтр `path NOT LIKE '/usr/%'`) | 300 | server+ws | shared object hijack |
| `kernel_keys` | 600 | server+ws | посаженные kerberos/keychain ключи |
| `deb_packages` diff | 3600 | server+ws | новые пакеты на хосте |
| `acpi_tables` | 86400 | server+ws | firmware tampering (low freq) |
| `sudoers` | 1800 | server+ws | изменения sudo policy |

Для разделения профилей "server" vs "workstation" — использовать ту же переменную, что и в P2-01: `osquery_profile: server|workstation` в Ansible group_vars. В .j2 — `{% if osquery_profile == 'workstation' %}` вокруг chrome_extensions/firefox_addons.

**Расширить [osquery_enrich.lua](agents/configs/fluent-bit/scripts/osquery_enrich.lua):** каждая новая таблица имеет свою схему колонок, требует отдельной ветки маппинга в ECS. Базовый паттерн: `event.dataset = "osquery." + table_name`, `event.action = action_field` (added/removed), специфика per-table.

### Точки изменений (P2-02)

- [agents/configs/osquery/osquery.conf](agents/configs/osquery/osquery.conf) (или `.j2` после P2-01).
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](agents/configs/fluent-bit/scripts/osquery_enrich.lua).
- [tests/osquery/osquery-trigger.yml](tests/osquery/osquery-trigger.yml) — добавить триггеры под новые таблицы (например, `pip install <test-pkg>` для `pip_packages` diff, добавление расширения в Chrome для `chrome_extensions`).
- [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml) — переменная `osquery_profile`.

### Критерий готовности (P2-02)

- На dev-хосте все новые запросы выполняются: `osqueryi --json "SELECT ..."` возвращает результаты без ошибок.
- Через расширенный `osquery-trigger.yml`: каждая новая таблица даёт событие в `fluent-osquery-*` с правильным `event.dataset` и заполненными ECS-полями.
- Watchdog osquery не превышает лимит 350 MB (текущий) — измерить RSS osqueryd через 24 часа после включения.
- На workstation профиль: появляются документы с `event.dataset=osquery.chrome_extensions` и `osquery.firefox_addons`; на server профиль — отсутствуют.

### Грабли (P2-02)

- **`chrome_extensions` под root** обычно работает, но в encrypted home directories (LUKS-encrypted /home, не примонтированный для root) падает. На workstation-профиле — допустимо, на серверах не критично.
- **`python_packages`/`npm_packages` на dev-машинах** могут вернуть тысячи строк (node_modules, pip global). Без diff-only (`removed: false`) первый запуск зальёт индекс. Проверить, что используется именно diff-режим.
- **`shell_history` приватность** — содержит команды пользователей, потенциально секреты в command-line. Зафиксировать в политике безопасности проекта; рассмотреть фильтр на стороне enrich (маскирование значений после `--password=`, `--token=`).
- **`process_envs` высокочастотный.** На сервере с ~500 процессами и интервалом 60 сек получаем 720 запусков/день × 500 строк = 360k событий/день только от одного хоста. Без жёсткого фильтра в WHERE (только процессы с подозрительным env) — затопит индекс. Запрос должен включать `WHERE key IN ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH') AND value IS NOT NULL`.

---

## P3-01. Unit-тесты Lua-скриптов (merge + enrich)

**Приоритет:** P3 (отложено)
**Стоимость:** ~1 день
**Статус:** не начато. Возвращаемся, когда начнём ловить регрессии в Lua после правок.
**Триггер для возврата:** появление бага в merge/enrich, который не был замечен при ревью; либо когда наберётся 3+ правки Lua подряд без тестового подтверждения.

### Зачем (P3-01)

Lua-фильтры — самый хрупкий узел стека: `auditd_merge.lua` держит stateful буфер по serial, `auditd_enrich.lua` и `osquery_enrich.lua` делают много табличных преобразований. Регресс там не падает шумно — он просто ломает поля ECS, и об этом узнаёшь по неработающим запросам в OpenSearch через дни. Тесты страхуют от этого.

### Почему не нужны агенты и полное окружение

Lua-скрипты — чистые функции над stdlib (string/table/math/io/os). Зависимости от fluent-bit нет — только конвенция сигнатуры `(tag, timestamp, record) → (code, ts, record)`. Значит вызвать функцию с подготовленной таблицей-входом можно из любого Lua-интерпретатора. Audit-парсинг (regex в `parsers.conf`) на этом уровне НЕ тестируется — фикстуры пишутся уже в post-parser формате.

### Подход (P3-01)

**Уровень 1 — unit (этот пункт).** Lua 5.1 + busted в Docker-образе `nickblah/lua:5.1-luajit-alpine` (тот же LuaJIT, что у fluent-bit). Запуск: `docker run --rm -v $PWD:/work -w /work <image> busted tests/lua/spec`. Время — секунды. Никакого fluent-bit/auditd/OpenSearch.

**Уровень 2 — integration (отдельная будущая задача).** Настоящий fluent-bit в docker-compose читает фикстуру `audit.log` → `out_file` → diff с expected JSON. Покрывает связку parser+merge+enrich. Здесь НЕ планируем.

### Структура

```text
tests/lua/
  Dockerfile                 # FROM nickblah/lua:5.1-luajit-alpine + busted
  run.sh                     # docker build + docker run
  spec/
    auditd_merge_spec.lua
    auditd_enrich_spec.lua
    osquery_enrich_spec.lua
  fixtures/
    auditd/{execve_simple,execve_no_eoe,sshd_login,sudo_cmd,serial_split}.lua
    osquery/{process_added,socket_added}.lua
  helpers/
    load_script.lua          # мокает io.popen до dofile (важно для hostname-кэша)
    ecs_assert.lua
```

### Минимальный набор сценариев на день

**auditd_merge:**

- одиночный execve → один merged
- полная серия `SYSCALL+EXECVE+PATH+CWD+PROCTITLE` → один merged
- серия без EOE (auditd 4.x) → timeout-флаш через N сек
- две серии с разными serial вперемежку → две независимые записи
- серия, разорванная между батчами → merge всё равно собирается

**auditd_enrich:**

- syscall→event.action для execve/openat/connect/setuid/unlink (smoke)
- очистка служебных `_paths`/`_event_types`/`_execve_args`
- host.name/user.id/user.name/process.parent.pid установлены
- file.path: absolute и relative+CWD конкатенация
- event.outcome из `success=yes/no`

**osquery_enrich:**

- processes → `process.*` маппинг
- diff-action (added/removed) → `event.action`
- мультистрочный JSON-массив → итерация

### Точки изменений (P3-01)

- Новый каталог [tests/lua/](tests/lua/).
- (опционально) `.github/workflows/lua-tests.yml` для CI.

### Критерий готовности (P3-01)

- `tests/lua/run.sh` локально проходит без ошибок.
- Покрыты все сценарии из списка выше.
- Любая правка в `*.lua` — gate в CI: тесты должны быть зелёными для merge.

### Грабли (P3-01)

- Кэш `_hostname` заполняется при первом вызове через `io.popen("hostname -f")`. Чтобы тест не зависел от реального хоста — мокать `io.popen` ДО `dofile()` загрузки скрипта.
- `nickblah/lua:5.1-luajit-alpine` — выбран сознательно, потому что fluent-bit ≥ 1.9 использует именно LuaJIT 2.1 (совместим с Lua 5.1). Не брать `lua:5.4` или PUC-Rio Lua 5.1 — поведение `bit32`/`tostring(number)` отличается.
- Фикстуры предпочтительнее ЗАПИСЫВАТЬ с реального fluent-bit (`out_file` после `useradd`/`sudo`/`ssh-keygen` на тестовом хосте), а не синтезировать руками — реалистичнее ловит edge-cases.

---

## P3-02. CI: статический анализ + syntax-check

**Приоритет:** P3 (гигиена)
**Стоимость:** ~4 часа
**Статус:** не начато
**Зависимости:** нет; полезно когда появится хотя бы базовое покрытие Lua-тестами (P3-01), но не обязательно.

### Зачем (P3-02)

Дешёвая защита от опечаток и регрессов "забыл закрыть скобку / undefined variable". Не заменяет тесты, но ловит ~80% явных синтаксических багов до merge'а. Особенно полезно для Lua, Ansible YAML и JSON-шаблонов.

### Что делать (P3-02)

Создать workflow в `.github/workflows/lint.yml` (или эквивалент в Gitea/GitLab — зависит от площадки). Шаги:

| Проверка | Команда |
| --- | --- |
| Lua статический анализ | `luacheck agents/configs/fluent-bit/scripts/*.lua` |
| Ansible syntax | `ansible-playbook --syntax-check logstash/deploy/logstash-deploy.yml agents/deploy/agents-deploy.yml` |
| fluent-bit конфиг | `fluent-bit --dry-run -c agents/configs/fluent-bit/fluent-bit.conf` (в Docker) |
| Logstash pipeline | `logstash -t -f logstash/configs/pipeline/ueba-main.conf` (в Docker) |
| osquery конфиг | `osqueryi --config_path=agents/configs/osquery/osquery.conf --config_check` (в Docker) |
| JSON-шаблоны | `python -m json.tool` на всех `logstash/configs/templates/*.json` (после P1-02) |
| YAML-валидность | `yamllint logstash/ agents/` |

Условия запуска: на каждый push в любую ветку + на PR. Cache Docker layers где возможно для скорости.

Базовый `luacheckrc` в корне репо: разрешить `_ENV`, fluent-bit globals (если будем добавлять), отключить max-line-length warnings (Lua-скрипты у нас длинные).

### Точки изменений (P3-02)

- Новый `.github/workflows/lint.yml`.
- Новый `.luacheckrc` в корне.
- (опционально) `.yamllint` в корне с расслабленными правилами под Ansible-стиль.

### Критерий готовности (P3-02)

- PR с заведомо сломанным Lua (опечатка в функции) — CI красный с понятным сообщением.
- PR с валидными изменениями — зелёный, прогон < 2 минут.
- В README или CLAUDE.md упоминание про CI gate.

### Грабли (P3-02)

- **fluent-bit `--dry-run` в Docker** требует определённой версии образа — пинить тег к версии, используемой в проде (см. [agents/deploy/group_vars/all.yml](agents/deploy/group_vars/all.yml)).
- **luacheck warnings vs errors.** По умолчанию luacheck ругается на много стилистики (unused arg, line too long). Настроить `.luacheckrc` так, чтобы failed CI был только на серьёзных вещах (undefined global, syntax error, type mismatch). Иначе будут постоянные жалобы на легитимный код.

---

## P3-03. Property-based fuzz для merge-buffer

**Приоритет:** P3 (edge-case защита)
**Стоимость:** ~0.5 дня
**Статус:** не начато
**Зависимости:** требует тестовой инфраструктуры из P3-01 (Lua-runner в Docker).

### Зачем (P3-03)

[auditd_merge.lua](agents/configs/fluent-bit/scripts/auditd_merge.lua) собирает auditd-серии по serial number. Записи приходят к fluent-bit пакетами из tail-input в произвольном порядке внутри пакета (kernel пишет последовательно, но fluent-bit читает чанками). Race conditions в порядке записей теоретически могут давать разный итоговый JSON. Property-based test проверяет инвариант: **итоговый merged-документ независим от порядка прихода строк одной серии**.

Это ловит редкий класс багов, которые stateful unit-тесты не находят, потому что в unit-тестах фикстуры фиксированы.

### Что делать (P3-03)

Скрипт `tests/property/merge_fuzz.lua` (запускается тем же runner'ом, что и P3-01):

1. Зафиксировать "канонический" merged-результат для конкретной серии (`SYSCALL+EXECVE+PATH+CWD+PROCTITLE`).
2. Сгенерировать N=1000 случайных перестановок этих 5 строк.
3. Каждую перестановку прогнать через `auditd_merge`-функцию, собрать output.
4. Проверить: для всех 1000 перестановок результат **изоморфен** каноническому (одинаковые ключи и значения, порядок ключей не важен).

Вторая property: **timeout-флаш разделяет серии правильно**. Если внутри серии случайно вставить искусственный sleep, превышающий timeout merge-функции, то ожидаем **два** документа на выходе (один до timeout, один после) — а не один склеенный.

### Точки изменений (P3-03)

- Новый `tests/property/merge_fuzz.lua`.
- Расширить `tests/lua/run.sh` опцией `--with-property` для запуска fuzz-тестов отдельно от обычных (они медленнее).

### Критерий готовности (P3-03)

- 1000 перестановок проходят без расхождений с каноническим результатом.
- Timeout-разделение работает корректно (две перестановки одной серии вокруг искусственного timeout дают два документа).
- В CI выполняется опционально (`--with-property` вызывается только на main-branch или вручную) — обычные PR не ждут лишних 30 секунд.

### Грабли (P3-03)

- **Порядок ключей в Lua-таблицах** недетерминирован. Сравнение "изоморфно" — НЕ через прямой `==` таблиц, а через рекурсивное сравнение значений по ключам.
- **Серии с timeout-флашем (auditd 4.x без EOE)** — там порядок важен (приходящие после timeout-флаша записи дают второй документ). Это отдельная property, не общая инвариантность.
- **Запись `PROCTITLE` обычно идёт последней** в реальном auditd-выводе. Перестановки с `PROCTITLE` в начале — синтетический случай. Если такие падают, но в реальной жизни не встречаются — задокументировать и oставить как known limitation.
