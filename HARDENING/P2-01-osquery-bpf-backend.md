# P2-01. osquery BPF backend — переключаемый по типу хоста

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор по проекту.
- [README_FOR_AI.md](../README_FOR_AI.md), раздел 4 — текущая схема osquery-источника. Эта задача добавит две новые event-driven таблицы (`bpf_process_events`, `bpf_socket_events`) — README_FOR_AI обязан остаться источником истины.
- [HARDENING_PLAN.md, раздел P2-01](HARDENING_PLAN.md) — обоснование, требования к ядру, переключение per-host, грабли.
- [CONTAINER_BEHAVIOR_PLAN.md](../CONTAINER_BEHAVIOR_PLAN.md) — **родительский документ этой задачи**: план поведенческой модели контейнеров. Эта итерация реализует Направление 1 (источники). Все новые поля, вводимые здесь, должны соответствовать схеме из раздела 3.1 этого документа.

## Цель итерации

Заложить фундамент **поведенческой модели Docker-контейнеров** (см. [CONTAINER_BEHAVIOR_PLAN.md](../CONTAINER_BEHAVIOR_PLAN.md)):

1. Активировать event-driven таблицы osquery через `--enable_bpf_events=true` **на docker-хостах** — получить надёжный источник процессов и соединений с нативным `container.id`.
2. Добавить таблицу `docker_containers` в расписание osquery — inventory запущенных контейнеров с diff.
3. В `osquery_enrich.lua` сформировать поля `container.name`, `container.image.name`, `container.entity_id` — ключ сущности для UEBA-скоринга.

На рабочих станциях BPF НЕ включать (overhead не оправдан без контейнеров). Toggle реализуется через Ansible-переменную и Jinja-template osquery-конфига.

**Value сразу:**

- Каждый процесс и сетевое соединение внутри контейнера получают `container.id` нативно — без polling gap и без ненадёжного `/proc/<pid>/cgroup` lookup.
- `container.entity_id = host.name:container.name` — стабильный ключ сущности, переживающий рестарты контейнера.
- Второй независимый источник process+socket событий — кросс-сверка с auditd (расхождение само по себе сигнал аномалии).
- Более точный `process.start_time` из kernel monotonic clock — улучшает стабильность `process.entity_id` (если P0-01 сделан).

**Независимая ценность:** даже без P0-03 / P1-01 — на docker-хостах появляется container-aware видимость, которой раньше не было.

**ECS-примечания:**
- `container.entity_id` — кастомное расширение ECS (аналог `process.entity_id`, которое есть в стандарте). Задокументировать в README_FOR_AI как extension.
- Образ контейнера: **`container.image.name`** (не `container.image`) — стандарт ECS 8.x.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Какие хосты в inventory относятся к docker-хостам?**
   - Нужно их перечислить и поместить в группу `[docker_hosts]` (или другая существующая группа — уточнить у пользователя).
   - Остальные считаются workstations / generic servers — для них BPF backend выключен.
2. **Версия osquery, зафиксированная в `agents/deploy/group_vars/all.yml`** — она ≥ 4.6?
   - Если нет — нужен апгрейд (отдельная подзадача, можно сделать в рамках этой итерации, можно отдельно). Уточнить.
3. **Какое значение интервала** для BPF-запросов в schedule?
   - **Recommended:** 10 сек (баланс latency/объём).
   - Альтернативы: 5 сек (быстрее, больше объём) / 30 сек (для очень busy-хостов).
4. **Готов ли P0-03 (auditd-правило `-S bpf`)?**
   - Если ДА — обязательно обновить это правило с `-F exe!=/usr/bin/osqueryd` перед включением BPF backend, иначе feedback loop.
   - Если НЕТ — отметить как риск для будущей раскатки P0-03.

## Pre-flight проверки

1. **Версия ядра** на docker-хостах:

   ```bash
   ansible docker_hosts -m setup -a "filter=ansible_kernel"
   ```

   Минимум **5.10**, recommended **5.15+**. На старых ядрах BPF backend нестабилен.

2. **Наличие BTF** (BPF Type Format — обязателен для CO-RE):

   ```bash
   ansible docker_hosts -m stat -a "path=/sys/kernel/btf/vmlinux"
   ```

   Если файл отсутствует — kernel собран без `CONFIG_DEBUG_INFO_BTF=y`, BPF backend работать не будет. На таких хостах задача невыполнима, исключить из группы.

3. **Версия osquery** на целевых хостах:

   ```bash
   ansible docker_hosts -m shell -a "osqueryd --version 2>&1 | head -1"
   ```

   Должна быть ≥ 4.6 (стабильно с 5.0). Если ниже — обновление пакета перед задачей.

4. **Состояние P0-03 (audit-правило `-S bpf`):**

   ```bash
   ansible docker_hosts -m shell -a "auditctl -l | grep -E '\-S bpf|ebpf_use' || echo 'no bpf rule'"
   ```

   - Если правило ЕСТЬ и в нём НЕТ исключения osqueryd — обязательно обновить до раскатки BPF backend.
   - Если правила НЕТ — отметить, что при появлении (раскатка P0-03 в будущем) понадобится whitelist.

5. **Прочитать целиком:**
   - [agents/configs/osquery/osquery.conf](../agents/configs/osquery/osquery.conf) — стиль текущего конфига.
   - [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — паттерн маппинга в ECS.
   - [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml) — где копируется osquery-конфиг, чтобы заменить на template.
   - [agents/deploy/inventory.ini](../agents/deploy/inventory.ini) — текущие группы.

## Реализация

### Шаг 1. Templatize osquery-конфиг

Переименовать `agents/configs/osquery/osquery.conf` → `agents/configs/osquery/osquery.conf.j2`. Содержимое оставить как есть — это валидный JSON, Jinja допускает любой текст без операторов.

Добавить условные блоки. **В секции `options`:**

```jinja
"options": {
  "config_plugin": "filesystem",
  "logger_plugin": "filesystem",
  "logger_path": "/var/log/osquery",
  "disable_logging": "false",
  "log_result_events": "true",
  "schedule_splay_percent": "10",
  "disable_audit": "true",
  {% if osquery_bpf_events_enabled | default(false) %}
  "enable_bpf_events": "true",
  "bpf_buffer_storage_size": "1024",
  "bpf_perf_event_array_exp": "14",
  {% endif %}
  "events_expiry": "3600",
  "events_max": "50000"
},
```

(Сохрани точно тот же набор `options`, что в оригинальном конфиге; добавь только три новых ключа под `{% if %}`.)

**В секции `schedule` в конец** (перед `}`), два блока:

**1. docker_containers — всегда на docker-хостах** (не только при BPF):

```jinja
  {% if osquery_bpf_events_enabled | default(false) %},
  "docker_containers": {
    "query": "SELECT id, name, image, image_id, status, pid, (SELECT hostname FROM system_info) AS hostname FROM docker_containers WHERE status = 'running'",
    "interval": 30,
    "description": "Running container inventory diff (P2-01)"
  }
  {% endif %}
```

**2. BPF event-driven таблицы** (только при enable_bpf_events):

```jinja
  {% if osquery_bpf_events_enabled | default(false) %},
  "bpf_processes": {
    "query": "SELECT * FROM bpf_process_events;",
    "interval": {{ osquery_bpf_interval | default(10) }},
    "removed": false,
    "description": "Event-driven process creation/exit via eBPF (P2-01)"
  },
  "bpf_sockets": {
    "query": "SELECT * FROM bpf_socket_events;",
    "interval": {{ osquery_bpf_interval | default(10) }},
    "removed": false,
    "description": "Event-driven socket bind/connect/accept via eBPF (P2-01)"
  }
  {% endif %}
```

**ВАЖНО:** JSON чувствителен к запятым. `{% if %},` перед новыми блоками — корректно только если предыдущий schedule-элемент НЕ имеет trailing comma. Сверь со скобками в текущем `osquery.conf` и расставь правильно.

После Jinja-рендера обязательно прогоняй через `python3 -c "import json; json.load(open('rendered.conf'))"` перед раскаткой.

### Шаг 2. Ansible-переменные и группы

**В [agents/deploy/group_vars/all.yml](../agents/deploy/group_vars/all.yml):**

```yaml
# osquery BPF backend toggle (P2-01)
# Дефолт: выключено (workstations и generic servers).
# Переопределяется на уровне группы (docker_hosts.yml) или per-host.
osquery_bpf_events_enabled: false

# Интервал scheduled BPF-запросов (сек). По умолчанию 10.
osquery_bpf_interval: 10
```

**В [agents/deploy/group_vars/all.yml.example](../agents/deploy/group_vars/all.yml.example):** добавить тот же блок с пояснением, что переопределить можно в `group_vars/docker_hosts.yml`.

**Создать `agents/deploy/group_vars/docker_hosts.yml`:**

```yaml
# Переопределения для группы docker_hosts.
# Хосты в этой группе получают BPF backend и связанные scheduled-запросы.
osquery_bpf_events_enabled: true
```

**Дополнить [agents/deploy/inventory.ini](../agents/deploy/inventory.ini)** — в комментариях показать структуру групп:

```ini
# Пример: docker_hosts получают osquery BPF backend (P2-01).
# Workstations и servers без контейнеров — BPF выключен.
#
# [docker_hosts]
# docker-node-1.example.com
# docker-node-2.example.com
#
# [workstations]
# ws-alice.example.com
#
# [servers]
# srv-db-1.example.com
```

(Если у пользователя уже есть inventory — не ломай его, только добавь нужные группы.)

### Шаг 3. Pre-flight задача в плейбуке

В [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml) добавить **перед** task'ами развертывания osquery:

```yaml
- name: "[P2-01] Pre-flight: kernel version for BPF backend"
  ansible.builtin.assert:
    that:
      - ansible_kernel is version('5.10', '>=')
    fail_msg: >-
      osquery_bpf_events_enabled=true requires kernel >= 5.10
      (found: {{ ansible_kernel }}). Set false for this host or upgrade kernel.
  when: osquery_bpf_events_enabled | default(false)
  tags: [osquery, p2_01]

- name: "[P2-01] Pre-flight: BTF availability"
  ansible.builtin.stat:
    path: /sys/kernel/btf/vmlinux
  register: btf_stat
  when: osquery_bpf_events_enabled | default(false)
  tags: [osquery, p2_01]

- name: "[P2-01] Fail if BTF missing"
  ansible.builtin.fail:
    msg: >-
      BTF (/sys/kernel/btf/vmlinux) is missing on this host —
      kernel built without CONFIG_DEBUG_INFO_BTF. BPF backend cannot work.
  when:
    - osquery_bpf_events_enabled | default(false)
    - not btf_stat.stat.exists
  tags: [osquery, p2_01]
```

### Шаг 4. Заменить copy на template

В [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml) найти существующий task, копирующий `osquery.conf` (через `copy` или `template`). Заменить на:

```yaml
- name: Render and deploy osquery config
  ansible.builtin.template:
    src: "{{ playbook_dir }}/../configs/osquery/osquery.conf.j2"
    dest: /etc/osquery/osquery.conf
    owner: root
    group: root
    mode: '0644'
    validate: 'python3 -c "import json,sys; json.load(open(''%s''))"'
  notify: Restart osqueryd
  tags: [osquery]
```

`validate:` критичен — если Jinja-рендер дал невалидный JSON, плейбук упадёт ДО подмены файла на хосте.

### Шаг 5. Расширить enrich для bpf_process_events / bpf_socket_events

В [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) добавить ветки маппинга.

Схема `bpf_process_events`:

```
tid, pid, parent, path, cmdline, uid, gid, ntime (kernel time),
exit_code, probe_error, cgroup, cid (container id)
```

Маппинг в ECS:

```lua
-- Внутри функции enrich_osquery, в блоке выбора по record["name"]:

elseif name == "bpf_processes" then
    record["event.category"] = "process"
    record["event.dataset"]  = "osquery.bpf_process_events"
    record["event.action"]   = (action == "added") and "process_started"
                                                   or "process_stopped"
    record["event.type"]     = (action == "added") and "start" or "end"

    if cols["pid"]      then record["process.pid"]      = tonumber(cols["pid"]) end
    if cols["parent"]   then record["process.parent.pid"] = tonumber(cols["parent"]) end
    if cols["path"]     then record["process.executable"] = cols["path"] end
    if cols["cmdline"]  then record["process.command_line"] = cols["cmdline"] end
    if cols["uid"]      then record["user.id"]  = cols["uid"] end
    if cols["gid"]      then record["user.group.id"] = cols["gid"] end
    if cols["exit_code"] then record["process.exit_code"] = tonumber(cols["exit_code"]) end

    -- container.id из cid (cgroup-path hash → берём первые 12 hex)
    if cols["cid"] and cols["cid"] ~= "" then
        local cid = string.sub(cols["cid"], 1, 12)
        record["container.id"] = cid
        -- Резолвинг container.name и container.image.name из кэша docker_containers
        -- (кэш заполняется при обработке events от таблицы docker_containers)
        local meta = container_cache[cid]
        if meta then
            record["container.name"]       = meta.name
            record["container.image.name"] = meta.image  -- ECS 8.x: container.image.name, не container.image
            local hostname = record["host.name"] or ""
            record["container.entity_id"] = hostname .. ":" .. meta.name
        end
    end

    -- Если P0-01 сделан, обновить cache_put/short_id с использованием ntime как start_time
    if cols["pid"] and cols["ntime"] then
        local seed = (record["host.name"] or "") .. ":" .. cols["pid"] .. ":" .. cols["ntime"]
        record["process.entity_id"] = short_id(seed)
        cache_put(cols["pid"], cols["ntime"])
    end

elseif name == "bpf_sockets" then
    record["event.category"] = "network"
    record["event.dataset"]  = "osquery.bpf_socket_events"
    record["event.action"]   = "socket_" .. (cols["action"] or "unknown")  -- bind/connect/accept
    record["event.type"]     = "start"

    if cols["pid"]            then record["process.pid"] = tonumber(cols["pid"]) end
    if cols["family"]         then record["network.protocol"] = cols["family"] end
    if cols["protocol"]       then record["network.transport"] = cols["protocol"] end
    if cols["local_address"]  then record["source.ip"]   = cols["local_address"] end
    if cols["local_port"]     then record["source.port"] = tonumber(cols["local_port"]) end
    if cols["remote_address"] then record["destination.ip"]   = cols["remote_address"] end
    if cols["remote_port"]    then record["destination.port"] = tonumber(cols["remote_port"]) end

elseif name == "docker_containers" then
    -- Заполняем container_cache: cid[12] → {name, image}
    -- Используется bpf_processes/bpf_sockets для резолвинга container.name и container.image.name
    record["event.category"]  = "host"
    record["event.dataset"]   = "osquery.docker_containers"
    record["event.action"]    = (action == "added") and "container_started" or "container_stopped"
    record["event.type"]      = (action == "added") and "start" or "end"

    if cols["id"] and cols["name"] then
        local cid = string.sub(cols["id"], 1, 12)
        if action == "added" then
            container_cache[cid] = { name = cols["name"], image = cols["image"] or "" }
        else
            container_cache[cid] = nil
        end
        record["container.id"]         = cid
        record["container.name"]        = cols["name"]
        record["container.image.name"]  = cols["image"] or ""  -- ECS 8.x: container.image.name
        local hostname = record["host.name"] or ""
        record["container.entity_id"]  = hostname .. ":" .. cols["name"]
    end
    if cols["status"] then record["container.runtime"] = "docker" end
```

Перед первым `elseif` добавить объявление кэша на уровне модуля (один раз при загрузке скрипта):

```lua
-- in-memory кэш container_id[12] → {name, image} для резолвинга в bpf_* событиях
local container_cache = {}
```

**Сверь** с реальным синтаксисом текущего `osquery_enrich.lua` — вставь в правильное место (where `name == "..."` branches are). Если P0-01 не сделан — пропусти `short_id`/`cache_put` блок.

### Шаг 6. Раскатка и smoke на docker-test-хосте

```bash
cd agents/deploy

# Сначала dry-run на одном docker-хосте
ansible-playbook agents-deploy.yml --ask-become-pass \
  --limit=docker-test-host --tags=osquery,p2_01 --check --diff

# Если ок — реально применить
ansible-playbook agents-deploy.yml --ask-become-pass \
  --limit=docker-test-host --tags=osquery,p2_01
```

**Smoke:**

```bash
# На docker-test-хосте: проверить, что флаг прорисовался
ansible docker-test-host -m shell -a "grep -E 'enable_bpf_events|bpf_processes' /etc/osquery/osquery.conf"
# Должны быть видны ключи

# Проверить, что osqueryd работает и не падает
ansible docker-test-host -m shell -a "systemctl status osqueryd | head -10"

# Через osqueryi проверить, что BPF-таблица доступна
ansible docker-test-host -m shell -a "osqueryi --json 'SELECT count(*) AS n FROM bpf_process_events'"
# Должно вернуть [{"n":"<число>"}]

# Запустить тестовый процесс в контейнере на docker-test-хосте, проверить наличие
# документа в OpenSearch с container.id заполненным:
ansible docker-test-host -m shell -a "docker run --rm alpine sh -c 'sleep 2'"
sleep 15
curl -s "$OS/fluent-osquery-*/_search?size=3&sort=@timestamp:desc&q=event.dataset:osquery.bpf_process_events" \
  | jq '.hits.hits[]._source | {pid: .["process.pid"], cmd: .["process.command_line"], container: .["container.id"]}'
```

Должны быть документы с непустым `container.id`.

### Шаг 7. Контр-проверка на workstation-test-хосте

```bash
ansible-playbook agents-deploy.yml --ask-become-pass \
  --limit=workstation-test --tags=osquery
ansible workstation-test -m shell -a "grep -c enable_bpf_events /etc/osquery/osquery.conf"
# Должно быть 0 (флаг не появился — feature flag off)
```

## Что НЕ делать в этой итерации

- **НЕ ставить новые osquery-запросы** (`shell_history`, `process_envs` и др.) — это P2-02, отдельная задача.
- **НЕ обновлять audit-правило `-S bpf`** в рамках этой задачи. Если P0-03 уже сделан — отдельным маленьким коммитом добавь whitelist `-F exe!=/usr/bin/osqueryd` к существующему правилу (5 минут работы), но не смешивай с этой итерацией.
- **НЕ настраивать TLS-шифрование** scheduled-запросов отдельно — для osquery 5047 → Logstash TLS делается в P1-03.
- **НЕ настраивать nightly tracing** через osquery `osquery_events` (отдельная feature). Только process_events + socket_events.
- **НЕ менять `disable_audit=true`** в options. eBPF backend сосуществует с auditd — это его суть.
- **НЕ создавать integration-тест** для BPF-таблиц в `osquery-trigger.yml` — отдельная подзадача после стабилизации.

## Проверка готовности

Из [HARDENING_PLAN.md P2-01 → Критерий готовности](HARDENING_PLAN.md):

- **На docker-test-хосте** (osquery_bpf_events_enabled=true, ядро ≥5.10):
  - `osqueryctl config_check` проходит.
  - `osqueryi --enable_bpf_events --json "SELECT count(*) FROM bpf_process_events"` возвращает ненулевой счётчик.
  - В `fluent-osquery-*` появляются документы с `event.dataset=osquery.bpf_process_events`.
  - Документы внутри контейнерных процессов имеют непустой `container.id`.
- **На workstation-test-хосте** (дефолтный false):
  - В рендере конфига нет флага `enable_bpf_events`.
  - В индексе нет документов с `bpf_*` dataset.
  - CPU osqueryd не вырос относительно baseline (sanity).
- **Pre-flight срабатывает:** прогон против хоста с ядром 4.x с `bpf=true` — плейбук падает с понятным сообщением ДО изменения конфига.

## Финал

1. **Обновить [CONTAINER_BEHAVIOR_PLAN.md](../CONTAINER_BEHAVIOR_PLAN.md):**
   - В разделе "Порядок реализации" отметить Неделю 1 как выполненную.
   - В разделе "Зависимости" обновить статус P2-01.
   - В разделе 3.1 уточнить, что `container.entity_id` — кастомное расширение ECS, задокументированное в README_FOR_AI.md.

2. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделе 4 ("Источник: osquery") добавить под-раздел "4.5 BPF backend (event-driven, только docker-хосты)":
     - Список двух таблиц: `bpf_process_events`, `bpf_socket_events`.
     - Гарантированные ECS-поля: тот же базовый блок + `container.id` для events внутри контейнеров.
     - Требования: ядро ≥5.10, наличие `/sys/kernel/btf/vmlinux`, osquery ≥4.6.
     - Pointer на toggle: `osquery_bpf_events_enabled` в `group_vars/docker_hosts.yml`.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В таблице "Стек агентов" к строке osquery добавить пометку: "На docker-хостах — BPF backend (`bpf_process_events`, `bpf_socket_events`) для container-aware видимости".
   - В "Известные особенности и грабли" добавить:
     - Матрица: docker_hosts → BPF on / workstations+servers → BPF off.
     - Cross-task: при наличии audit-правила `-S bpf` (P0-03) — обязательно whitelist `osqueryd` иначе feedback loop.

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P2-01 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить:**

   ```
   P2-01: osquery BPF backend toggleable per host

   - osquery.conf templatized as .j2, conditional BPF blocks
   - Ansible: osquery_bpf_events_enabled flag (default false, true for docker_hosts)
   - Pre-flight: kernel >=5.10 + BTF availability assertion
   - osquery_enrich.lua: bpf_process_events / bpf_socket_events ECS mapping
     + container.id from cgroup hash
   - validate: python3 json.tool on rendered template
   - README_FOR_AI: section 4.5 with new tables
   - CLAUDE.md: docker/ws toggle matrix + P0-03 cross-dep note
   ```

5. **Сообщить пользователю**: BPF backend активен на docker-хостах, в индексе `fluent-osquery-*` есть события с `container.id`; контр-проверка на workstation подтверждает, что overhead там не появился. Если P0-03 уже сделан — НАПОМНИ про необходимость отдельного маленького PR с whitelist для bpf-правила.
