# CLAUDE.md — UEBA проект
Мы разрабатываем конфигурации источников для сбора данных.
Данные будут использоваться для UEBA системы на основе скоринга.
Собираемые данные должны поступать нормализованными по ECS 8.x.
Главный приоритет - сохранение совместимости с оригинальным Elastic.

**Цели:** 
1. Минимизировать потребление токенов через оптимизированную навигацию по проекту и точные инструкции.
2. Разработать скрипты для автоматизации развертывания и обновления агентов.
3. Настроить источники для сбора событий, которые в дальнейшем можно применить для поведенческого анализа. Используем современный подход к решению вопроса и действуем как эксперт в области компьютерной безопасности.

## План улучшений и промпты

Все задачи hardening и подробные ТЗ для AI-агентов лежат в [HARDENING/](HARDENING/README.md):

- [HARDENING/HARDENING_PLAN.md](HARDENING/HARDENING_PLAN.md) — оставшиеся задачи: P1-03, P1-04, P3-01, P3-02, P3-03. Выполненные задачи v0.9 описаны в [docs/RELEASE_NOTES_0.9.md](docs/RELEASE_NOTES_0.9.md).
- `HARDENING/PX-NN-<slug>.md` — промпты для исполнения по одной итерации (сейчас: P1-03, P1-04).
- [HARDENING/CONTAINER_BEHAVIOR_PLAN.md](HARDENING/CONTAINER_BEHAVIOR_PLAN.md) — план поведенческой модели контейнеров (P4).
- См. [HARDENING/README.md](HARDENING/README.md) для порядка исполнения и принципов.

## Справочник по данным для AI-агентов

Если задача касается ECS-схемы (типизация полей, добавление/изменение event.action / event.category, новых источников) — обязательно сверять с [README_FOR_AI.md](README_FOR_AI.md). Этот файл — источник истины по схеме данных, любые правки enrich-скриптов или audit-правил должны его обновлять.

## Стек агентов

| Сервис | Роль |
|--------|------|
| **auditd** | Kernel audit: execve, sudo, auth, file_integrity → /var/log/audit/audit.log |
| **fluent-bit** | 1) Читает audit.log; merge по serial + ECS enrich (Lua) → TCP 5045 → `fluent-audit-*`<br>2) Читает osqueryd.results.log; ECS enrich (Lua) → TCP 5047 → `fluent-osquery-*` |
| **osquery** | Diff-мониторинг: процессы, соединения, пользователи, модули, сервисы, cron, SSH-ключи.<br>**На docker-хостах** (группа `[docker_hosts]`, `osquery_bpf_events_enabled=true`, ядро ≥5.10): BPF backend → `bpf_process_events`, `bpf_socket_events` — container-aware видимость с нативным `container.id`; `docker_containers` diff для инвентаря контейнеров. |

**auditbeat** не используется — конфликтует с auditd за audit netlink-сокет.

## Структура проекта

```
ueba-stand/
│
├── logstash/
│   ├── configs/
│   │   ├── logstash.yml                 — настройки Logstash (workers, queue)
│   │   ├── pipelines.yml                — список пайплайнов
│   │   ├── pipeline/
│   │   │   └── ueba-main.conf           — ГЛАВНЫЙ файл: beats relay + fluent-bit TCP 5045/5047/5048
│   │   └── patterns/                    — grok-паттерны (.gitkeep)
│   └── deploy/
│       ├── logstash-deploy.yml          — Ansible плейбук (docker pull + deploy)
│       ├── ansible.cfg
│       ├── inventory.ini
│       ├── docker-compose.yml           — разворачивается на целевом хосте
│       ├── group_vars/all.yml           — переменные деплоя
│       ├── templates/.env.j2            — шаблон credentials
│       └── files/                       — opensearch-ca.pem (gitignored)
│
├── agents/
│   ├── configs/
│   │   ├── auditd/
│   │   │   └── audit.rules              — правила auditd для UEBA (execve, network, identity...)
│   │   ├── fluent-bit/
│   │   │   ├── fluent-bit.conf          — главный конфиг fluent-bit (auditd pipeline)
│   │   │   ├── parsers.conf             — парсеры auditd строк
│   │   │   ├── fluent-bit.env.j2        — Ansible template: /etc/default/fluent-bit
│   │   │   └── scripts/
│   │   │       ├── auditd_merge.lua     — объединение событий по serial number
│   │   │       ├── auditd_enrich.lua    — обогащение в ECS + MITRE ATT&CK теги
│   │   │       └── osquery_enrich.lua   — ECS-обогащение osquery diff-событий
│   │   └── osquery/osquery.conf.j2      — Jinja2-шаблон конфига osquery (BPF backend per-group)
│   └── deploy/
│       ├── agents-deploy.yml            — Ansible плейбук (auditd + fluent-bit + osquery)
│       ├── agents-deploy-legacy.yml     — архив старого плейбука
│       ├── ansible.cfg
│       ├── inventory.ini
│       ├── group_vars/all.yml           — logstash_host, версии пакетов
│       ├── group_vars/all.yml.example   — шаблон переменных
│       └── fetch-packages/              — скачать .deb для офлайн-деплоя
│           ├── fetch.ps1
│           └── Dockerfile
│
├── docs/
│   └── RELEASE_NOTES_0.9.md             — Release notes v0.9 для человека
│
├── opensearch/
│   └── templates/
│       ├── fluent-audit.json            — шаблон индекса fluent-audit-* (ECS 8.11)
│       ├── fluent-osquery.json          — шаблон индекса fluent-osquery-* + osquery.* namespace
│       └── README.md                   — инструкция по применению (curl + PowerShell)
│
├── README.md
└── .gitignore
```

## Ключевые файлы по темам

| Тема | Файлы | Назначение |
|------|-------|-----------|
| **Пайплайн** | `logstash/configs/pipeline/ueba-main.conf` | beats relay 5044 + fluent-bit TCP 5045/5047 |
| **Конфиги Logstash** | `logstash/configs/logstash.yml`, `pipelines.yml` | Настройки рантайма |
| **Деплой Logstash** | `logstash/deploy/logstash-deploy.yml` | Ansible: docker pull + copy + up |
| **Переменные Logstash** | `logstash/deploy/group_vars/all.yml` | opensearch_url, SSL, image, bind_addr |
| **Правила auditd** | `agents/configs/auditd/audit.rules` | execve, network, priv_escalation, file watch; Tier A (P1-01): anti-forensics, persistence, container escape; Tier B: env/mac/pkg/firewall/dns — cherry-pick из Neo23x0/auditd |
| **Конфиг fluent-bit** | `agents/configs/fluent-bit/fluent-bit.conf` | auditd + osquery pipelines |
| **Lua merge** | `agents/configs/fluent-bit/scripts/auditd_merge.lua` | объединение auditd записей по serial |
| **Lua enrich** | `agents/configs/fluent-bit/scripts/auditd_enrich.lua` | ECS-обогащение (MITRE ATT&CK теги отключены); pid→start_time кэш + `/proc/<pid>/stat` для `process.entity_id`; обработчики USER_*/CRED_*/SERVICE_START/SERVICE_STOP и реклассификация AF_UNIX/AF_NETLINK/AF_PACKET сокетов (QA-02) |
| **Lua osquery enrich** | `agents/configs/fluent-bit/scripts/osquery_enrich.lua` | ECS-обогащение osquery diff-событий + osquery.* namespace; pid→start_time кэш; `process.entity_id` совпадает с auditd; QA-03: `cgroup_ns_cache` (osquery.cid → container.id) + AF_NETLINK/AF_UNIX → category=process + `normalize_int64` для BPF exit_code + `uid_to_name` для kernel_keys + `container_observed_*` action |
| **Конфиг osquery** | `agents/configs/osquery/osquery.conf.j2` | Jinja2-шаблон: diff-запросы + BPF backend per-group + profile server/workstation |
| **Деплой агентов** | `agents/deploy/agents-deploy.yml` | Ansible: auditd + fluent-bit + osquery |
| **Переменные агентов** | `agents/deploy/group_vars/all.yml` | logstash_host, версии .deb, osquery_profile |
| **Index templates** | `opensearch/templates/*.json` | Маппинги ECS 8.11 v2.0 для всех индексов; применяются через logstash-deploy.yml |
| **Release Notes** | `docs/RELEASE_NOTES_0.9.md` | Human-readable описание v0.9 |

## Индексы OpenSearch

| Индекс | Источник |
|--------|---------|
| `fluent-audit-YYYY.MM.dd` | fluent-bit: auditd ECS-события (execve, sudo, auth, network, file) — TCP 5045 |
| `fluent-osquery-YYYY.MM.dd` | fluent-bit: osquery diff-события ECS + osquery.* namespace — TCP 5047 |

## Инструкции по сокращению токенов

### 1. Поиск по проекту
- **Файлы**: `Glob` с паттерном (напр., `agents/configs/**/*.j2`)
- **Содержимое**: `Grep` с регулярным выражением вместо чтения всего файла
- **Не читайте без цели**: если нужно найти что-то конкретное — сначала Grep

### 2. Чтение больших конфигов
- Для файлов > 50 строк указывайте `limit` и `offset` в Read
- Сначала Grep для поиска нужного участка, потом Read 5–10 строк вокруг него

### 3. Параллельное выполнение
- Читайте несвязные файлы в одном вызове Read
- Это уменьшает количество обходов туда-сюда

### 4. Документирование
- **Изменения пайплайна**: обновить `ueba_event_pipeline_map.md` (если существует)
- **Переменные деплоя Logstash**: `logstash/deploy/group_vars/all.yml`
- **Переменные деплоя агентов**: `agents/deploy/group_vars/all.yml`

## Оптимизация для частых операций

### Изменить пайплайн Logstash
```
1. Grep в logstash/configs/pipeline/ueba-main.conf
2. Read 10–15 строк вокруг найденного
3. Edit нужный блок
4. Прод: cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Изменить конфиг агентов (auditd / fluent-bit / osquery)
```
1. Read agents/configs/<subsystem>/<file> целиком (все < 200 строк)
2. Edit нужный блок
3. cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

### Развернуть Logstash на новом хосте
```
1. Обновить logstash/deploy/inventory.ini
2. Положить CA-сертификат: logstash/deploy/files/opensearch-ca.pem
3. ansible-vault create logstash/deploy/host_vars/<host>.yml  (opensearch_password)
4. cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Развернуть агентов на новых VM
```
1. Обновить agents/deploy/inventory.ini
2. Задать logstash_host в agents/deploy/group_vars/all.yml
3. Скачать .deb пакеты: .\agents\deploy\fetch-packages\fetch.ps1
4. cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

### Применить index templates на новом стенде
```
1. Открыть opensearch/templates/README.md — там curl и PowerShell команды
2. Применить перед первой отправкой событий (иначе ip-поля замапятся как keyword)
3. Проверить: curl -u admin:pass 'http://opensearch:9200/_cat/templates?v&name=fluent-*'
```

## Команды для быстрого старта

```bash
# Проверка индексов OpenSearch
curl -s 'http://opensearch:9200/_cat/indices?v&index=fluent-audit-*,fluent-osquery-*' | sort

# Деплой Logstash в прод
cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass

# Деплой агентов
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass

# Syntax-check плейбуков
ansible-playbook --syntax-check logstash/deploy/logstash-deploy.yml
ansible-playbook --syntax-check agents/deploy/agents-deploy.yml

# Проверка агентов на хосте
systemctl status auditd fluent-bit osqueryd

# Метрики fluent-bit (pipeline health)
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool
```

## Известные особенности и грабли

### auditd 4.x — нет type=EOE в audit.log
auditd **4.0+** не пишет `type=EOE` в `/var/log/audit/audit.log` — в 4.x EOE обрабатывается внутри dispatcher-плагинов и в лог не попадает. `end_of_event_timeout = 2` в `auditd.conf` **не исправляет** это поведение.

**Следствие**: `auditd_merge.lua` НЕ должен полагаться на EOE как единственный триггер флаша. Скрипт флашит по timeout (wall clock, `os.time()`): после TIMEOUT секунд без новых записей для данного serial — запись уходит в поток. EOE-ветка оставлена для совместимости с auditd < 4.0.

**Диагностика fluent-bit**: если `filter.lua.0.add_records = 0` при ненулевом `input.tail.0.records` — merge-скрипт не флашит. Проверить:
```bash
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool
```

### pid→start_time кэш в enrich-скриптах (холодный старт)
`auditd_enrich.lua` и `osquery_enrich.lua` держат in-memory кэш `pid → start_time`. Кэш **теряется при рестарте fluent-bit**. Сразу после старта:
- `process.parent.entity_id` отсутствует для процессов, чьи родители ещё не встречались в потоке событий (родитель жив, но его execve fluent-bit пропустил).
- Для долгоживущих процессов enrich обратится в `/proc/<pid>/stat` напрямую — это работает, пока процесс жив.

Размер кэша ограничен 10 000 записей; при превышении кэш сбрасывается целиком (bulk eviction).

### exit-события короткоживущих процессов
Если процесс завершился до того, как enrich обработал его exit-событие, `/proc/<pid>/stat` уже недоступен и кэша нет → `start_time` берётся из `@timestamp` события. Поле `labels.entity_id_source = "event_timestamp_fallback"` сигнализирует об этом. `process.entity_id` такого события **не совпадёт** с osquery — это known limitation.

### osquery BPF backend — матрица групп и whitelist для bpf-правила

**Матрица:**

| Группа Ansible | `osquery_bpf_events_enabled` | BPF-таблицы |
|---|---|---|
| `[docker_hosts]` | `true` (из `group_vars/docker_hosts.yml`) | `bpf_process_events`, `bpf_socket_events`, `docker_containers` |
| `[workstations]`, `[servers]` | `false` (из `group_vars/all.yml`) | нет |

**Требования на docker-хостах:** ядро ≥ 5.10, `/sys/kernel/btf/vmlinux`, osquery ≥ 4.6. Pre-flight assert в плейбуке.

**Feedback loop с auditd `-S bpf`:** osqueryd при загрузке BPF-программ триггерит правило `-S bpf` в audit.rules → события попадают в fluent-bit → snowball. Необходимо добавить к bpf-правилу `-F exe!=/usr/bin/osqueryd` (отдельный коммит, не смешивать с другими задачами).

**container_cache в osquery_enrich.lua:** in-memory словарь `cid[12] → {name, image}`. Заполняется из diff-событий `docker_containers`. `bpf_process_events` и `bpf_socket_events` используют кэш для резолвинга `container.name` / `container.image.name` / `container.entity_id`. Кэш теряется при рестарте fluent-bit — первые BPF-события после рестарта не получат container-атрибуцию.

**cgroup_ns_cache в osquery_enrich.lua (QA-03):** in-memory маппинг `cgroup_namespace_inode → container.id[12]`. Заполняется при `docker_containers/added`: для каждого added контейнера enrich читает `/proc/<container.pid>/ns/cgroup` через `readlink` (символлинк `cgroup:[<inode>]`). BPF-события содержат `cols.cid = inode` — это позволяет резолвить `container.id` даже для короткоживущих subprocess, где `/proc/<pid>/cgroup` уже недоступен (`bpf_process_events` для `/app/extra/healthcheck`, `/bin/sh` итд). **Failure modes:**

- Кэш теряется при рестарте fluent-bit. Первые BPF-события после рестарта без container-атрибуции до прихода первого `docker_containers/added` diff (≤30 сек).
- При `docker_containers/removed` запись из кэша **НЕ** удаляется — osquery diff может «мигнуть» (контейнер бежит, но строка пропала на 1 интервал и вернулась). Bulk evict только при превышении `CGNS_CACHE_MAX = 1000`.
- `event.action="container_observed_added"`/`"container_observed_removed"` (НЕ `started/stopped`): osquery diff не отражает реальный lifecycle, а только присутствие в snapshot. Реальный lifecycle — Docker Events API (см. `HARDENING/CONTAINER_BEHAVIOR_PLAN.md`, P4). Fallback `event.action=container_exited` если `osquery.state in ("exited","dead")`.

**BPF exit_code overflow (QA-03):** BPF taps записывают signed int64 как uint64 — `-115 EINPROGRESS` приходит как `18446744073709551501`. `normalize_int64()` в `osquery_enrich.lua` декодирует обратно для `osquery.exit_code` (в общем cols→osquery.* loop) и `process.exit_code` (в `bpf_processes` блоке).

**AF_UNIX/AF_NETLINK/AF_PACKET в bpf_sockets (QA-03):** для non-IP families enrich override'ит `event.category` из `network` (QUERY_META default) в `process`. Заполнение ECS `network.*` полей пропускается (нет IP/port). `event.action=socket_<syscall>_nonip` (отдельно от `socket_<syscall>` для AF_INET/AF_INET6).

### Профили osquery и shell_history (P2-02)

**Профильная переменная:** `osquery_profile` в `agents/deploy/group_vars/all.yml` (default: `server`). Переопределяется через `group_vars/workstations.yml` (`workstation`).

**Матрица запросов по профилям:**

| Запросы | server | workstation |
|---------|--------|-------------|
| shell_history, last_logins, preload_envs, python/npm/pip/deb_packages_diff, kernel_keys_diff, sudoers_diff, acpi_tables_diff, suspicious_mmap | ✓ | ✓ |
| chrome_extensions_diff, firefox_addons_diff | — | ✓ |

**shell_history и приватность:** `shell_history` читает `~/.bash_history` / `~/.zsh_history` всех пользователей. Маскирование `--password=`, `--token=`, `--api-key=` в Lua **не применяется** (отключено по решению проекта) — raw command lines попадают в `fluent-osquery-*`. При изменении политики — добавить `gsub`-паттерны в `osquery_enrich.lua` блок `shell_history`.

### Auditd bpf-правило и osquery BPF backend

Правило `-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=unset -k ebpf_use` добавлено в P0-04 **без** whitelist'а osqueryd.

На хостах с включённым BPF backend (`[docker_hosts]`) osqueryd триггерит это правило при загрузке BPF-программ → feedback loop. **Необходимо добавить к bpf-правилу `-F exe!=/usr/bin/osqueryd`** — отдельный коммит.

### `USER_*` / `SERVICE_*`: очистка raw-полей в самом конце enrich (QA-02)

`auditd_enrich.lua` хранит merge-поля `USER_*`/`CRED_*`/`SERVICE_*` с префиксом источника (`user_res`, `user_ses`, `cred_disp_acct`, `service_start_msg`, ...). Очистка этих полей должна выполняться **в самом конце** функции `enrich_ecs`, **после** блоков «Результат события» (читает `user_res`/`service_*_res` → `event.outcome`) и «Сессия auditd» (читает `user_ses` → `auditd.session`).

**Грабли (QA-01 → QA-02):** ранее очистка стояла внутри блока `USER_*` и удаляла `user_res`/`user_ses` до того, как они читались → `event.outcome` и `auditd.session` отсутствовали в 100% authentication-событий. Если двигаешь блоки или добавляешь новый источник с префиксом — убедись, что финальный cleanup идёт последним.

### process.args порядок — собирать по индексу `argc`, не через pairs() (QA-02)

`auditd_merge.lua` блок EXECVE собирает `_execve_args` итерируясь по `a0..a<argc-1>` через `tonumber(kv.argc)`. **Нельзя** использовать `for k,v in pairs(kv) do if k:match("^a%d+$") then ...` — порядок хеш-таблицы недетерминирован и реверсирует args (`sleep 10` → `["10","sleep"]`), что ломает ECS и совместимость с Elastic.

### AF_UNIX/AF_NETLINK/AF_PACKET — реклассификация event.category (QA-02)

decode_saddr в `auditd_enrich.lua` возвращает `unix`/`netlink`/`packet` для family 1/16/17 соответственно. Блок SOCKADDR:

- **AF_UNIX (family=1)**: `event.category=["network","file"]` (массив — двойная категория для IPC через файл-сокет), `network.type=unix`.
- **AF_NETLINK (family=16)**: `event.category=process` (управление ядром/маршрутизацией, не сетевой трафик), `network.type=netlink`.
- **AF_PACKET (family=17)**: `event.category=process` (raw L2 — sniffer/forwarder), `network.type=packet`.

Это **ECS-расширение проекта** (ECS допускает массив в `event.category`); не путать с baseline ECS, где AF_UNIX-сокеты обычно идут как `network`.

---

## Что НЕ читать

- `.git/` — используйте `git log` вместо чтения объектов
- `*.log` — используйте `journalctl -n 50`
- `agents/deploy/files/*.deb` — бинарные пакеты, в git не хранятся

---

**Последнее обновление:** 2026-05-23
**Версия проекта:** 0.9 — auditd+fluent-bit+osquery (pure fluent-bit стек) → Logstash → OpenSearch
