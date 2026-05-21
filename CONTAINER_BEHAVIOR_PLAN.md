# Поведенческая модель сервисов (Docker-контейнеры) — план реализации

**Версия:** 0.1  
**Дата:** 2026-05-21  
**Статус:** на рассмотрение

---

## Постановка задачи

Построить поведенческую модель Docker-контейнеров на основе телеметрии с Linux-хостов.  
Модель описывает "нормальный портрет" каждого сервиса по шести измерениям:

| Измерение | Что фиксируется |
|-----------|-----------------|
| Процессы | Ожидаемые имена, пути, аргументы, parent→child дерево |
| Сеть | Направления соединений (IP/порты), объём, протоколы |
| Файлы | Пути, которые сервис читает/пишет |
| Идентичность | UID/GID процессов, факты повышения привилегий |
| Жизненный цикл | Частота рестартов, смена образа, появление новых контейнеров |
| Аутентификация | SSH-доступ к хосту, sudo на хосте |

Отклонение от модели → вклад в UEBA-скор сущности.

---

## Ключевые решения

### Единица наблюдения (сущность)

```
container.entity_id = host.name + ":" + container.name
```

- `host.name` — физический или виртуальный хост
- `container.name` — имя контейнера в Docker Compose / docker run (стабильно между рестартами)
- `container.id` — короткоживущий, используется только для внутреннего join; не является ключом сущности

### Источники данных

Два независимых механизма — намеренное дублирование для кросс-верификации:

| Источник | Роль |
|----------|------|
| **osquery BPF backend** | Поведенческая модель контейнеров: процессы + соединения с нативным `container.id` |
| **auditd** | Compliance trail, sudo, auth, file integrity, syscall-level атаки (уровень хоста) |

Расхождение между двумя источниками (событие есть в auditd, но нет в osquery BPF и наоборот) — само по себе аномальный сигнал.

---

## Направление 1 — Источники (агенты)

### 1.1 Активировать osquery BPF backend на docker-хостах

**Задача:** P2-01 (промпт готов: `HARDENING/P2-01-osquery-bpf-backend.md`)

osquery начиная с версии 4.6 имеет встроенный eBPF backend — event-driven таблицы без polling gap:

- `bpf_process_events` — каждый `execve` в реальном времени
- `bpf_socket_events` — каждый `connect` / `bind` / `accept`

Оба содержат нативное поле `cid` (container ID из cgroup) — container attribution без дополнительных lookup.

**Требования к хосту:**
- Ядро ≥ 5.10, рекомендуется ≥ 5.15
- BTF: `/sys/kernel/btf/vmlinux` должен существовать (`CONFIG_DEBUG_INFO_BTF=y`)
- osquery ≥ 4.6

**Что настраивается:**
- `osquery.conf` → Jinja-template: `enable_bpf_events: true` только для группы `[docker_hosts]`
- Ansible pre-flight: проверка версии ядра и наличия BTF перед раскаткой
- Интервал scheduled BPF-запросов: 10 сек

### 1.2 Добавить docker_containers в osquery.conf

```sql
SELECT id, name, image, image_id, status, pid
FROM docker_containers
WHERE status = 'running'
```
Интервал: 30 сек. Даёт diff контейнеров: запущен / остановлен / сменил образ.

### 1.3 Расширить osquery_enrich.lua

- Маппинг `bpf_process_events` → ECS (описан в P2-01):
  - `process.pid`, `process.parent.pid`, `process.executable`, `process.command_line`
  - `user.id`, `user.group.id`
  - `container.id` из поля `cid`
  - `process.entity_id` из `host.name + pid + ntime` (kernel monotonic clock)

- Маппинг `bpf_socket_events` → ECS:
  - `source.ip`, `source.port`, `destination.ip`, `destination.port`
  - `network.transport`, `event.action` = `socket_connect` / `socket_bind` / `socket_accept`
  - `container.id` из поля `cid`

- Резолвинг `container.name` и `container.image` через lookup из diff `docker_containers` по `container.id`

- Формирование `container.entity_id = host.name + ":" + container.name`

### 1.4 auditd — не изменяется

Текущие правила остаются без изменений. auditd продолжает закрывать:
- sudo / USER_CMD (через PAM, осquery BPF этого не видит)
- Аутентификационные события (USER_LOGIN, USER_AUTH, USER_LOGOUT)
- File integrity (`-w /etc/passwd`, `/etc/sudoers` и др.)
- Syscall-level атаки: `ptrace`, `finit_module`, `memfd_create`, `io_uring`
- Privilege escalation: `setuid`, `setgid`, `setresuid`

---

## Направление 2 — OpenSearch

### 2.1 Обновить index template fluent-osquery-*

Добавить маппинги новых полей:

```json
"container.id":          { "type": "keyword" },
"container.name":        { "type": "keyword" },
"container.image":       { "type": "keyword" },
"container.entity_id":   { "type": "keyword" },
"event.dataset":         { "type": "keyword" }
```

Применять до первой индексации BPF-событий, иначе поля лягут как `text`.

### 2.2 Настроить Anomaly Detectors (OpenSearch RCF)

Все детекторы используют `category_field: container.entity_id` — OpenSearch строит независимую модель для каждого сервиса.

| Детектор | Индекс | Метрика | Окно | Что ловит |
|----------|--------|---------|------|-----------|
| Process burst | `fluent-osquery-*` | `count(bpf_process_events, action=added)` | 5 мин | всплеск запуска процессов |
| Socket burst | `fluent-osquery-*` | `count(bpf_socket_events, action=connect)` | 5 мин | C2 beaconing, exfil |
| New listening port | `fluent-osquery-*` | `count(listening_ports, diff=added)` | 1 мин | reverse shell, backdoor |
| execve rate (host) | `fluent-audit-*` | `count(event.action=executed)` | 5 мин | fileless, injection |
| SSH failures (host) | `system-auth-*` | `count(event.outcome=failure)` | 1 мин | brute-force |

Каждый детектор возвращает `anomaly_score` ∈ [0..1] per `container.entity_id`.

### 2.3 Настроить Alerting

- Threshold: composite score > 0.7 → уведомление в SOC (webhook / email)
- Отдельные правила для критичных событий (не ML, а детерминированные):
  - `process.name IN (sh, bash, python, perl)` в контейнере с uid=www-data
  - `user.id = 0` у процесса в контейнере, где исторически uid > 0
  - Запись в `/etc/`, `/usr/bin/`, `/tmp/*.sh`

---

## Направление 3 — Данные для скоринговой системы (надпроект)

Этот раздел описывает, **что скоринговая система получит от стенда** после реализации направлений 1–2.

### 3.1 Индексы и их содержимое

#### `fluent-osquery-YYYY.MM.dd`

Основной источник для поведенческой модели контейнеров.

**Гарантированные поля для BPF-событий:**

| Поле | Тип | Описание |
|------|-----|----------|
| `@timestamp` | date | Время события (UTC) |
| `host.name` | keyword | Имя хоста |
| `container.id` | keyword | Docker container ID (первые 12 символов) |
| `container.name` | keyword | Имя контейнера (docker-compose service name) |
| `container.image` | keyword | Образ (без тега) |
| `container.entity_id` | keyword | `host.name:container.name` — ключ сущности |
| `event.dataset` | keyword | `osquery.bpf_process_events` или `osquery.bpf_socket_events` |
| `event.action` | keyword | `process_started`, `process_stopped`, `socket_connect`, `socket_bind` |
| `event.category` | keyword | `process` или `network` |
| `process.pid` | long | PID в host namespace |
| `process.parent.pid` | long | PPID |
| `process.executable` | keyword | Полный путь бинаря |
| `process.command_line` | keyword | Командная строка с аргументами |
| `process.entity_id` | keyword | `short_hash(host.name:pid:ntime)` — стабильный ID |
| `user.id` | keyword | UID процесса |
| `user.group.id` | keyword | GID процесса |
| `destination.ip` | ip | Для socket_connect |
| `destination.port` | long | Для socket_connect |
| `source.port` | long | Для socket_bind |
| `network.transport` | keyword | `tcp` / `udp` |

**Polling-события (уже существуют, дополняются `container.*`):**

| `event.dataset` | Интервал | Что даёт |
|-----------------|----------|----------|
| `osquery.processes` | 30 сек | diff новых/завершённых процессов с `container.entity_id` |
| `osquery.process_connections` | 30 сек | активные соединения живых процессов |
| `osquery.listening_ports` | 60 сек | diff новых/закрытых портов |
| `osquery.process_open_files` | 60 сек | открытые файловые дескрипторы |
| `osquery.docker_containers` | 30 сек | diff запущенных/остановленных контейнеров |

#### `fluent-audit-YYYY.MM.dd`

Уровень хоста. Нет `container.entity_id` — это уровень хоста (`host.name`).

| Поле | Описание |
|------|----------|
| `event.action` | `executed`, `network-connection`, `opened-file`, `privileged-call` |
| `process.entity_id` | Стабильный hash, совместим с osquery |
| `process.parent.entity_id` | Для построения process tree |
| `user.id` / `user.name` | UID / имя пользователя |
| `process.executable` | Полный путь |
| `process.command_line` | Аргументы |
| `destination.ip` / `destination.port` | Для network-connection |
| `file.path` | Для opened-file |

#### `system-auth-YYYY.MM.dd`

SSH аутентификация, уровень хоста.

| Поле | Описание |
|------|----------|
| `event.outcome` | `success` / `failure` |
| `event.action` | `ssh_login`, `ssh_logout`, `ssh_invalid_user` |
| `user.name` | Имя пользователя |
| `source.ip` | IP источника подключения |
| `host.name` | Хост, на который подключились |

### 3.2 Что система получает для baseline

После 14 дней накопления данных по каждой сущности `container.entity_id` доступно:

- **Process whitelist**: множество `{process.executable, process.command_line_pattern, user.id}`, которые наблюдались в контейнере
- **Network whitelist**: множество `{destination.ip, destination.port, network.transport}` исходящих соединений
- **Port profile**: множество портов, на которых контейнер слушает
- **File access profile**: пути файлов, с которыми взаимодействует контейнер
- **UID profile**: множество `user.id`, под которыми выполняются процессы контейнера
- **Lifecycle profile**: типичная частота рестартов, стабильность `container.image`

Всё это строится стандартными агрегациями OpenSearch по полю `container.entity_id` за скользящее окно.

### 3.3 Готовые аномальные скоры из OpenSearch AD

Для каждой сущности `container.entity_id` OpenSearch Anomaly Detection возвращает:

```json
{
  "entity": "vm-prod-01:nginx-proxy",
  "detectors": {
    "process_burst":     { "score": 0.12, "timestamp": "..." },
    "socket_burst":      { "score": 0.87, "timestamp": "..." },
    "new_port":          { "score": 0.00, "timestamp": "..." },
    "execve_rate_host":  { "score": 0.23, "timestamp": "..." },
    "ssh_failures_host": { "score": 0.05, "timestamp": "..." }
  }
}
```

Данные доступны через OpenSearch REST API: `GET /_plugins/_anomaly_detection/detectors/<id>/results`.

### 3.4 Rule-based сигналы (детерминированные, без ML)

Дополнительно через OpenSearch Alerting формируются бинарные сигналы:

| Сигнал | Источник | Вес для скоринга |
|--------|----------|-----------------|
| Новый `process.executable` вне whitelist | `fluent-osquery-*` | высокий |
| Shell (`sh`, `bash`, `python`) внутри prod-контейнера | `fluent-audit-*` | критичный |
| `user.id = 0` у процесса где исторически uid > 0 | `fluent-osquery-*` | критичный |
| Новый `destination.ip` вне network whitelist | `fluent-osquery-*` | высокий |
| Запись в `/etc/`, `/usr/bin/`, `/tmp/*.sh` | `fluent-audit-*` | высокий |
| Новый `container.image` (смена образа) | `fluent-osquery-*` | средний |
| Контейнер рестартовал > N раз за час | `fluent-osquery-*` | средний |
| `process.parent.entity_id` нехарактерный | `fluent-audit-*` | высокий |

Каждый сигнал — отдельный документ в индексе `ueba-signals-YYYY.MM.dd` (будет создан при настройке Alerting).

### 3.5 Ограничения и известные gaps

| Ограничение | Причина | Обходной путь |
|-------------|---------|---------------|
| auditd события не имеют `container.entity_id` | auditd работает на уровне host namespace | join по `process.entity_id` с osquery BPF событиями |
| osquery BPF только на ядрах ≥ 5.10 с BTF | Требование eBPF CO-RE | На старых ядрах — только polling-таблицы (30 сек gap) |
| Нет DNS-запросов контейнеров | DNS не собирается текущим стеком | Требует отдельного источника |
| Нет container-to-container трафика (overlay network) | osquery видит только host-level TCP | Требует network plugin или eBPF network probe |
| `process.parent.entity_id` может отсутствовать | Холодный старт fluent-bit (кэш пустой) | `labels.entity_id_source = event_timestamp_fallback` сигнализирует об этом |

---

## Порядок реализации

```
Неделя 1
  ├── P2-01: osquery BPF backend (промпт готов)
  ├── docker_containers query в osquery.conf
  └── osquery_enrich.lua: BPF маппинг + container.entity_id

Неделя 2
  ├── OpenSearch: обновить template fluent-osquery-*
  └── [Начало накопления данных — 14 дней]

Неделя 3–4
  └── Накопление baseline

Неделя 5
  ├── Настроить 5 RCF Anomaly Detectors
  ├── Настроить Alerting (rule-based сигналы)
  └── Создать индекс ueba-signals-*

Неделя 6
  └── Передать доступ к OpenSearch API надпроекту
      + документация по индексам и API endpoints
```

**Итого:** ~6 недель до готовности данных для скоринговой системы.  
Новых агентов не вводится, стек не меняется.

---

## Зависимости

| Зависимость | Статус |
|-------------|--------|
| osquery ≥ 4.6 на docker-хостах | уточнить |
| Ядро ≥ 5.10 + BTF на docker-хостах | уточнить |
| P0-01 (`process.entity_id`) | выполнено 2026-05-18 |
| P2-01 промпт | готов |
| Доступ к OpenSearch Anomaly Detection plugin | проверить версию |

---

*Документ подготовлен командой UEBA-stand. Вопросы: см. [README_FOR_AI.md](README_FOR_AI.md) — источник истины по схеме данных.*
