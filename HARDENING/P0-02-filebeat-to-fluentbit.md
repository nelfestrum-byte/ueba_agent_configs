# P0-02. Замена filebeat на fluent-bit SSH-pipeline

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — главный навигатор по проекту.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме. **Раздел 5** ("Источник: filebeat — SSH auth") нужно будет полностью переписать после этой задачи.
- [HARDENING_PLAN.md, раздел P0-02](HARDENING_PLAN.md) — полные детали, решения и грабли.

## Цель итерации

Заменить filebeat-агента на fluent-bit pipeline, читающий `/var/log/auth.log` и пишущий ECS-документы в новый индекс `system-auth-YYYY.MM.dd`. Filebeat удалить полностью с целевых хостов.

**Value сразу:**

- Стек агентов становится pure fluent-bit (auditd + osquery остаются как есть; единый ECS-enrich стиль через Lua).
- Уходит зависимость от apt-репозитория Elastic — не нужно держать .deb filebeat в fetch-packages.
- Единая точка мониторинга health для всех источников (метрики fluent-bit на 2020/tcp).

Это **независимый** value-add: даже если P0-01/P0-03 не сделаны, миграция приносит ценность сразу — мы становимся менее зависимыми от внешних репозиториев.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Стратегия отката (rollback safety):** делать ли overlap-период (filebeat и fluent-bit ssh-pipeline работают параллельно несколько часов на одном хосте, потом filebeat сносится) или сразу clean cut?
   - Recommended: **clean cut на test-хосте**, потом по флоту через 24 часа наблюдения.
2. **Что делать со старым индексом `filebeat-*`?**
   - Оставить как есть (read-only с момента миграции), retention сам уничтожит.
   - Сразу удалить через `DELETE /filebeat-*`.
3. **На каком тестовом хосте проверять перед раскаткой по всему inventory?** Названия из [agents/deploy/inventory.ini](../agents/deploy/inventory.ini).

## Pre-flight проверки

1. Проверить дистрибутив целевых хостов:

   ```bash
   ansible -i agents/deploy/inventory.ini all -m setup -a "filter=ansible_distribution*"
   ```

   Если есть Ubuntu 22.04+ или Debian 12+ — проверить наличие `/var/log/auth.log` (на некоторых системах он может быть отключён в пользу journald):

   ```bash
   ansible all -m stat -a "path=/var/log/auth.log"
   ```

   Если auth.log отсутствует на каком-то хосте — отметить, нужен `[INPUT] systemd` вместо `tail` (см. грабли в плане).

2. Подтвердить: fluent-bit user уже в группе `adm` (для чтения audit.log). Если да — auth.log тоже будет читаться (та же группа).

3. Прочитать текущие:
   - [agents/configs/filebeat/filebeat.yml.j2](../agents/configs/filebeat/filebeat.yml.j2) — что именно собирает filebeat сейчас, чтобы убедиться, что мы покрываем тот же scope.
   - [agents/configs/fluent-bit/fluent-bit.conf](../agents/configs/fluent-bit/fluent-bit.conf) — стиль существующих INPUT/FILTER/OUTPUT блоков.
   - [agents/configs/fluent-bit/parsers.conf](../agents/configs/fluent-bit/parsers.conf) — стиль парсеров.
   - [logstash/configs/pipeline/ueba-main.conf](../logstash/configs/pipeline/ueba-main.conf) — куда вставлять новый input.
   - [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml) — какие task'и убрать/добавить.

4. Снимок объёма events в filebeat-* за последние 24ч (чтобы потом сравнить с system-auth-*):

   ```bash
   curl -s 'http://localhost:9200/_cat/indices/filebeat-*?v&h=index,docs.count' | tail -5
   ```

## Реализация

### Шаг 1. Создать `agents/configs/fluent-bit/scripts/sshd_enrich.lua`

Lua-скрипт по аналогии с [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua), но проще — парсит уже распарсенный fluent-bit'ом message и достаёт user/IP/action.

Минимальный набор форматов sshd (расширять по факту реальных логов):

| Pattern | event.action | event.outcome | event.type |
| --- | --- | --- | --- |
| `Failed password for invalid user (\S+) from (\S+) port (\d+)` | `ssh_login_failed` | `failure` | `start` |
| `Failed password for (\S+) from (\S+) port (\d+)` | `ssh_login_failed` | `failure` | `start` |
| `Accepted password for (\S+) from (\S+) port (\d+)` | `ssh_login` | `success` | `start` |
| `Accepted publickey for (\S+) from (\S+) port (\d+).*` | `ssh_login` | `success` | `start` |
| `session opened for user (\S+) by .*uid=(\d+)` | `session_opened` | `success` | `start` |
| `session closed for user (\S+)` | `session_closed` | `success` | `end` |
| `Invalid user (\S+) from (\S+) port (\d+)` | `invalid_user` | `failure` | `start` |
| `Disconnected from authenticating user (\S+) (\S+) port (\d+) \[preauth\]` | `ssh_disconnect_preauth` | `failure` | `end` |
| `Connection closed by (?:authenticating user (\S+) )?(\S+) port (\d+)` | `ssh_connection_closed` | (нет outcome) | `end` |
| `PAM \d+ more authentication failures` | `pam_auth_failure` | `failure` | `info` |

ECS-маппинг для каждого события:

```lua
record["ecs.version"]   = "8.11"
record["event.dataset"] = "system.auth"
record["event.module"]  = "system"
record["event.kind"]    = "event"
record["event.category"] = "authentication"
record["event.outcome"] = outcome    -- см. таблицу
record["event.action"]  = action
record["event.type"]    = etype
record["user.name"]     = user
record["source.ip"]     = src_ip
record["source.port"]   = tonumber(src_port)
record["process.name"]  = "sshd"
record["host.name"]     = get_hostname()  -- по аналогии с auditd_enrich
record["host.os.type"]  = "linux"
record["host.os.family"]= "linux"
record["related.user"]  = { user }
record["related.ip"]    = { src_ip }
record["tags"]          = { "system-auth", "fluent-bit", "linux" }
```

Строки, не подходящие ни под один pattern (например, su/CRON/sudo через auth.log) — НЕ дропать, а оставить с `event.action="other"` и `event.category="authentication"`. Можно фильтрануть на стороне Logstash или в дальнейших итерациях.

### Шаг 2. Парсер в `parsers.conf`

Добавить парсер для syslog-формата auth.log:

```ini
[PARSER]
    Name        syslog_sshd
    Format      regex
    Regex       ^(?<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?<hostname>\S+) (?<program>[^\[\s:]+)(?:\[(?<pid>\d+)\])?: (?<message>.*)$
    Time_Key    timestamp
    Time_Format %b %e %H:%M:%S
    Time_Keep   On
```

Примечание: `%b %e %H:%M:%S` без года — fluent-bit подставит текущий год; вокруг 31 декабря возможна неоднозначность (см. грабли в плане, приемлемо).

### Шаг 3. Конфиг fluent-bit

Добавить в [fluent-bit.conf](../agents/configs/fluent-bit/fluent-bit.conf) (рядом с существующими INPUT для audit.log и osquery):

```ini
[INPUT]
    Name              tail
    Path              /var/log/auth.log
    Tag               system.auth
    Parser            syslog_sshd
    DB                /var/lib/fluent-bit/sshd.db
    Mem_Buf_Limit     5MB
    Refresh_Interval  5
    Skip_Long_Lines   On

[FILTER]
    Name              lua
    Match             system.auth
    script            /etc/fluent-bit/scripts/sshd_enrich.lua
    call              enrich_sshd

[OUTPUT]
    Name              tcp
    Match             system.auth
    Host              ${LOGSTASH_HOST}
    Port              5048
    Format            json_lines
    json_date_format  iso8601
    json_date_key     @timestamp
```

### Шаг 4. Logstash pipeline

В [ueba-main.conf](../logstash/configs/pipeline/ueba-main.conf):

1. **Добавить новый input** (рядом с существующими 5045/5047):

   ```text
   input {
     tcp {
       port  => 5048
       codec => json_lines
       tags  => ["system-auth", "fluent-bit"]
     }
   }
   ```

2. **Добавить output-ветку** маршрутизации по тегу:

   ```text
   if "system-auth" in [tags] {
     opensearch {
       hosts => ["${OPENSEARCH_URL}"]
       user  => "${OPENSEARCH_USER}"
       password => "${OPENSEARCH_PASSWORD}"
       ssl_certificate_verification => true
       cacert => "/usr/share/logstash/config/opensearch-ca.pem"
       index => "system-auth-%{+YYYY.MM.dd}"
       action => "create"
     }
   }
   ```

   Если в файле есть единый `output { opensearch { index => "..." } }` со conditional'ом — добавить ветку туда; смотри текущий стиль.

### Шаг 5. Ansible playbook

В [agents-deploy.yml](../agents/deploy/agents-deploy.yml):

1. **Удалить** task'и установки и конфигурации filebeat:
   - копирование `filebeat.yml.j2`
   - `apt install filebeat`
   - `systemctl enable/start filebeat`

2. **Добавить purge-секцию** (с тегом `migration_p0_02` чтобы можно было откатить):

   ```yaml
   - name: Stop filebeat service if running
     ansible.builtin.systemd:
       name: filebeat
       state: stopped
       enabled: no
     failed_when: false
     tags: [migration_p0_02]

   - name: Purge filebeat package
     ansible.builtin.apt:
       name: filebeat
       state: absent
       purge: yes
     tags: [migration_p0_02]

   - name: Remove filebeat residual directories
     ansible.builtin.file:
       path: "{{ item }}"
       state: absent
     loop:
       - /etc/filebeat
       - /var/lib/filebeat
       - /var/log/filebeat
     tags: [migration_p0_02]
   ```

3. **Добавить** копирование `sshd_enrich.lua` рядом с другими Lua-скриптами в task'е fluent-bit (если используется loop по scripts — добавить в список).

4. **Убедиться**, что в fluent-bit task'е есть `creates /var/lib/fluent-bit` для DB-файла sshd.db (либо обычный directory-task).

### Шаг 6. Удалить из репо

```bash
git rm -r agents/configs/filebeat/
```

В [fetch-packages/fetch.ps1](../agents/deploy/fetch-packages/fetch.ps1) убрать строку, скачивающую `filebeat_*.deb`.

### Шаг 7. Раскатка

1. Сначала на test-хосте (`ansible-playbook -i inventory.ini agents-deploy.yml --limit=test-host`).
2. Smoke: `ssh user@test-host` (правильный пароль и неправильный), потом проверить в OpenSearch:

   ```bash
   curl -s 'http://localhost:9200/system-auth-*/_search?size=5&sort=@timestamp:desc' | jq '.hits.hits[]._source | {action: .["event.action"], outcome: .["event.outcome"], user: .["user.name"], src: .["source.ip"]}'
   ```

   Должны быть и success, и failure события с заполненными полями.

3. После 1-2 часов наблюдения — раскатать на остальные хосты.

## Что НЕ делать в этой итерации

- **НЕ удалять Logstash beats input на 5044.** Это закладка под Windows winlogbeat в будущем (упомянуто в плане).
- **НЕ создавать index template** для `system-auth-*` — это P1-02. Сейчас индекс создаётся с dynamic mapping, это приемлемо до P1-02.
- **НЕ добавлять TLS на порт 5048** — это P1-03.
- **НЕ парсить все возможные строки auth.log** (su, sudo через PAM, CRON). Покрыть только sshd-форматы из таблицы; всё остальное падает в "other" с event.category=authentication.
- **НЕ настраивать `[INPUT] systemd`** "на всякий случай". Если на каком-то хосте нет auth.log — это отдельная подзадача, обработать через `when:` в Ansible (skip на этом хосте).
- **НЕ мигрировать существующие данные** из `filebeat-*` в `system-auth-*`. Старые остаются как историчесекие; новые приходят в новый индекс.

## Проверка готовности

Из [HARDENING_PLAN.md P0-02 → Критерий готовности](HARDENING_PLAN.md):

- На test-хосте `dpkg -l | grep filebeat` пусто; `systemctl status filebeat` → unit not found.
- `curl http://127.0.0.1:2020/api/v1/metrics | jq '.input."tail.X"'` (для auth.log) показывает ненулевой счётчик records.
- В OpenSearch `system-auth-*` появляются документы с заполненными `event.action`, `event.outcome`, `user.name`, `source.ip`, `source.port`.
- Logstash beats 5044 — нет входящего трафика от агентских хостов (`ss -an | grep 5044` на logstash-хосте пусто либо только listening).
- Индекс `filebeat-*` перестал расти.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - **Раздел 2** (Архитектура пайплайна): обновить таблицу — заменить строку filebeat на fluent-bit system-auth pipeline на TCP 5048 → `system-auth-*`.
   - **Раздел 5** ("Источник: filebeat — SSH auth (временный компонент)"): **переписать полностью** под новый pipeline. Описать форматы строк, какие event.action возникают, гарантированные ECS-поля. Убрать пометку "временный".

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В стеке агентов: убрать строку filebeat; в строку fluent-bit добавить третий pipeline (auth.log → 5048 → `system-auth-*`).
   - В таблице индексов OpenSearch: заменить `filebeat-{version}-*` на `system-auth-*`.
   - В "Ключевые файлы по темам": убрать строку про `filebeat.yml.j2`, добавить про `sshd_enrich.lua`.

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P0-02 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить** одним коммитом:

   ```
   P0-02: replace filebeat with fluent-bit SSH auth pipeline

   - New sshd_enrich.lua maps auth.log to ECS system.auth dataset
   - syslog_sshd parser in parsers.conf
   - fluent-bit.conf: tail /var/log/auth.log → TCP 5048
   - logstash ueba-main.conf: new tcp input → system-auth-* index
   - agents-deploy.yml: purge filebeat package, remove residuals
   - Removed agents/configs/filebeat/, removed filebeat from fetch.ps1
   - README_FOR_AI: rewrote section 5 under new pipeline
   - CLAUDE.md: agent stack/index table updated
   ```

5. **Сообщить пользователю**: миграция выполнена, filebeat снесён, новый индекс работает. Предложить следующий шаг: P0-03 или P1-01.
