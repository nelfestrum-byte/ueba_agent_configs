# P2-02. Расширение osquery-запросов

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор.
- [README_FOR_AI.md](../README_FOR_AI.md), раздел 4 — текущая схема osquery (что уже собирается, что мапится в ECS). Эта задача добавит **10 новых scheduled-запросов** — все они должны быть задокументированы в README_FOR_AI после внедрения.
- [HARDENING_PLAN.md, раздел P2-02](HARDENING_PLAN.md) — таблица запросов с интервалами, профилями, целями, граблями.
- [agents/configs/osquery/osquery.conf](../agents/configs/osquery/osquery.conf) — стиль текущих scheduled-запросов. Если P2-01 сделан — это уже `osquery.conf.j2` template.

## Цель итерации

Добавить 10 высокосигнальных osquery-запросов: `shell_history`, `last`, `process_envs`, `chrome_extensions`, `firefox_addons`, `python_packages`, `npm_packages`, `pip_packages`, `process_memory_map`, `kernel_keys`, `deb_packages`, `acpi_tables`, `sudoers`. Разделение per-profile: некоторые — только на workstations, остальные — на всём флоте.

**Value сразу:**

- **Supply-chain видимость** (python/npm/pip packages diff) — закрывает класс атак через зависимости.
- **Preload injection детект** (process_envs с фильтром по `LD_PRELOAD` и пр.).
- **Sequence-аномалии** в command-line (shell_history) — основа для UEBA-скоринга по командам.
- **Login forensics** (last) — кросс-сверка с auditd USER_LOGIN.
- **Persistence детект** (sudoers diff).

**Независимая ценность:** каждый запрос даёт своё наблюдение для UEBA, ничего из остального плана для этого не нужно.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Профиль каждого хоста:** есть ли у пользователя уже разделение workstations vs servers в inventory, или вводить новую группу `[workstations]`?
   - От ответа зависит структура group_vars и условий в .j2.
2. **`shell_history` — приватность.**
   - Запрос читает `~/.bash_history` и `~/.zsh_history` ВСЕХ пользователей — это потенциально секреты в command-line (пароли передавались через `--password=`).
   - Допустимо ли это в политике безопасности проекта? Или нужно сразу фильтровать и маскировать?
3. **Готовность к +5-10% объёма событий** от osquery в индексе `fluent-osquery-*` — приемлемо, или нужно сначала проверить retention/диск?
4. **P2-01 уже сделан?** Если ДА — будем расширять существующий `.j2` template с `osquery_profile`-условиями. Если НЕТ — нужно templatize конфиг в рамках этой задачи (или вернуться позже).

## Pre-flight проверки

1. **Прочитать целиком** [agents/configs/osquery/osquery.conf](../agents/configs/osquery/osquery.conf) (или `.j2` если P2-01 сделан). Выписать все существующие `schedule` блоки и их интервалы — мы будем добавлять, ничего не удалять.

2. **Прочитать целиком** [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua). Найти блок выбора по `record["name"]` — туда вставлять новые ветки маппинга.

3. **Прочитать** [tests/osquery/osquery-trigger.yml](../tests/osquery/osquery-trigger.yml) — стиль триггеров. Расширим этот плейбук, не создаём новый.

4. **Замер baseline** объёма `fluent-osquery-*` за 24ч ДО внедрения:

   ```bash
   curl -s "$OS/_cat/indices/fluent-osquery-*?v&h=index,docs.count,store.size" | tail -3
   ```

5. **Проверка наличия таблиц на dev-стенде:**

   ```bash
   osqueryi --json "SELECT name FROM osquery_registry WHERE registry='table' AND name IN ('shell_history','last','process_envs','chrome_extensions','firefox_addons','python_packages','npm_packages','pip_packages','process_memory_map','kernel_keys','deb_packages','acpi_tables','sudoers')"
   ```

   Все должны быть available. Если что-то отсутствует — версия osquery старая (см. P2-01 pre-flight).

## Реализация

### Шаг 1. Профильная переменная

В [agents/deploy/group_vars/all.yml](../agents/deploy/group_vars/all.yml):

```yaml
# Профиль хоста — управляет тем, какие osquery-запросы включены.
# Значения: "server" (default), "workstation".
# Переопределяется через group_vars/workstations.yml или per-host.
osquery_profile: server
```

Создать `agents/deploy/group_vars/workstations.yml`:

```yaml
osquery_profile: workstation
```

В inventory.ini в комментариях показать пример секции `[workstations]`.

### Шаг 2. Расширить osquery.conf.j2

В `agents/configs/osquery/osquery.conf.j2` (если ещё не template — переименовать сейчас и обновить Ansible task на `template:` с `validate:` JSON-проверкой, см. P2-01 шаги 1 и 4) добавить в конец `schedule:` (перед закрывающей `}`):

```jinja
  ,
  "shell_history": {
    "query": "SELECT * FROM shell_history;",
    "interval": 300,
    "removed": false,
    "description": "User command history (bash/zsh)"
  },
  "last_logins": {
    "query": "SELECT username, tty, host AS source_host, time, type FROM last WHERE type IN (7,8);",
    "interval": 300,
    "removed": false,
    "description": "User login/logout sessions from utmp/wtmp"
  },
  "preload_envs": {
    "query": "SELECT pe.pid, pe.key, pe.value, p.name AS process_name, p.path AS process_path, p.cmdline FROM process_envs pe JOIN processes p ON p.pid = pe.pid WHERE pe.key IN ('LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH') AND pe.value != '';",
    "interval": 60,
    "removed": false,
    "description": "Processes with LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH set"
  },
  "python_packages_diff": {
    "query": "SELECT name, version, path FROM python_packages;",
    "interval": 7200,
    "removed": false,
    "description": "Installed Python packages (supply-chain)"
  },
  "npm_packages_diff": {
    "query": "SELECT name, version, path FROM npm_packages;",
    "interval": 7200,
    "removed": false,
    "description": "Installed npm packages (supply-chain)"
  },
  "pip_packages_diff": {
    "query": "SELECT name, version, path FROM pip_packages;",
    "interval": 7200,
    "removed": false,
    "description": "Installed pip packages (supply-chain)"
  },
  "kernel_keys_diff": {
    "query": "SELECT * FROM kernel_keys;",
    "interval": 600,
    "removed": false,
    "description": "Kernel keyring entries (kerberos/keychain credentials)"
  },
  "deb_packages_diff": {
    "query": "SELECT name, version, arch FROM deb_packages;",
    "interval": 3600,
    "removed": false,
    "description": "Installed deb packages diff"
  },
  "acpi_tables_diff": {
    "query": "SELECT * FROM acpi_tables;",
    "interval": 86400,
    "removed": false,
    "description": "ACPI firmware tables (low-freq tamper detection)"
  },
  "sudoers_diff": {
    "query": "SELECT * FROM sudoers;",
    "interval": 1800,
    "removed": false,
    "description": "Sudoers rules diff"
  },
  "suspicious_mmap": {
    "query": "SELECT pmm.pid, pmm.path, pmm.start, pmm.end, p.name AS process_name FROM process_memory_map pmm JOIN processes p ON p.pid = pmm.pid WHERE pmm.path != '' AND pmm.path NOT LIKE '/usr/%' AND pmm.path NOT LIKE '/lib/%' AND pmm.path NOT LIKE '/lib64/%' AND pmm.path NOT LIKE '[%';",
    "interval": 300,
    "removed": false,
    "description": "Non-standard shared objects mmap'd by processes"
  }{% if osquery_profile == 'workstation' %},
  "chrome_extensions_diff": {
    "query": "SELECT uid, name, version, identifier, path FROM users CROSS JOIN chrome_extensions USING (uid);",
    "interval": 3600,
    "removed": false,
    "description": "Chrome extensions per user (workstation only)"
  },
  "firefox_addons_diff": {
    "query": "SELECT uid, name, version, identifier, path FROM users CROSS JOIN firefox_addons USING (uid);",
    "interval": 3600,
    "removed": false,
    "description": "Firefox addons per user (workstation only)"
  }{% endif %}
```

**ВНИМАНИЕ:** JSON и запятые. Ведущая `,` зависит от того, что стоит перед нашим блоком (если P2-01 уже вставил bpf-секции — наш блок идёт после них, тоже с запятой). Обязательно прогнать через `python3 -m json.tool` после Jinja-рендера.

### Шаг 3. Расширить osquery_enrich.lua

В [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) добавить ветки маппинга. Для каждого запроса:

```lua
elseif name == "shell_history" then
    record["event.category"] = "process"
    record["event.dataset"]  = "osquery.shell_history"
    record["event.action"]   = "shell_command"
    record["event.type"]     = "info"
    if cols["username"] then record["user.name"] = cols["username"] end
    if cols["command"]  then
        -- Маскирование секретов в command-line
        local cmd = cols["command"]
        cmd = cmd:gsub("(%-%-password=)%S+", "%1<redacted>")
        cmd = cmd:gsub("(%-%-token=)%S+",    "%1<redacted>")
        cmd = cmd:gsub("(%-%-api-key=)%S+",  "%1<redacted>")
        record["process.command_line"] = cmd
    end
    if cols["history_file"] then record["file.path"] = cols["history_file"] end

elseif name == "last_logins" then
    record["event.category"] = "authentication"
    record["event.dataset"]  = "osquery.last"
    record["event.action"]   = (cols["type"] == "7") and "user_login" or "user_logout"
    record["event.type"]     = (cols["type"] == "7") and "start" or "end"
    if cols["username"]    then record["user.name"] = cols["username"] end
    if cols["source_host"] then record["source.ip"] = cols["source_host"] end
    if cols["tty"]         then record["user.terminal"] = cols["tty"] end

elseif name == "preload_envs" then
    record["event.category"] = "process"
    record["event.dataset"]  = "osquery.process_envs"
    record["event.action"]   = "preload_env_set"
    record["event.type"]     = "info"
    if cols["pid"]          then record["process.pid"]      = tonumber(cols["pid"]) end
    if cols["process_name"] then record["process.name"]     = cols["process_name"] end
    if cols["process_path"] then record["process.executable"] = cols["process_path"] end
    if cols["cmdline"]      then record["process.command_line"] = cols["cmdline"] end
    if cols["key"]          then record["process.env.key"]   = cols["key"] end
    if cols["value"]        then record["process.env.value"] = cols["value"] end

elseif name == "python_packages_diff" or
       name == "npm_packages_diff"    or
       name == "pip_packages_diff" then
    record["event.category"] = "package"
    record["event.dataset"]  = "osquery." .. (
        name == "python_packages_diff" and "python_packages" or
        name == "npm_packages_diff"    and "npm_packages"    or
        "pip_packages")
    record["event.action"]   = (action == "added") and "package_installed"
                                                   or "package_removed"
    record["event.type"]     = (action == "added") and "installation" or "deletion"
    if cols["name"]    then record["package.name"]    = cols["name"] end
    if cols["version"] then record["package.version"] = cols["version"] end
    if cols["path"]    then record["package.path"]    = cols["path"] end

elseif name == "deb_packages_diff" then
    record["event.category"] = "package"
    record["event.dataset"]  = "osquery.deb_packages"
    record["event.action"]   = (action == "added") and "package_installed" or "package_removed"
    record["event.type"]     = (action == "added") and "installation" or "deletion"
    if cols["name"]    then record["package.name"]    = cols["name"] end
    if cols["version"] then record["package.version"] = cols["version"] end
    if cols["arch"]    then record["package.architecture"] = cols["arch"] end

elseif name == "kernel_keys_diff" then
    record["event.category"] = "iam"
    record["event.dataset"]  = "osquery.kernel_keys"
    record["event.action"]   = (action == "added") and "kernel_key_added" or "kernel_key_removed"
    record["event.type"]     = (action == "added") and "creation" or "deletion"
    -- columns: serial, type, description, uid, gid

elseif name == "sudoers_diff" then
    record["event.category"] = "iam"
    record["event.dataset"]  = "osquery.sudoers"
    record["event.action"]   = "sudoers_modified"
    record["event.type"]     = "change"

elseif name == "acpi_tables_diff" then
    record["event.category"] = "host"
    record["event.dataset"]  = "osquery.acpi_tables"
    record["event.action"]   = (action == "added") and "acpi_table_added" or "acpi_table_removed"
    record["event.type"]     = "change"

elseif name == "suspicious_mmap" then
    record["event.category"] = "process"
    record["event.dataset"]  = "osquery.process_memory_map"
    record["event.action"]   = "non_standard_mmap"
    record["event.type"]     = "info"
    if cols["pid"]          then record["process.pid"]    = tonumber(cols["pid"]) end
    if cols["process_name"] then record["process.name"]   = cols["process_name"] end
    if cols["path"]         then record["file.path"]      = cols["path"] end

elseif name == "chrome_extensions_diff" then
    record["event.category"] = "configuration"
    record["event.dataset"]  = "osquery.chrome_extensions"
    record["event.action"]   = (action == "added") and "extension_installed" or "extension_removed"
    record["event.type"]     = (action == "added") and "installation" or "deletion"
    if cols["name"]       then record["package.name"]      = cols["name"] end
    if cols["version"]    then record["package.version"]   = cols["version"] end
    if cols["identifier"] then record["package.identifier"] = cols["identifier"] end
    if cols["uid"]        then record["user.id"]            = cols["uid"] end

elseif name == "firefox_addons_diff" then
    record["event.category"] = "configuration"
    record["event.dataset"]  = "osquery.firefox_addons"
    record["event.action"]   = (action == "added") and "addon_installed" or "addon_removed"
    record["event.type"]     = (action == "added") and "installation" or "deletion"
    if cols["name"]       then record["package.name"]      = cols["name"] end
    if cols["version"]    then record["package.version"]   = cols["version"] end
    if cols["identifier"] then record["package.identifier"] = cols["identifier"] end
    if cols["uid"]        then record["user.id"]            = cols["uid"] end
```

Сверь имена `cols[]` со схемой osquery-таблиц через `osqueryi "PRAGMA table_info(<table>)"` на dev-стенде — могут отличаться от того, что я тут написал.

### Шаг 4. Расширить тестовый плейбук

В [tests/osquery/osquery-trigger.yml](../tests/osquery/osquery-trigger.yml) добавить триггеры для новых запросов (по стилю существующих):

```yaml
- name: "[apply] Install test pip package (trigger: pip_packages_diff)"
  ansible.builtin.command: pip install --break-system-packages --user requests==2.25.0
  changed_when: false
  tags: [apply, key_pip_packages]

- name: "[apply] Run command with LD_PRELOAD (trigger: preload_envs)"
  ansible.builtin.shell: LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6 /bin/true || true
  args: { executable: /bin/bash }
  changed_when: false
  tags: [apply, key_preload_envs]

- name: "[apply] Add line to user bash_history (trigger: shell_history)"
  ansible.builtin.lineinfile:
    path: "/root/.bash_history"
    line: "echo aud-trig-marker"
    create: yes
  tags: [apply, key_shell_history]

# и аналогично для остальных…
```

В rollback — снести test pip package и убрать строку из bash_history.

### Шаг 5. Раскатка

```bash
cd agents/deploy

# Сначала на test-хосте (server profile)
ansible-playbook agents-deploy.yml --ask-become-pass --limit=test-server --tags=osquery

# Проверить, что только server-запросы пришли
curl -s "$OS/fluent-osquery-*/_search?size=20" \
  -d '{"query":{"range":{"@timestamp":{"gte":"now-5m"}}},"aggs":{"dataset":{"terms":{"field":"event.dataset","size":30}}}}' \
  | jq '.aggregations.dataset.buckets[] | {name: .key, count: .doc_count}'

# Должны быть все, кроме chrome_extensions/firefox_addons

# Затем на workstation
ansible-playbook agents-deploy.yml --ask-become-pass --limit=test-workstation --tags=osquery

# Триггер chrome_extensions: на workstation должен прийти при добавлении расширения
```

### Шаг 6. Замер дельты

Через 24 часа:

```bash
curl -s "$OS/_cat/indices/fluent-osquery-*?v&h=index,docs.count,store.size" | tail -3
```

Сравнить с baseline. Допустимая дельта: **+5..10%** в среднем. Если больше — посмотреть какой dataset доминирует:

```bash
curl -s "$OS/fluent-osquery-*/_search?size=0" \
  -d '{"aggs":{"d":{"terms":{"field":"event.dataset","size":30}}}}' \
  | jq '.aggregations.d.buckets'
```

Если, например, `python_packages` даёт 60% объёма — нужен фильтр (только diff, не первичный заполнитель). Проверить `removed: false` и интервалы.

## Что НЕ делать в этой итерации

- **НЕ удалять и не менять существующие** scheduled-запросы. Только добавление.
- **НЕ менять watchdog лимиты** osquery — наблюдаем за RSS osqueryd, корректировка лимита — отдельная подзадача, если упрёмся.
- **НЕ маскировать `shell_history` полностью** — только обозначенные параметры (`--password`, `--token`, `--api-key`). Полная маскировка хешированием сломает UEBA-семантику.
- **НЕ включать на проде сразу** — обкатка минимум 24 часа на test-host. После этого rollout группами через `--limit` Ansible.
- **НЕ затаскивать `process_envs` без фильтра** — без WHERE на конкретные ключи запрос даст десятки тысяч строк в час. Запрос в Шаге 2 уже с фильтром, не упрости его.
- **НЕ создавать новый индекс** для расширения — всё пишется в существующий `fluent-osquery-*` (отделение по `event.dataset`).

## Проверка готовности

Из [HARDENING_PLAN.md P2-02 → Критерий готовности](HARDENING_PLAN.md):

- На dev-хосте все новые запросы выполняются: `osqueryi --json "SELECT ..."` для каждого даёт результаты без ошибок.
- Триггеры в `osquery-trigger.yml` приводят к появлению документов в `fluent-osquery-*` с корректным `event.dataset` и ECS-полями.
- Watchdog osquery не превышает 350 MB RSS через 24 часа.
- На workstation-профиле: документы с `event.dataset=osquery.chrome_extensions` / `osquery.firefox_addons` появляются.
- На server-профиле: вышеперечисленные dataset'ы ОТСУТСТВУЮТ.
- Объём `fluent-osquery-*` после 24 часов вырос не более чем на +10% относительно baseline.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделе 4.3 ("Запросы osquery и их ECS-маппинг") добавить под-разделы для каждого нового запроса. Для каждого:
     - SQL (или хотя бы ключевые поля SELECT)
     - Интервал
     - **Профиль:** server / workstation / both
     - `event.action`, `event.category`, `event.type` маппинг
     - **UEBA-feature:** для чего используется в скоринге
   - В разделе 4.4 (Гарантированные ECS-поля) добавить `package.*` и `process.env.*` namespace'ы.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В "Известные особенности и грабли" добавить пункт:
     - "Профили osquery: `osquery_profile=server|workstation` в group_vars. Workstation получает дополнительно chrome_extensions / firefox_addons. Маскирование `--password=` / `--token=` в `shell_history` происходит на стороне Lua-enrich."

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P2-02 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить:**

   ```
   P2-02: extend osquery scheduled queries (supply-chain, preload, shell history)

   - 10 new scheduled queries: shell_history, last_logins, preload_envs,
     python/npm/pip/deb_packages_diff, kernel_keys, sudoers, acpi_tables,
     suspicious_mmap; workstation-only: chrome_extensions, firefox_addons
   - osquery_profile (server|workstation) variable + workstations.yml group_vars
   - osquery_enrich.lua: ECS mapping for all new datasets, package.* namespace
   - shell_history: redact --password/--token/--api-key values
   - osquery-trigger.yml: triggers for new queries
   - Verified delta volume <+10% on test-host after 24h
   - README_FOR_AI: extended section 4.3 with per-query docs
   - CLAUDE.md: profile matrix + shell_history privacy note
   ```

5. **Сообщить пользователю**: 10 запросов активны, дельта объёма по факту, что попало в shell_history примеры (если есть подозрительные паттерны — флагнуть). Спросить, нужно ли немедленно убирать какие-то из запросов из-за шума.
