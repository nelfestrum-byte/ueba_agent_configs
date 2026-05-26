# QA-FIX-11. osquery_enrich: детектор truncation argv в bpf_process_events

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, раздел «osquery BPF backend — матрица групп», граблины про container_cache.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник ECS, разделы про `process.command_line` и `labels.*`.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — главный файл правки.

Дополнительно — внешний контекст:

- osquery issue [#7497](https://github.com/osquery/osquery/issues/7497) — argv truncation в BPF backend.
- osquery 5.23.0 BPF probe sched_process_exec: argv копируется через `bpf_probe_read_user_str()` в фиксированный buffer, при коротких процессах и переключении контекста копирование прерывается после argv[0].

## Цель итерации

Закрыть **проблему пользователя из QA-01 v4** и связанный с ней риск UEBA-скоринга:

| # | Проблема | Симптом |
|---|----------|---------|
| 1 | Для процесса `cat /etc/passwd` в nginx-контейнере osquery BPF записал `command_line="cat"` (только argv[0]) | Один из двух наблюдаемых execve fork'ов теряет argv (race condition в osquery BPF, неисправляемый на нашей стороне) |
| 2 | UEBA-скоринг получает фантомный сигнал «процесс запущен без аргументов», что неверно | Невозможно отличить truncated argv от реального запуска без аргументов |

**Гипотеза причины:** в [osquery_enrich.lua:613-637](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L613) блок `bpf_processes` напрямую присваивает `record["process.command_line"] = cols["cmdline"]`. Если osquery вернул только `"cat"`, в индекс попадает `"cat"` — без сигнала, что это потенциально неполные данные.

**Решение:** добавить детектор — если `cmdline` это **одиночный токен** (без пробелов) и совпадает с `basename(path)`, пометить документ флагом `labels.cmdline_truncated = "argv0_only"`. Downstream UEBA-коррелятор использует флаг как hint: «не повышать score за `cat` без аргументов, возможно argv был обрезан BPF».

Дополнительно (Phase 2, опционально в этой же итерации) — для всех `bpf_process_events` добавить `labels.cmdline_source = "osquery_bpf"` (vs. `auditd_execve`), чтобы UEBA знал источник.

**Value:** UEBA-скоринг отличает шум osquery BPF от реальных сигналов. Не теряем существующее поведение — `process.command_line` остаётся как есть, флаг только информационный.

**Что НЕ решает этот патч:** не восстанавливаем потерянный argv. Для этого нужна cross-stream корреляция с auditd execve (отдельный долгий fix QA-FIX-12 или downstream).

## Pre-flight

```bash
OS=http://192.168.37.161:9200

# Снимок ДО фикса: сколько bpf_process_events с cmdline == single token
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } }
  ]}},
  "aggs": {
    "by_cmdline": { "terms": { "field": "process.command_line", "size": 30 } },
    "total":      { "value_count": { "field": "process.pid" } }
  }
}'
# Записать: сколько cmdline без пробелов (визуально по top buckets).

# Конкретно: cat / sh / ls / cp / mv / curl без аргументов
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 5,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } },
    { "terms": { "process.command_line": ["cat","sh","ls","cp","mv","curl","sed","awk","grep","echo"] } }
  ]}},
  "_source": ["process.command_line","process.executable","host.name","container.name","@timestamp"]
}'
# Записать count. Эти кандидаты на truncation flag.

# Проверить, что labels.cmdline_truncated ещё нет в индексе (новое поле)
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "aggs": { "has_label": { "filter": { "exists": { "field": "labels.cmdline_truncated" } } } }
}'
# Ожидание ДО: has_label.doc_count = 0.
```

## Реализация

### Шаг 0. Подтвердить корневую причину

1. Прочитать целиком [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua), блок `bpf_processes` (~стр.613-654). Убедиться, что присваивание `record["process.command_line"] = cols["cmdline"]` действительно прямое, без существующих модификаций.
2. Прочитать [agents/configs/osquery/osquery.conf.j2](../agents/configs/osquery/osquery.conf.j2), запрос `bpf_processes` — какие колонки select'ятся (нужно `path` и `cmdline` точно). Если колонка `cmdline` уже отсутствует или переименована — сначала разобраться.

### Шаг 1. Truncation detector

В [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua), блок `bpf_processes`, заменить присваивание `process.command_line`:

```lua
-- ── BPF process events (P2-01, docker-хосты) ─────────────────────────
if query_name == "bpf_processes" then
    record["event.dataset"] = "osquery.bpf_process_events"
    if cols["pid"]       then record["process.pid"]          = tonumber(cols["pid"]) end
    if cols["parent"]    then record["process.parent.pid"]   = tonumber(cols["parent"]) end
    if cols["path"]      and cols["path"] ~= "" then
        record["process.executable"] = cols["path"]
    end

    -- process.command_line из osquery BPF tap.
    -- ВАЖНО: osquery BPF probe (sched_process_exec) подвержен race condition
    -- (см. github.com/osquery/osquery/issues/7497): при коротких процессах
    -- argv копируется только частично, остаётся argv[0].
    -- Детектируем truncation и помечаем флагом для downstream UEBA.
    if cols["cmdline"] and cols["cmdline"] ~= "" then
        record["process.command_line"] = cols["cmdline"]

        -- Truncation heuristic: cmdline без пробелов И совпадает с basename(path).
        -- Не false-positive для коротких argv типа "cat" — UEBA должен учитывать
        -- этот флаг как СИГНАЛ НЕОПРЕДЕЛЁННОСТИ, а не как уверенность в truncation.
        local exe = cols["path"] or ""
        local base = exe:match("([^/]+)$") or exe
        if not cols["cmdline"]:find(" ", 1, true) and cols["cmdline"] == base then
            record["labels.cmdline_truncated"] = "argv0_only"
        end
    end

    -- Источник cmdline для downstream корреляции с auditd execve.
    record["labels.cmdline_source"] = "osquery_bpf"

    if cols["uid"]       and cols["uid"] ~= "" then record["user.id"]        = cols["uid"] end
    -- ... остальной код блока без изменений ...
```

**Замечание про эвристику:**
- Прямой матч `cmdline == basename(path)` ловит классический случай (`cat` для `/bin/cat`).
- Не ловит случаи, когда argv[0] был переименован программой (`bash` запущен как `-bash` для login shell) — это false negative, приемлемо.
- Не ловит truncation, при котором argv[0]+часть argv[1] (`cat /etc/`) — теоретически возможен, но в практике osquery BPF либо argv[0], либо полностью (см. issue #7497).
- Не false-positive для legitimate single-arg запусков типа `pwd`, `date`, `hostname` — это OK, для UEBA одинокий `pwd` тоже не несёт информации.

### Шаг 2. Раскатка через ansible

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass --limit bpf_hosts
# или для всех:
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

Проверить, что fluent-bit перезапустился без ошибок:

```bash
ansible bpf_hosts -m shell -a "systemctl is-active fluent-bit; journalctl -u fluent-bit -n 30 --no-pager | grep -iE 'error|fatal|lua'" -i agents/deploy/inventory.ini
```

### Шаг 3. Опционально — обновить index template

Поле `labels.cmdline_truncated` / `labels.cmdline_source` попадёт под dynamic mapping как keyword — это OK. Явное добавление в [opensearch/templates/fluent-osquery.json](../opensearch/templates/fluent-osquery.json) не обязательно, но желательно для документации:

```json
"labels": {
  "properties": {
    "config_version":   { "type": "keyword" },
    "cmdline_truncated": { "type": "keyword" },
    "cmdline_source":    { "type": "keyword" }
  }
}
```

(если в template `labels` уже есть как блок).

## Post-flight (smoke-тест)

Сгенерировать truncation вручную:

```bash
# На bpf_hosts (любом) в любом контейнере
ssh agent01.uir.prj 'docker exec nginx-test sh -c "cat /etc/passwd"'
# Подождать 30 сек — osquery snapshot interval

# Проверить labels.cmdline_truncated в новых событиях
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 5,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } },
    { "exists": { "field": "labels.cmdline_truncated" } },
    { "range": { "@timestamp": { "gte": "now-5m" } } }
  ]}},
  "_source": ["process.command_line","process.executable","labels","container.name","@timestamp"]
}'
# Ожидание: видим хотя бы один документ с labels.cmdline_truncated=argv0_only.

# Распределение truncated vs normal
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } },
    { "range": { "@timestamp": { "gte": "now-15m" } } }
  ]}},
  "aggs": {
    "truncated":      { "filter": { "exists": { "field": "labels.cmdline_truncated" } } },
    "has_cmdline":    { "filter": { "exists": { "field": "process.command_line" } } },
    "has_source_lbl": { "filter": { "exists": { "field": "labels.cmdline_source" } } }
  }
}'
# Ожидание:
#  - truncated.doc_count > 0 (ловит часть событий)
#  - has_source_lbl.doc_count == total (все новые bpf_process_events помечены)
#  - truncated / total — small percentage (5-20%, не 100%)
```

## Что НЕ делать в этой итерации

- **НЕ менять источник `process.command_line`** — оставляем `cols["cmdline"]` как есть. Восстановление полного argv — отдельная задача (cross-stream join с auditd).
- **НЕ удалять документы с truncated cmdline** — флаг только информационный.
- **НЕ применять эвристику к osquery/processes (полная таблица)** — там cmdline всегда полная (из /proc/<pid>/cmdline на момент snapshot), эвристика даст false positives.
- **НЕ применять к bpf_socket_events** — там нет cmdline вообще.
- **НЕ обновлять osquery до новой версии** в этом патче — это отдельный risk plan.

## Критерии готовности

- В новых `osquery.bpf_process_events` документах появляется `labels.cmdline_source = "osquery_bpf"` в 100%.
- `labels.cmdline_truncated = "argv0_only"` появляется в части документов (там, где cmdline это одиночный токен = basename(path)).
- Существующее поле `process.command_line` остаётся как было — не изменено.
- fluent-bit healthy на bpf_hosts, нет Lua errors.
- Smoke-тест с ручным `docker exec ... cat /etc/passwd` показывает event БЕЗ truncation флага (argv захвачен полностью); event для случая, когда BPF потерял argv — С флагом.

## Финал

1. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В раздел «osquery BPF backend — матрица групп и whitelist для bpf-правила» добавить блок про argv truncation и `labels.cmdline_truncated` флаг. Указать: «UEBA-коррелятор должен учитывать этот флаг и не повышать score за `command_line` без аргументов, если флаг установлен».

2. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В раздел про `osquery.bpf_process_events` (если такого нет — создать) описать новые `labels.*` поля.

3. **Закоммитить:**

   ```
   QA-FIX-11: bpf_process_events argv truncation detector

   - osquery_enrich.lua bpf_processes block:
     - Heuristic: cmdline без пробелов И == basename(path)
       => labels.cmdline_truncated = "argv0_only".
     - All bpf_process_events now have labels.cmdline_source = "osquery_bpf"
       for downstream correlation with auditd execve.
   - opensearch/templates/fluent-osquery.json: explicit keyword mapping
     for labels.cmdline_truncated / labels.cmdline_source (optional).

   Addresses user QA-01 v4 finding: "cat /etc/passwd" in nginx container
   shows process.command_line='cat' due to osquery BPF race condition
   (osquery#7497). Flag enables UEBA to discount such events.
   ```

4. **Сообщить пользователю:** теперь видно в индексе документы с возможно неполным argv (`labels.cmdline_truncated=argv0_only`). Для полной картины — JOIN с `fluent-audit-*` execve по `host.name + process.pid + @timestamp±2s` (это уже downstream-задача в UEBA-корреляторе). Если нужно — следующая итерация QA-FIX-12 выровняет `process.entity_id` между osquery BPF и auditd, что упростит JOIN.
