# QA-04. fluent-osquery index template: integer-типы для osquery namespace + дополнения

## Контекст для AI

Перед началом работы прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, раздел про индексные шаблоны и их применение.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика, по которой найдены несоответствия типов.
- [opensearch/templates/fluent-osquery.json](../opensearch/templates/fluent-osquery.json) — текущий шаблон, который правим.
- [opensearch/templates/README.md](../opensearch/templates/README.md) — как применять шаблон.

## Цель итерации

Закрыть **WARN #13 из QA-01 отчёта** и сопутствующие маппинг-проблемы:

| # | Проблема | Текущий тип | Должно быть |
|---|----------|-------------|-------------|
| 1 | `osquery.pid`, `osquery.parent`, `osquery.tid` — попадают под dynamic template strings_as_keywords | `keyword` | `long` (PID может быть до 2^22; integer достаточно, но осquery передаёт строкой → берём long для безопасности) |
| 2 | `osquery.local_port`, `osquery.remote_port` | `keyword` | `integer` |
| 3 | `osquery.exit_code` (после нормализации в QA-03 будет integer) | `keyword` (sometimes число) | `long` (int64 negative для errno) |
| 4 | `osquery.unix_time` (в osquery.result) — уже long ✓ | `long` ✓ | (не трогать) |
| 5 | `osquery.start_time`, `osquery.ntime`, `osquery.duration` (BPF) | `keyword` | `long` |
| 6 | `osquery.cid` (BPF cgroup ns inode) | `keyword` | `long` |
| 7 | `osquery.uid`, `osquery.gid`, `osquery.euid`, `osquery.egid` | `keyword` | `keyword` ✓ (UID — традиционно keyword в ECS для строкового сравнения; **оставляем**) |
| 8 | `process.exit_code` | dynamic | `long` (явно прописать) |
| 9 | `container.image.tag` отсутствует в template (поле появляется в QA-03) | dynamic → keyword | `keyword` |
| 10 | `service.name` отсутствует (поле появляется в QA-02, но шаблон osquery — на всякий случай тоже) | — | (это поле для fluent-audit; здесь не нужно) |

**Value:** range-запросы по port/pid/duration работают корректно. Дашборды (Top processes by exit_code, port-scans по port-range) перестают спотыкаться о `keyword`-маппинг.

**Важно:** index template применяется только **к новым индексам**. Существующие `fluent-osquery-YYYY.MM.dd` останутся со старым маппингом до следующего ротейта (по дате — следующий день).

## Pre-flight

```bash
OS=http://192.168.37.161:9200

# 1. Текущая версия шаблона
curl -s "$OS/_index_template/fluent-osquery?pretty" | head -40

# 2. Что реально применилось к индексу сегодняшнему
curl -s "$OS/fluent-osquery-*/_mapping/field/osquery.pid,osquery.local_port,osquery.remote_port,osquery.cid,osquery.duration?pretty"
# Должны увидеть type=keyword для большинства из них.

# 3. Запросы, которые сейчас не работают как должны:
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"osquery.local_port":{"gte":1024,"lte":65535}}}}'
# Может вернуть 0 (range на keyword делает лексикографическое сравнение, что некорректно).

# 4. Проверить, есть ли osquery.cid в индексе
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"top_cid":{"terms":{"field":"osquery.cid","size":3}}}}'
```

## Реализация

### Шаг 1. Обновить [opensearch/templates/fluent-osquery.json](../opensearch/templates/fluent-osquery.json)

Расширить блок `mappings.properties.osquery` (сейчас в нём только `result`), добавив явные числовые поля. Также добавить `image.tag` в `container` и `exit_code` в `process`.

**Целевой фрагмент** (вместо текущего блока `"osquery": { "properties": { "result": { ... } } }`):

```json
        "osquery": {
          "properties": {
            "result": {
              "properties": {
                "name":            { "type": "keyword" },
                "action":          { "type": "keyword" },
                "host_identifier": { "type": "keyword" },
                "unix_time":       { "type": "long" },
                "version":         { "type": "keyword" }
              }
            },
            "pid":          { "type": "long" },
            "parent":       { "type": "long" },
            "tid":          { "type": "long" },
            "local_port":   { "type": "integer" },
            "remote_port":  { "type": "integer" },
            "exit_code":    { "type": "long" },
            "start_time":   { "type": "long" },
            "ntime":        { "type": "long" },
            "duration":     { "type": "long" },
            "cid":          { "type": "long" },
            "fd":           { "type": "long" },
            "uid":          { "type": "keyword" },
            "gid":          { "type": "keyword" },
            "euid":         { "type": "keyword" },
            "egid":         { "type": "keyword" },
            "family":       { "type": "keyword" },
            "protocol":     { "type": "keyword" },
            "syscall":      { "type": "keyword" },
            "type":         { "type": "keyword" },
            "name":         { "type": "keyword" },
            "path":         { "type": "wildcard" },
            "cmdline":      { "type": "wildcard" },
            "hostname":     { "type": "keyword" },
            "username":     { "type": "keyword" },
            "state":        { "type": "keyword" },
            "status":       { "type": "keyword" },
            "image":        { "type": "keyword" },
            "image_id":     { "type": "keyword" },
            "id":           { "type": "keyword" },
            "local_address":  { "type": "keyword" },
            "remote_address": { "type": "keyword" },
            "process_name":   { "type": "keyword" },
            "process_path":   { "type": "wildcard" },
            "permissions":    { "type": "keyword" },
            "serial_number":  { "type": "keyword" },
            "description":    { "type": "keyword" },
            "flags":          { "type": "keyword" },
            "timeout":        { "type": "keyword" },
            "usage":          { "type": "keyword" },
            "start":          { "type": "keyword" },
            "end":            { "type": "keyword" },
            "probe_error":    { "type": "keyword" }
          }
        },
```

Также в `container`:

```json
        "container": {
          "properties": {
            "id":        { "type": "keyword" },
            "name":      { "type": "keyword" },
            "runtime":   { "type": "keyword" },
            "entity_id": { "type": "keyword" },
            "image": {
              "properties": {
                "name": { "type": "keyword" },
                "tag":  { "type": "keyword" }
              }
            }
          }
        },
```

И в `process`:

```json
        "process": {
          "properties": {
            "pid":          { "type": "integer" },
            "name":         { "type": "keyword" },
            "executable":   { "type": "wildcard" },
            "command_line": { "type": "wildcard" },
            "entity_id":    { "type": "keyword" },
            "start":        { "type": "date" },
            "exit_code":    { "type": "long" },
            "args":         { "type": "keyword" },
            "args_count":   { "type": "integer" },
            "working_directory": { "type": "wildcard" },
            "parent": {
              "properties": {
                "pid":          { "type": "integer" },
                "entity_id":    { "type": "keyword" },
                "start":        { "type": "date" },
                "name":         { "type": "keyword" },
                "command_line": { "type": "wildcard" }
              }
            }
          }
        },
```

И в `_meta`:

```json
  "_meta": {
    "description": "UEBA osquery diff events — ECS 8.11 + osquery.* namespace",
    "source": "ueba-stand/opensearch/templates",
    "version": "2.1",
    "project_version": "0.9"
  },
```

(bumpнуть version до 2.1)

**Замечание:** `dynamic: true` оставляем — это safety net для новых osquery-полей, не названных явно. Они попадут под `strings_as_keywords` dynamic_template — это безопасно (keyword), но прицельные числовые поля выше превращаются в `long`/`integer`/`wildcard` нужно явно.

### Шаг 2. Аналогичная ревизия для [opensearch/templates/fluent-audit.json](../opensearch/templates/fluent-audit.json)

Прочитать текущий fluent-audit.json и добавить недостающие явные типы (по аналогии с уже обнаруженными в QA-01 — `service.name`, `auditd.session` как integer, `process.args_count`, и т.д.):

```bash
# Перед редактированием — прочитать что есть
cat opensearch/templates/fluent-audit.json | head -200
```

Минимально добавить:

```json
        "service": {
          "properties": {
            "name": { "type": "keyword" }
          }
        },
        "auditd": {
          "properties": {
            "session": { "type": "long" },
            "data": {
              "properties": {
                "syscall": { "type": "keyword" }
              }
            },
            "paths": { "type": "wildcard" }
          }
        },
```

И в `process` добавить `args_count` (integer), `args` (keyword), `working_directory` (wildcard), `title` (wildcard) если их нет.

### Шаг 3. Применить обновлённые шаблоны

```bash
# Для osquery
curl -s -X PUT "$OS/_index_template/fluent-osquery" \
  -H "Content-Type: application/json" \
  -d @opensearch/templates/fluent-osquery.json

# Для audit (если правил)
curl -s -X PUT "$OS/_index_template/fluent-audit" \
  -H "Content-Type: application/json" \
  -d @opensearch/templates/fluent-audit.json

# Проверить, что приняты
curl -s "$OS/_cat/templates?v&name=fluent-*"
# Ожидание: обе строки видны, priority 200
```

### Шаг 4. Применение к существующим индексам

Шаблон применяется только к **новым** индексам. Варианты для существующих:

**А. Подождать до завтра** (рекомендуется). Завтра в полночь создастся `fluent-osquery-YYYY.MM.dd+1` с новым маппингом.

**Б. Принудительный rollover** через reindex (только если нужно срочно):

```bash
# 1. Создать новый индекс с правильным маппингом
curl -s -X PUT "$OS/fluent-osquery-2026.05.22-v2" \
  -H "Content-Type: application/json" -d '{}'  # шаблон применится автоматически

# 2. Скопировать данные
curl -s -X POST "$OS/_reindex?wait_for_completion=false" \
  -H "Content-Type: application/json" -d '{
    "source": {"index": "fluent-osquery-2026.05.22"},
    "dest":   {"index": "fluent-osquery-2026.05.22-v2"}
  }'

# 3. Дождаться, переключить alias (если используется), удалить старый
```

**Рекомендация:** вариант А, дождаться следующего дня. Для срочной проверки маппинга — создать пустой test-индекс:

```bash
curl -s -X PUT "$OS/fluent-osquery-test" -H "Content-Type: application/json" -d '{}'
curl -s "$OS/fluent-osquery-test/_mapping?pretty" | grep -A2 osquery.pid
# Ожидание: "type": "long"
curl -s -X DELETE "$OS/fluent-osquery-test"
```

### Шаг 5. Smoke-тест на новом индексе

Если применили вариант А — назавтра:

```bash
OS=http://192.168.37.161:9200

# Range-запрос по integer-полю должен работать численно
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"range":{"osquery.local_port":{"gte":1024,"lte":65535}}},"aggs":{"total":{"value_count":{"field":"process.pid"}}}}'
# Ожидание: total.value > 0 (раньше могло быть 0 из-за лексикографического сравнения keyword)

# Aggregation по cid — теперь long
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"avg_cid":{"avg":{"field":"osquery.cid"}}}}'
# Ожидание: avg_cid.value — численное среднее, не ошибка типа
```

## Что НЕ делать в этой итерации

- **НЕ удалять старые индексы** (`fluent-osquery-2026.05.22`) без явного согласия пользователя — они содержат данные.
- **НЕ менять `dynamic: true` на `strict`** — потеряем гибкость для добавления новых osquery-таблиц.
- **НЕ менять `index.refresh_interval`, `number_of_shards`, `number_of_replicas`** — это отдельная задача оптимизации.
- **НЕ добавлять reindex-pipeline** в эту итерацию — слишком большой scope. Подождать до следующего дня.
- **НЕ переходить на ILM/ISM policies** в этой итерации — отдельная задача (требует OpenSearch ISM-плагин и план retention).

## Критерии готовности

- `curl "$OS/_index_template/fluent-osquery"` показывает version=2.1 и `osquery.pid → type: long`.
- Новый индекс (вручную созданный пустой test) → `_mapping` показывает корректные типы для всех осquery.* полей.
- Range-запрос по `osquery.local_port` или `osquery.cid` возвращает численно правильные результаты.
- Старые индексы `fluent-osquery-YYYY.MM.dd` НЕ испортились (нельзя менять mapping существующего индекса).
- Если правил fluent-audit.json — то же самое для него.

## Финал

1. **Обновить [opensearch/templates/README.md](../opensearch/templates/README.md):**
   - Раздел про версионирование шаблонов: добавить запись «v2.1: явные типы для osquery.* namespace».
   - В команды применения добавить swarm-вариант для re-create индекса если нужно срочно.

2. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделе про индексные шаблоны указать, что `osquery.pid`/`osquery.local_port`/`osquery.cid` — числовые поля.

3. **Закоммитить:**

   ```
   QA-04: explicit numeric mappings for osquery.* namespace

   - opensearch/templates/fluent-osquery.json v2.1:
     - osquery.pid/parent/tid/cid/start_time/ntime/duration → long
     - osquery.local_port/remote_port → integer
     - osquery.exit_code → long (handles int64 negatives from BPF)
     - container.image.tag added
     - process.exit_code, process.args, process.args_count, working_directory explicit
   - opensearch/templates/fluent-audit.json (if applicable):
     - service.name, auditd.session (long), process.args_count
   - README updated with mapping versioning note

   Closes WARN #13 from QA-01 (osquery namespace numeric fields).
   ```

4. **Сообщить пользователю:** маппинги в порядке; index template v2.1 применится к завтрашнему индексу. Серия QA-FIX (02/03/04) закрывает FAIL и WARN из QA-01.
