# QA-FIX-12. osquery bpf_process_events: выравнивание process.entity_id с auditd / osquery.processes

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор, разделы про pid→start_time кэш и BPF backend.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник ECS, раздел про `process.entity_id`.
- [testing/QA-01-opensearch-field-audit.md](QA-01-opensearch-field-audit.md) — методика, где зафиксировано расхождение entity_id.
- [agents/configs/fluent-bit/scripts/osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) — главный файл правки (блок `bpf_processes`, ~стр.613-637).
- [agents/configs/fluent-bit/scripts/auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — для сверки формулы entity_id.
- [agents/configs/fluent-bit/scripts/proc_common.lua](../agents/configs/fluent-bit/scripts/proc_common.lua) — общая функция `resolve_start` / `short_id`.

## Цель итерации

Закрыть **WARN из QA-01 v4 «cross-index entity_id mismatch»** — `process.entity_id` для одного и того же `host.name + pid` не совпадает между `osquery.bpf_process_events` и `fluent-audit-*` (audit execve).

### Текущее состояние

Пример из QA-01 v4: pid 205424 на `agent01.uir.prj` (`/app/extra/healthcheck`):
- audit execve: `entity_id = 368b0e6098d885b0`
- osquery.bpf_process_events: `entity_id = 4b9fad0a123c63a4`

### Корневая причина

В [osquery_enrich.lua:629-637](../agents/configs/fluent-bit/scripts/osquery_enrich.lua#L629) для `bpf_processes`:

```lua
-- process.entity_id — seed: host:pid:ntime (kernel monotonic ns).
-- ntime ≠ epoch seconds, поэтому cache_put не вызываем (не смешиваем
-- с epoch-based кэшем из таблицы processes / auditd_enrich).
if cols["pid"] and cols["ntime"] and cols["ntime"] ~= "" then
    local seed = (record["host.name"] or "")
              .. ":" .. cols["pid"]
              .. ":" .. cols["ntime"]
    record["process.entity_id"] = common.short_id(seed)
end
```

`cols["ntime"]` — это **kernel monotonic boot time в наносекундах** (CLOCK_MONOTONIC, BPF tap'ом). А в `auditd_enrich` и `osquery_enrich` блоке `processes` сидер — **epoch seconds × 100** (jiffies из `/proc/<pid>/stat` field 22, `starttime`). Это два разных временных пространства — `short_id` хэш никогда не совпадёт.

### Что хотим

Чтобы для одного процесса `host:pid:start_time` давал **один и тот же entity_id** во всех трёх источниках:
- `auditd_enrich` execve → epoch start_time из `/proc/<pid>/stat`
- `osquery/processes` → epoch start_time из `/proc/<pid>/stat`
- `osquery.bpf_process_events` → epoch start_time из `/proc/<pid>/stat` (это правка)

**Value:** UEBA-коррелятор может JOIN'ить три потока по `host.name + process.entity_id` без дополнительных хэшей. Cross-stream attribution (BPF поймал короткий exec → auditd не успел → osquery/processes уже не видит): сейчас невозможна, после фикса — возможна (когда процесс живёт хотя бы 1 osquery snapshot interval).

### Риски и ограничения

- **Risk 1**: для **короткоживущих процессов** (< 100ms) `/proc/<pid>/stat` уже недоступен к моменту обработки BPF события — `resolve_start` вернёт nil → entity_id **не будет установлен вообще** (худший вариант: было неверно, стало пусто).
- **Risk 2**: для процессов в контейнерах с PID namespace `/proc/<pid>/stat` всё ещё доступен с host PID (osquery BPF отдаёт host PID, не container PID). Это OK.
- **Risk 3**: накопленные документы в `fluent-osquery-*` уже имеют старый entity_id — старые корреляции ломаются. Но они и так не работали (mismatch), так что регрессии нет.
- **Risk 4**: возможна синхронизационная race — BPF event приходит до того, как kernel закоммитил `/proc/<pid>/stat`. На практике для exec syscall stat доступен сразу после возврата из exec. Маловероятно.

### Альтернатива (отвергнута)

Можно было пойти в обратную сторону — в auditd_enrich для execve тоже использовать ntime. Но:
- auditd 4.x не передаёт monotonic time нативно.
- ntime недоступен в `osquery/processes` (не BPF) — третий источник тоже не выровнялся бы.

Поэтому правим bpf_processes.

## Pre-flight

```bash
OS=http://192.168.37.161:9200

# Снимок ДО: подсчитать mismatch для long-living процессов
# Берём execve pid из audit, ищем тот же pid+host в bpf_process_events.

# Найти долгоживущий процесс (live ≥ 5 min)
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 10,
  "query": { "bool": { "must": [
    { "term": { "event.action": "execve" } },
    { "range": { "process.start": { "lte": "now-5m" } } }
  ]}},
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["host.name","process.pid","process.entity_id","process.executable","@timestamp"]
}'
# Записать host+pid+entity_id для нескольких процессов.

# Для каждого — найти тот же pid в bpf_process_events
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 5,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } },
    { "term": { "host.name": "agent01.uir.prj" } },
    { "term": { "process.pid": <PID> } }
  ]}},
  "_source": ["process.pid","process.entity_id","host.name","@timestamp"]
}'
# Записать entity_id. Сейчас ДОЛЖЕН отличаться от auditd.

# Дополнительно — записать сколько bpf_process_events имеют entity_id в принципе
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "term": { "event.dataset": "osquery.bpf_process_events" } },
  "aggs": {
    "total":            { "value_count": { "field": "process.pid" } },
    "missing_entityid": { "missing":     { "field": "process.entity_id" } }
  }
}'
# Записать total + missing_entityid (для сравнения после фикса — missing может вырасти
# из-за коротких процессов где /proc/<pid>/stat недоступен).
```

## Реализация

### Шаг 0. Подтвердить корневую причину

1. Прочитать целиком [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua) блок `bpf_processes` (~стр.613-654) — убедиться, что текущая формула seed действительно использует `ntime`.
2. Прочитать [agents/configs/fluent-bit/scripts/proc_common.lua](../agents/configs/fluent-bit/scripts/proc_common.lua) — функции `resolve_start(pid)` и `short_id(seed)`. Уточнить:
   - Что возвращает `resolve_start` (nil если /proc недоступен? epoch sec? epoch×100?).
   - Какой формат seed ожидается (с разделителем `:`? число или строка start_time?).
3. Прочитать [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — формирование entity_id для execve. Скопировать формулу как есть для согласованности.

Если фактическая формула отличается от описания выше — **скорректировать план и сообщить пользователю до правки**.

### Шаг 1. Заменить ntime-сидер на epoch start_time

В [osquery_enrich.lua](../agents/configs/fluent-bit/scripts/osquery_enrich.lua), блок `bpf_processes`, заменить блок entity_id:

```lua
-- ── BPF process events (P2-01, docker-хосты) ─────────────────────────
if query_name == "bpf_processes" then
    record["event.dataset"] = "osquery.bpf_process_events"
    if cols["pid"]       then record["process.pid"]          = tonumber(cols["pid"]) end
    if cols["parent"]    then record["process.parent.pid"]   = tonumber(cols["parent"]) end
    if cols["path"]      and cols["path"] ~= "" then
        record["process.executable"] = cols["path"]
    end

    -- ... cmdline / uid / gid / exit_code блок без изменений ...

    -- process.entity_id — выровнено с auditd_enrich и osquery/processes:
    -- seed = host:pid:epoch_start_time (через /proc/<pid>/stat).
    -- Cross-index JOIN audit↔bpf_process_events по entity_id корректен для
    -- живых процессов (которые ещё доступны через /proc к моменту enrich'а).
    -- Для коротких процессов (/proc уже закрыт) entity_id НЕ ставим — лучше пусто,
    -- чем mismatch со static fallback.
    local bpf_pid = tonumber(cols["pid"])
    if bpf_pid and bpf_pid > 0 then
        local start_ts = common.resolve_start(bpf_pid)
        if start_ts then
            local seed = (record["host.name"] or "")
                      .. ":" .. tostring(bpf_pid)
                      .. ":" .. tostring(start_ts)
            record["process.entity_id"] = common.short_id(seed)
            -- Для bpf_socket_events того же процесса cache_put не нужен —
            -- resolve_start сам кэширует в proc_common.
        else
            -- Маркер для UEBA: entity_id отсутствует из-за короткой жизни процесса.
            -- В отличие от auditd event_timestamp_fallback (там подставляется @timestamp),
            -- здесь мы НЕ хотим fallback, чтобы не создавать mismatch с другими источниками.
            record["labels.entity_id_source"] = "bpf_proc_short_lived"
        end
    end

    -- ntime по-прежнему сохраняем как сырое поле для отладки.
    -- (если в текущем коде ntime копируется в osquery.ntime — оставить как есть)

    -- ... container resolution блок без изменений ...
```

**Важно — что меняется:**
- Удалить **полностью** старый блок с `cols["ntime"]` для entity_id. Поле `osquery.ntime` остаётся в индексе как сырое (для отладки), entity_id больше его не использует.
- `resolve_start` уже использует in-memory cache (через `proc_common.lua`), повторное чтение `/proc/<pid>/stat` не нужно.
- Совместимость с `bpf_socket_events` (~стр.674-683) уже корректна — там тоже `resolve_start`. После фикса bpf_processes и bpf_sockets для одного pid дадут **одинаковый** entity_id (если процесс ещё жив).

### Шаг 2. Опционально — обновить index template

Поле `labels.entity_id_source` уже существует (приходит из auditd_enrich `event_timestamp_fallback`). Добавление нового значения `bpf_proc_short_lived` не требует изменений в шаблоне — keyword принимает любую строку.

### Шаг 3. Раскатка

```bash
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass --limit bpf_hosts
```

Проверить, что fluent-bit перезапустился без ошибок:

```bash
ansible bpf_hosts -m shell -a "systemctl is-active fluent-bit; journalctl -u fluent-bit -n 30 --no-pager | grep -iE 'error|fatal|lua'" -i agents/deploy/inventory.ini
```

## Post-flight (smoke-тест)

Подождать 2-3 минуты для накопления свежих событий.

### Тест 1: cross-source match для долгоживущего процесса

```bash
OS=http://192.168.37.161:9200

# 1. На docker_host'е запустить процесс с предсказуемой длительностью
ssh agent01.uir.prj 'docker exec ueba_correlator sleep 60'  # любой долгоживущий

# 2. Найти этот процесс в audit
curl -s "$OS/fluent-audit-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "query": { "bool": { "must": [
    { "term": { "event.action": "execve" } },
    { "term": { "host.name": "agent01.uir.prj" } },
    { "match": { "process.command_line": "sleep 60" } },
    { "range": { "@timestamp": { "gte": "now-2m" } } }
  ]}},
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["process.pid","process.entity_id","process.executable","@timestamp"]
}'
# Записать pid + entity_id (PID_AUDIT, EID_AUDIT)

# 3. Найти тот же pid в osquery.bpf_process_events
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "query": { "bool": { "must": [
    { "term": { "event.dataset": "osquery.bpf_process_events" } },
    { "term": { "host.name": "agent01.uir.prj" } },
    { "term": { "process.pid": PID_AUDIT } }
  ]}},
  "_source": ["process.pid","process.entity_id","@timestamp"]
}'
# Ожидание: entity_id == EID_AUDIT ✓
```

### Тест 2: общее покрытие entity_id

```bash
curl -s "$OS/fluent-osquery-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "term":  { "event.dataset": "osquery.bpf_process_events" } },
    { "range": { "@timestamp": { "gte": "now-15m" } } }
  ]}},
  "aggs": {
    "total":               { "value_count": { "field": "process.pid" } },
    "has_entity_id":       { "filter": { "exists": { "field": "process.entity_id" } } },
    "short_lived":         { "filter": { "term": { "labels.entity_id_source": "bpf_proc_short_lived" } } }
  }
}'
# Ожидание:
#   has_entity_id / total: было ~100% (хотя hash был неверный), теперь — зависит от доли долгоживущих процессов.
#     Можем потерять 10-40% (короткие BPF execve, для которых /proc исчез).
#   short_lived.doc_count > 0 — флаг работает.
# Если has_entity_id / total < 50% — это регрессия, дать пользователю выбор:
#   (a) откатить ntime-сидер (но JOIN снова сломается),
#   (b) принять trade-off (UEBA скоринг должен использовать short_lived как сигнал).
```

### Тест 3: bpf_processes и bpf_socket_events одного pid дают одинаковый entity_id

```bash
# Найти pid, у которого есть оба типа событий за окно
curl -s "$OS/fluent-osquery-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-15m" } } },
  "aggs": {
    "by_pid": {
      "terms": { "field": "process.pid", "size": 5, "min_doc_count": 2 },
      "aggs": {
        "by_dataset": { "terms": { "field": "event.dataset" } },
        "entity_ids": { "terms": { "field": "process.entity_id" } }
      }
    }
  }
}'
# Ожидание: для pid, который встречается в bpf_processes И bpf_sockets,
# entity_ids buckets содержат ОДИН ключ — entity_id совпадает.
```

## Что НЕ делать в этой итерации

- **НЕ менять auditd_enrich.lua** — auditd execve уже использует epoch start_time, оно эталонное.
- **НЕ менять osquery/processes блок** — он тоже эталонный, использует proc_common.
- **НЕ удалять `osquery.ntime`** — оставить как сырое поле в индексе для возможной отладки.
- **НЕ делать reindex старых документов** — старые entity_id остаются как есть. Они и так не работали для JOIN.
- **НЕ добавлять fallback на @timestamp** для коротких процессов в bpf_processes — это создаст mismatch с auditd, где для коротких exit используется event_timestamp_fallback (а здесь не будет соответствующего auditd события вообще).
- **НЕ трогать container resolution** — это отдельная подсистема, не связана с entity_id.

## Критерии готовности

- Для одного и того же `host.name + process.pid` долгоживущего процесса `process.entity_id` **совпадает** между `fluent-audit-*` execve, `fluent-osquery-*` `osquery.bpf_process_events`, `fluent-osquery-*` `osquery.bpf_socket_events`, `fluent-osquery-*` `osquery.processes`.
- Документы с пропавшим `entity_id` (short-lived процессы) помечаются `labels.entity_id_source = "bpf_proc_short_lived"`.
- `process.entity_id` присутствует в новых bpf_process_events ≥50% документов (порог зависит от профиля нагрузки — если меньше, обсудить с пользователем).
- fluent-bit healthy на bpf_hosts, нет Lua errors.
- Smoke-тест №1 (cross-source match) проходит — entity_id совпадает.

## Финал

1. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе «osquery BPF backend» удалить упоминание про ntime-сидер в bpf_processes (заменить на epoch start_time для cross-stream JOIN).
   - Добавить отметку про `labels.entity_id_source = "bpf_proc_short_lived"` как маркер потерянного entity_id из-за короткой жизни процесса.

2. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел про `process.entity_id` — пометить, что теперь все четыре источника (auditd, osquery/processes, bpf_processes, bpf_socket_events) дают **согласованный** hash для одного pid+host+start_time.

3. **Закоммитить:**

   ```
   QA-FIX-12: align bpf_processes entity_id with auditd execve

   - osquery_enrich.lua bpf_processes block:
     - Drop ntime-based seed (kernel monotonic ns) for entity_id.
     - Use proc_common.resolve_start(pid) (epoch start_time), matching
       auditd_enrich and osquery/processes formula.
     - Short-lived processes (where /proc/<pid>/stat is gone) get
       labels.entity_id_source="bpf_proc_short_lived" instead of a
       fabricated entity_id.
   - osquery.ntime preserved as raw field for debugging.

   Closes WARN "cross-index entity_id mismatch" from QA-01 v4 audit.
   Enables UEBA join across audit/process and osquery streams by
   host.name + process.entity_id for long-lived processes.
   ```

4. **Сообщить пользователю:** для долгоживущих процессов теперь JOIN audit↔osquery работает по `host.name + process.entity_id`. Trade-off: для очень коротких процессов entity_id теперь может отсутствовать (вместо неверного значения), помечается флагом — UEBA-коррелятор должен использовать `host.name + process.pid + @timestamp±2s` как fallback в этом случае.
