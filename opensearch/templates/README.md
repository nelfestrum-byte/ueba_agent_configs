# OpenSearch Index Templates

Шаблоны индексов для UEBA-стенда. Определяют маппинги ECS 8.11 и настройки
для всех индексов проекта. Применяются вручную через OpenSearch REST API.

## Шаблоны

| Файл | Index Pattern | Приоритет | Описание |
|------|---------------|-----------|----------|
| `fluent-audit.json` | `fluent-audit-*` | 200 | auditd события: execve, network, file, auth |
| `fluent-osquery.json` | `fluent-osquery-*` | 200 | osquery diff-события + `osquery.*` namespace + `container.*` (BPF) |
| `system-auth.json` | `system-auth-*` | 200 | **не активен** — SSH pipeline удалён (P0-03) |

Применение через Ansible автоматизировано в `logstash/deploy/logstash-deploy.yml` (только fluent-audit и fluent-osquery). Ручное применение описано ниже.

---

## Применение

### Linux / macOS (curl)

```bash
BASE="https://opensearch.host:9200"
CREDS="admin:your_password"      # заменить
CACERT="--cacert /path/to/opensearch-ca.pem"   # или -k для dev

for name in fluent-audit fluent-osquery; do
  echo "→ $name"
  curl -s -u "$CREDS" $CACERT \
    -X PUT "$BASE/_index_template/$name" \
    -H "Content-Type: application/json" \
    --data-binary @"${name}.json" | python3 -m json.tool
done
```

### Windows (PowerShell)

```powershell
$BASE    = "https://opensearch.host:9200"
$CREDS   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:your_password"))
$Headers = @{ Authorization = "Basic $CREDS"; "Content-Type" = "application/json" }

foreach ($name in "fluent-audit", "fluent-osquery") {
    $body = Get-Content -Raw "$PSScriptRoot\$name.json"
    $resp = Invoke-RestMethod -Method Put `
        -Uri "$BASE/_index_template/$name" `
        -Headers $Headers `
        -Body $body
    Write-Host "$name -> $($resp | ConvertTo-Json -Compress)"
}
```

Для dev-стенда (`http://localhost:9200` без TLS) убрать `$CACERT` / сертификатную часть.

---

## Проверка

```bash
# Список всех UEBA-шаблонов:
curl -s -u "$CREDS" "$BASE/_cat/templates?v&name=fluent-*"

# Полный шаблон:
curl -s -u "$CREDS" "$BASE/_index_template/fluent-audit" | python3 -m json.tool

# Маппинги реального индекса (после первого события):
curl -s -u "$CREDS" "$BASE/fluent-audit-$(date +%Y.%m.%d)/_mapping" | python3 -m json.tool
```

---

## Настройка под окружение

| Параметр | По умолчанию | Для dev (1 нода) |
|----------|-------------|------------------|
| `number_of_replicas` | `1` | `0` — иначе индекс будет в статусе yellow |
| `number_of_shards` | `1` | `1` (менять не нужно) |
| `index.refresh_interval` | `5s` | `1s` — если нужен real-time поиск |

Параметры шардов/реплик **нельзя изменить** для уже созданного индекса.
Для существующих индексов — только refresh_interval через `PUT /<index>/_settings`.

---

## Ключевые решения маппинга

| Поле | Тип | Причина |
|------|-----|---------|
| `process.command_line`, `process.executable`, `file.path` | `wildcard` | Эффективный glob-поиск: `*bash -c*`, `*/tmp/*` |
| `source.ip`, `destination.ip`, `related.ip` | `ip` | CIDR-запросы: `source.ip: 10.0.0.0/8` |
| `process.start`, `process.parent.start` | `date` | ISO 8601 строки от `common.to_iso()` |
| `process.pid` | `integer` | Числовые range-запросы |
| `auditd.session` | `long` (v2.1) | Достаточный запас для session id; в v2.0 был `integer` |
| `osquery.pid`/`parent`/`tid`/`cid`/`ntime`/`duration`/`start_time` | `long` (v2.1) | Числовые поля от osquery/BPF, нужны для range и avg-аггрегаций |
| `osquery.local_port`, `osquery.remote_port` | `integer` (v2.1) | Range по диапазону портов (1024–65535) |
| `osquery.exit_code`, `process.exit_code` | `long` (v2.1) | BPF int64 negatives (errno), нормализованы в osquery_enrich.lua |
| `osquery.path`, `osquery.cmdline`, `osquery.process_path` | `wildcard` (v2.1) | Glob по путям/cmdline |
| `auditd.paths` | `wildcard` (v2.1) | Множественные пути (rename: source+dest) — glob-поиск |
| `osquery.result.unix_time` | `long` | Epoch timestamp из osquery JSON |
| `event.module`, `ecs.version` | `constant_keyword` | Одно значение на индекс — экономия CPU/диска |
| `event.dataset` (audit) | `constant_keyword` | Всегда "auditd" для fluent-audit-* |
| `event.dataset` (osquery) | `keyword` | Варьируется: osquery.processes, osquery.bpf_process_events и др. |
| `key` (audit, top-level) | `keyword` | auditd rule key: fileless_exec, process_injection и пр. |
| `container.*` (osquery) | `keyword` | BPF backend: container.id, name, entity_id, image.name, image.tag |
| `service.name` (audit, v2.1) | `keyword` | systemd unit name для SERVICE_START/STOP событий |
| `file.hash.*` (audit) | `keyword` | md5/sha1/sha256 — точный lookup без full-text |
| `osquery.uid`/`gid`/`euid`/`egid` | `keyword` | UID — традиционно keyword в ECS, для строкового сравнения и terms-аггрегаций |
| все прочие строки (dynamic template) | `keyword` | Агрегации и точный поиск без text/analyzer overhead |
| `total_fields.limit: 2000` (osquery) | — | osquery содержит разные колонки по ~20 запросам |

---

## Версионирование шаблонов

Версия указана в `_meta.version` каждого файла. Шаблон применяется только к **новым индексам** (создаваемым после `PUT _index_template`). Существующие `fluent-osquery-YYYY.MM.dd`/`fluent-audit-YYYY.MM.dd` остаются со старым маппингом до ротейта (по дате — следующий день).

| Версия | Дата | Изменения |
|--------|------|-----------|
| 2.0 | 2026-05-15 | Базовый ECS 8.11 маппинг, osquery.* namespace (только `result.*`), `container.*` для BPF backend |
| 2.1 | 2026-05-23 | QA-04: явные числовые типы для `osquery.*` namespace (pid/parent/tid/cid/ntime/duration/start_time → long, local_port/remote_port → integer, exit_code → long); `container.image.tag`, `process.exit_code` (long); audit: `service.name` (keyword), `auditd.session` (integer→long), `auditd.paths` (keyword→wildcard), `process.working_directory` (keyword→wildcard) |

### Срочная переапликация маппинга к существующему индексу

По умолчанию — подождать следующий день (новый индекс пойдёт с новым маппингом). Для срочной проверки шаблона создать пустой test-индекс:

```bash
OS=http://opensearch:9200
curl -s -X PUT "$OS/fluent-osquery-test" -H "Content-Type: application/json" -d '{}'
curl -s "$OS/fluent-osquery-test/_mapping?pretty" | grep -A2 '"pid"'
# Ожидание: "type": "long"
curl -s -X DELETE "$OS/fluent-osquery-test"
```

Для реальной миграции (если нельзя ждать ротейт) — reindex в новый индекс с тем же name+суффикс:

```bash
# 1. Создать пустой dest (шаблон применится автоматически)
curl -s -X PUT "$OS/fluent-osquery-$(date +%Y.%m.%d)-v2" -H "Content-Type: application/json" -d '{}'

# 2. Скопировать данные
curl -s -X POST "$OS/_reindex?wait_for_completion=false" \
  -H "Content-Type: application/json" -d '{
    "source": {"index": "fluent-osquery-'"$(date +%Y.%m.%d)"'"},
    "dest":   {"index": "fluent-osquery-'"$(date +%Y.%m.%d)"'-v2"}
  }'

# 3. После завершения — переключить alias/удалить старый индекс
```
