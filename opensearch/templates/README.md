# OpenSearch Index Templates

Шаблоны индексов для UEBA-стенда. Определяют маппинги ECS 8.11 и настройки
для всех индексов проекта. Применяются вручную через OpenSearch REST API.

## Шаблоны

| Файл | Index Pattern | Приоритет | Описание |
|------|---------------|-----------|----------|
| `fluent-audit.json` | `fluent-audit-*` | 200 | auditd события: execve, network, file, auth |
| `fluent-osquery.json` | `fluent-osquery-*` | 200 | osquery diff-события + `osquery.*` namespace |
| `system-auth.json` | `system-auth-*` | 200 | SSH auth события из journald via sshd_enrich.lua |
| `filebeat-auth.json` | `filebeat-*` | 50 | устаревший (filebeat удалён, заменён system-auth) |

---

## Применение

### Linux / macOS (curl)

```bash
BASE="https://opensearch.host:9200"
CREDS="admin:your_password"      # заменить
CACERT="--cacert /path/to/opensearch-ca.pem"   # или -k для dev

for name in fluent-audit fluent-osquery system-auth; do
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

foreach ($name in "fluent-audit", "fluent-osquery", "system-auth") {
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
curl -s -u "$CREDS" "$BASE/_cat/templates?v&name=fluent-*,system-auth*"

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
| `source.ip`, `destination.ip` | `ip` | CIDR-запросы: `source.ip: 10.0.0.0/8` |
| `process.start`, `process.parent.start` | `date` | ISO 8601 строки от `common.to_iso()` |
| `process.pid`, `auditd.session` | `integer` | Числовые range-запросы |
| `osquery.result.unix_time` | `long` | Epoch timestamp из osquery JSON |
| все прочие строки (dynamic template) | `keyword` | Агрегации и точный поиск без text/analyzer overhead |
| `total_fields.limit: 2000` (osquery) | — | osquery содержит разные колонки по ~20 запросам |
