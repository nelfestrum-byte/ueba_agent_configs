# P1-02. ECS Index Templates для OpenSearch

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник по ECS-схеме. Все типизированные поля в шаблонах должны соответствовать тому, что описано в README_FOR_AI.
- [HARDENING_PLAN.md, раздел P1-02](HARDENING_PLAN.md) — обоснование, таблица типов, черновик шаблона, грабли.

## Цель итерации

Создать ECS Index Templates для OpenSearch на 4 паттерна индексов и применять их через Ansible до того, как индексы создаются динамически. Это устраняет:

- Type conflicts (массив vs строка → `mapper_parsing_exception`).
- Неправильную автотипизацию (`source.ip` как text, `file.hash.md5` как text+keyword).
- Несогласованность типов между дневными индексами.

**Value сразу:**

- Все будущие индексы получают стабильные типы — дашборды и поисковые запросы работают предсказуемо.
- `source.ip` становится `ip` type → доступны CIDR-фильтры и geo-enrich.
- `event.module`/`event.dataset` через `constant_keyword` → экономия 5-15% диска на индекс.
- Это **независимая ценность**, даже если P0-01/P0-02 не сделаны (шаблон просто не включит соответствующие поля — добавим позже).

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Что делать с существующими индексами**, у которых старый dynamic mapping (например `fluent-audit-2026.04.*`)?
   - Recommended: **смириться** (старые умрут по retention; новые будут со шаблоном). Reindex — отдельная задача.
   - Альтернатива: explicit reindex старых данных в новые шаблонированные индексы (стоит в нашем случае не делать).
2. **Тип `wildcard`** для `process.command_line` — поддерживается ли в целевой версии OpenSearch?
   - Если не уверены — проверить на dev-стенде, при отсутствии — fallback на `keyword` (потеря substring-поиска, некритично).
3. **Тип `constant_keyword`** — то же самое, проверка на целевой версии.

## Pre-flight проверки

1. Проверить версию OpenSearch на dev-стенде:

   ```bash
   curl -s http://localhost:9200 | jq '.version.number'
   ```

2. Проверить поддержку `wildcard` и `constant_keyword`:

   ```bash
   # Test wildcard
   curl -X PUT 'http://localhost:9200/_test_wildcard' -H 'Content-Type: application/json' -d '{
     "mappings": { "properties": { "f": { "type": "wildcard" } } }
   }'
   curl -X DELETE 'http://localhost:9200/_test_wildcard'

   # Test constant_keyword
   curl -X PUT 'http://localhost:9200/_test_ck' -H 'Content-Type: application/json' -d '{
     "mappings": { "properties": { "f": { "type": "constant_keyword", "value": "x" } } }
   }'
   curl -X DELETE 'http://localhost:9200/_test_ck'
   ```

   Если возвращают 200 — типы доступны. Если 400 — fallback на `keyword`.

3. Проверить, есть ли уже какой-нибудь системный шаблон с pattern `*`:

   ```bash
   curl -s 'http://localhost:9200/_index_template?pretty' | jq '.index_templates[] | {name, patterns: .index_template.index_patterns}'
   ```

   Если есть — наш `priority: 200` должен быть выше существующих.

4. Проверить состояние P0-01 (добавлен ли `process.entity_id` в enrich) и P0-02 (создан ли индекс `system-auth-*`). Влияет на содержимое шаблонов:
   - Если P0-01 **не сделан** — `process.entity_id` всё равно включить в шаблон (когда P0-01 будет сделан, поле уже типизировано).
   - Если P0-02 **не сделан** — шаблон `system-auth.json` всё равно создать (применится, когда первый документ туда придёт).

## Реализация

### Шаг 1. Создать `logstash/configs/templates/` и 4 шаблона

`logstash/configs/templates/fluent-audit.json`:

```json
{
  "index_patterns": ["fluent-audit-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "dynamic": "true",
      "properties": {
        "@timestamp":                  { "type": "date" },
        "ecs.version":                 { "type": "constant_keyword" },
        "event.kind":                  { "type": "constant_keyword", "value": "event" },
        "event.module":                { "type": "constant_keyword", "value": "auditd" },
        "event.dataset":               { "type": "constant_keyword", "value": "auditd" },
        "event.category":              { "type": "keyword" },
        "event.action":                { "type": "keyword" },
        "event.outcome":               { "type": "keyword" },
        "event.type":                  { "type": "keyword" },
        "host.name":                   { "type": "keyword" },
        "host.os.type":                { "type": "keyword" },
        "host.os.family":              { "type": "keyword" },
        "user.id":                     { "type": "keyword" },
        "user.name":                   { "type": "keyword" },
        "user.effective.id":           { "type": "keyword" },
        "user.effective.name":         { "type": "keyword" },
        "process.pid":                 { "type": "long" },
        "process.parent.pid":          { "type": "long" },
        "process.entity_id":           { "type": "keyword" },
        "process.parent.entity_id":    { "type": "keyword" },
        "process.name":                { "type": "keyword" },
        "process.executable":          { "type": "keyword" },
        "process.working_directory":   { "type": "keyword" },
        "process.command_line":        { "type": "wildcard" },
        "process.args":                { "type": "keyword" },
        "process.args_count":          { "type": "integer" },
        "source.ip":                   { "type": "ip" },
        "source.port":                 { "type": "long" },
        "destination.ip":              { "type": "ip" },
        "destination.port":            { "type": "long" },
        "file.path":                   { "type": "keyword" },
        "file.name":                   { "type": "keyword" },
        "file.extension":              { "type": "keyword" },
        "file.inode":                  { "type": "keyword" },
        "file.device":                 { "type": "keyword" },
        "file.mode":                   { "type": "keyword" },
        "file.uid":                    { "type": "keyword" },
        "file.gid":                    { "type": "keyword" },
        "file.hash.md5":               { "type": "keyword" },
        "file.hash.sha1":              { "type": "keyword" },
        "file.hash.sha256":            { "type": "keyword" },
        "auditd.session":              { "type": "long" },
        "auditd.data.syscall":         { "type": "keyword" },
        "auditd.key":                  { "type": "keyword" },
        "tags":                        { "type": "keyword" },
        "related.user":                { "type": "keyword" },
        "related.ip":                  { "type": "ip" },
        "related.hash":                { "type": "keyword" }
      }
    }
  }
}
```

`logstash/configs/templates/fluent-osquery.json` — тот же скелет, но `event.module=osquery`, `event.dataset=osquery`, плюс osquery-специфика:

```json
"osquery.action":            { "type": "keyword" },
"osquery.name":              { "type": "keyword" },
"osquery.host_identifier":   { "type": "keyword" }
```

И копируется общий блок ECS-полей (process.*, user.*, source.*, destination.*, file.*, related.*, tags, host.*, event.*, @timestamp, ecs.version) — те же типы, что в fluent-audit.

`logstash/configs/templates/system-auth.json` — `event.module=system`, `event.dataset=system.auth`, без auditd-специфики и без `osquery.*`. Главные поля: user, source.ip, source.port, event.*, host.*, related.user, related.ip, process.name (фиксировано "sshd"). Можно сделать `process.name: { "type": "constant_keyword", "value": "sshd" }` — экономия диска.

`logstash/configs/templates/suricata.json` — `event.module=suricata`, плюс network-богатые поля:

```json
"event.severity":            { "type": "long" },
"network.transport":         { "type": "keyword" },
"network.protocol":          { "type": "keyword" },
"suricata.eve.event_type":   { "type": "keyword" },
"suricata.eve.flow_id":      { "type": "long" },
"suricata.eve.alert.signature": { "type": "keyword" },
"suricata.eve.alert.signature_id": { "type": "long" },
"suricata.eve.alert.severity": { "type": "long" }
```

(плюс общий ECS-блок source/destination/host/event/@timestamp).

**Совет:** не дублируй вручную — вынеси общий ECS-блок в комментарий в README шаблонов или внутри одного файла как reference; если повторений станет много — рассмотрим composable templates (отдельная задача).

### Шаг 2. Ansible-task для PUT-загрузки шаблонов

В [logstash/deploy/logstash-deploy.yml](../logstash/deploy/logstash-deploy.yml) добавить task (рядом с копированием pipeline-конфига):

```yaml
- name: Copy index template JSON files to deploy host
  ansible.builtin.copy:
    src: "{{ playbook_dir }}/../configs/templates/"
    dest: /tmp/opensearch-templates/
    mode: '0644'
  tags: [templates]

- name: Apply OpenSearch index templates via API
  ansible.builtin.uri:
    url: "{{ opensearch_url }}/_index_template/{{ item }}"
    method: PUT
    body_format: json
    body: "{{ lookup('file', playbook_dir + '/../configs/templates/' + item + '.json') }}"
    user: "{{ opensearch_user }}"
    password: "{{ opensearch_password }}"
    force_basic_auth: yes
    validate_certs: yes
    ca_path: "{{ playbook_dir }}/files/opensearch-ca.pem"
    status_code: [200, 201]
  loop:
    - fluent-audit
    - fluent-osquery
    - system-auth
    - suricata
  tags: [templates]
```

Загрузка может идти с control-node Ansible напрямую (uri-модуль), необязательно через target-хост.

### Шаг 3. Применить на dev-стенде

```bash
cd logstash/deploy
ansible-playbook logstash-deploy.yml --ask-vault-pass --tags=templates --limit=dev
```

Проверить:

```bash
curl -s "$OS/_index_template?pretty" | jq '.index_templates[] | select(.name | startswith("fluent-") or startswith("system-") or startswith("suricata")) | .name'
```

Должны быть 4 имени.

### Шаг 4. Создать тестовый индекс и проверить маппинг

```bash
# Удалить если есть от предыдущих опытов
curl -X DELETE "$OS/fluent-audit-test"

# Послать тестовый документ
curl -X POST "$OS/fluent-audit-test/_doc" -H 'Content-Type: application/json' -d '{
  "@timestamp": "2026-05-16T12:00:00Z",
  "source.ip": "192.168.1.1",
  "process.pid": 12345
}'

# Проверить, что source.ip типа ip:
curl -s "$OS/fluent-audit-test/_mapping" | jq '.["fluent-audit-test"].mappings.properties["source.ip"].type'
# Должно вернуть: "ip"

# Cleanup
curl -X DELETE "$OS/fluent-audit-test"
```

### Шаг 5. Симуляция type-conflict (regression test)

```bash
# Документ 1: process.args как массив
curl -X POST "$OS/fluent-audit-test/_doc" -H 'Content-Type: application/json' -d '{
  "@timestamp": "2026-05-16T12:00:00Z",
  "process.args": ["sh", "-c", "ls"]
}'

# Документ 2: process.args как строка (раньше падало)
curl -X POST "$OS/fluent-audit-test/_doc" -H 'Content-Type: application/json' -d '{
  "@timestamp": "2026-05-16T12:00:01Z",
  "process.args": "sh -c ls"
}'
```

Оба должны индексироваться без ошибки. Если документ 2 падает — шаблон не работает; проверить, что `fluent-audit-test` действительно матчится по `fluent-audit-*` (приоритет, alias).

## Что НЕ делать в этой итерации

- **НЕ переиндексировать существующие данные.** Старые индексы остаются с dynamic mapping; шаблон работает только для новых.
- **НЕ применять template через Logstash output (`template => ...`).** Делаем через PUT API из Ansible — это решение принято в плане.
- **НЕ создавать composable templates** (`component_template`). Стартуем с self-contained шаблонов на каждый pattern. Рефакторинг в композицию — отдельная задача, если шаблонов станет >6.
- **НЕ менять Logstash pipeline.** Шаблон применяется на стороне OpenSearch до индексации; Logstash не трогаем.
- **НЕ настраивать ILM/ISM** (retention policies) — это отдельная задача.

## Проверка готовности

Из [HARDENING_PLAN.md P1-02 → Критерий готовности](HARDENING_PLAN.md):

- `curl -s "$OS/_index_template?pretty" | jq '.index_templates[].name'` показывает все 4 шаблона.
- Новый индекс `fluent-audit-<сегодня>` создан **после** применения шаблона. `source.ip` имеет тип `ip` (проверка: `curl "$OS/fluent-audit-*/_mapping" | jq '.[].mappings.properties["source.ip"].type'`).
- Симуляция type-conflict проходит: документы с `process.args` как массив и как строка оба индексируются.
- (опционально) Размер свежего индекса с `constant_keyword` для `event.module` на 5-15% меньше старого без шаблона.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделах 3.3, 4.4 — пометить, что типы полей теперь зафиксированы через index templates (раздел Logstash). Можно добавить новую секцию "Index templates" перед разделом 7 со списком файлов шаблонов и их соответствием индексам.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В "Ключевые файлы по темам" добавить строку: `logstash/configs/templates/*.json` — ECS index templates для OpenSearch.
   - В "Команды для быстрого старта" добавить проверку шаблонов:

     ```bash
     # Проверить применённые index templates
     curl -s "$OS/_index_template?pretty" | jq '.index_templates[].name'
     ```

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P1-02 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить:**

   ```
   P1-02: ECS index templates for OpenSearch

   - 4 templates: fluent-audit, fluent-osquery, system-auth, suricata
   - constant_keyword for event.module/event.dataset (disk savings)
   - ip type for source.ip/destination.ip/related.ip (CIDR + geo)
   - Ansible PUT task in logstash-deploy.yml (tag: templates)
   - Verified on dev: source.ip → ip; process.args array+string both index
   - README_FOR_AI: added index templates section
   - CLAUDE.md: template files listed + check command added
   ```

5. **Сообщить пользователю**: 4 шаблона активны, type conflicts закрыты, дашборды/запросы могут переезжать на новые индексы с уверенностью в типах.
