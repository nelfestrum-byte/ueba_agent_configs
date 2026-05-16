# CLAUDE.md — UEBA проект
Мы разрабатываем конфигурации источников для сбора данных.
Данные будут использоваться для UEBA системы на основе скоринга.
Собираемые данные должны поступать нормализованными по ECS 8.x.
Главный приоритет - сохранение совместимости с оригинальным Elastic.

**Цели:** 
1. Минимизировать потребление токенов через оптимизированную навигацию по проекту и точные инструкции.
2. Разработать скрипты для автоматизации развертывания и обновления агентов.
3. Настроить источники для сбора событий, которые в дальнейшем можно применить для поведенческого анализа. Используем современный подход к решению вопроса и действуем как эксперт в области компьютерной безопасности.

## Стек агентов

| Сервис | Роль |
|--------|------|
| **auditd** | Kernel audit: execve, sudo, auth, file_integrity → /var/log/audit/audit.log |
| **fluent-bit** | 1) Читает audit.log; merge по serial + ECS enrich (Lua) → TCP 5045 → `fluent-audit-*`<br>2) Читает osqueryd.results.log; ECS enrich (Lua) → TCP 5047 → `fluent-osquery-*` |
| **filebeat** | Читает /var/log/auth.log (SSH auth) → Logstash beats 5044 → `filebeat-*` |
| **osquery** | Diff-мониторинг: процессы, соединения, пользователи, модули, сервисы, cron, SSH-ключи |

**auditbeat** остановлен/отключён — конфликтует с auditd за audit netlink-сокет.

## Структура проекта

```
ueba-stand/
│
├── logstash/
│   ├── configs/
│   │   ├── logstash.yml                 — настройки Logstash (workers, queue)
│   │   ├── pipelines.yml                — список пайплайнов
│   │   ├── pipeline/
│   │   │   └── ueba-main.conf           — ГЛАВНЫЙ файл: beats relay + Suricata/Windows
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
│   │   │       └── auditd_enrich.lua    — обогащение в ECS + MITRE ATT&CK теги
│   │   ├── filebeat/
│   │   │   └── filebeat.yml.j2          — конфиг filebeat (Ansible template)
│   │   └── osquery/osquery.conf         — diff-запросы (без count/snapshot метрик)
│   └── deploy/
│       ├── agents-deploy.yml            — Ansible плейбук (auditd + fluent-bit + filebeat + osquery)
│       ├── agents-deploy-legacy.yml     — архив старого плейбука
│       ├── ansible.cfg
│       ├── inventory.ini
│       ├── group_vars/all.yml           — logstash_host, версии пакетов
│       ├── group_vars/all.yml.example   — шаблон переменных
│       └── fetch-packages/              — скачать .deb для офлайн-деплоя
│           ├── fetch.ps1
│           └── Dockerfile
│
├── dev_stand/
│   ├── README.md
│   ├── docker-compose.yml               — OpenSearch + Dashboards + Logstash
│   ├── opensearch/opensearch.yml
│   └── scripts/                         — семплы событий для ручной отправки
│       ├── send-auditd.sh
│       ├── send-sshd.sh
│       └── send-osquery.sh
│
├── README.md
└── .gitignore
```

## Ключевые файлы по темам

| Тема | Файлы | Назначение |
|------|-------|-----------|
| **Пайплайн** | `logstash/configs/pipeline/ueba-main.conf` | beats 5044 + fluent-bit TCP 5045 + Suricata/Windows |
| **Конфиги Logstash** | `logstash/configs/logstash.yml`, `pipelines.yml` | Настройки рантайма |
| **Деплой Logstash** | `logstash/deploy/logstash-deploy.yml` | Ansible: docker pull + copy + up |
| **Переменные Logstash** | `logstash/deploy/group_vars/all.yml` | opensearch_url, SSL, image, bind_addr |
| **Правила auditd** | `agents/configs/auditd/audit.rules` | execve, network, priv_escalation, file watch |
| **Конфиг fluent-bit** | `agents/configs/fluent-bit/fluent-bit.conf` | auditd pipeline: tail → merge → enrich → TCP 5045 |
| **Lua merge** | `agents/configs/fluent-bit/scripts/auditd_merge.lua` | объединение auditd записей по serial |
| **Lua enrich** | `agents/configs/fluent-bit/scripts/auditd_enrich.lua` | ECS-обогащение + MITRE ATT&CK теги |
| **Lua osquery enrich** | `agents/configs/fluent-bit/scripts/osquery_enrich.lua` | ECS-обогащение osquery diff-событий + osquery.* namespace |
| **Конфиг filebeat** | `agents/configs/filebeat/filebeat.yml.j2` | только system/auth (SSH auth.log) |
| **Конфиг osquery** | `agents/configs/osquery/osquery.conf` | diff-запросы: процессы, сети, пользователи |
| **Деплой агентов** | `agents/deploy/agents-deploy.yml` | Ansible: auditd + fluent-bit + filebeat + osquery |
| **Переменные агентов** | `agents/deploy/group_vars/all.yml` | logstash_host, версии .deb |
| **Dev-стенд** | `dev_stand/docker-compose.yml` | Локальный прогон без агентов |

## Индексы OpenSearch

| Индекс | Источник |
|--------|---------|
| `fluent-audit-YYYY.MM.dd` | fluent-bit: auditd ECS-события (execve, sudo, auth, network, file) — TCP 5045 |
| `fluent-osquery-YYYY.MM.dd` | fluent-bit: osquery diff-события ECS + osquery.* namespace — TCP 5047 |
| `filebeat-{version}-YYYY.MM.dd` | filebeat: SSH auth.log (system/auth module) — beats 5044 |
| `suricata-YYYY.MM.dd` | Suricata eve.json (TCP 5049) |
| `winevtlog-YYYY.MM.dd` | Windows winevtlog (TCP 5046, stub) |

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
4. Dev: cd dev_stand && docker compose restart logstash
5. Прод: cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Изменить конфиг агентов (auditbeat / filebeat / osquery)
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

## Команды для быстрого старта

```bash
# Dev-стенд
cd dev_stand && docker compose up -d
docker compose logs -f logstash

# Перезапустить Logstash после правки конфига (dev)
docker compose restart logstash

# Проверка индексов OpenSearch
curl -s 'http://localhost:9200/_cat/indices?v&index=auditbeat-*,filebeat-*,suricata-*' | sort

# Деплой Logstash в прод
cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass

# Деплой агентов
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass

# Syntax-check плейбуков
ansible-playbook --syntax-check logstash/deploy/logstash-deploy.yml
ansible-playbook --syntax-check agents/deploy/agents-deploy.yml

# Проверка агентов на хосте
systemctl status auditbeat filebeat osqueryd
auditbeat test output && filebeat test output
```

## Известные особенности и грабли

### auditd 4.x — нет type=EOE в audit.log
auditd **4.0+** не пишет `type=EOE` в `/var/log/audit/audit.log` — в 4.x EOE обрабатывается внутри dispatcher-плагинов и в лог не попадает. `end_of_event_timeout = 2` в `auditd.conf` **не исправляет** это поведение.

**Следствие**: `auditd_merge.lua` НЕ должен полагаться на EOE как единственный триггер флаша. Скрипт флашит по timeout (wall clock, `os.time()`): после TIMEOUT секунд без новых записей для данного serial — запись уходит в поток. EOE-ветка оставлена для совместимости с auditd < 4.0.

**Диагностика fluent-bit**: если `filter.lua.0.add_records = 0` при ненулевом `input.tail.0.records` — merge-скрипт не флашит. Проверить:
```bash
curl -s http://127.0.0.1:2020/api/v1/metrics | python3 -m json.tool
```

---

## Что НЕ читать

- `.git/` — используйте `git log` вместо чтения объектов
- `*.log` — используйте `docker compose logs -n 50` или `journalctl -n 50`
- `agents/deploy/files/*.deb` — бинарные пакеты, в git не хранятся

---

**Последнее обновление:** 2026-05-15
**Версия проекта:** beats-ecs / auditbeat+filebeat+osquery → OpenSearch
