# CLAUDE.md — UEBA проект

**Цель:** минимизировать потребление токенов через оптимизированную навигацию по проекту и точные инструкции.

## Структура проекта

```
ueba-stand/                              — корень репозитория (физическое имя не меняем)
│
├── logstash/
│   ├── configs/
│   │   ├── logstash.yml                 — настройки Logstash (workers, queue)
│   │   ├── pipelines.yml                — список пайплайнов
│   │   ├── pipeline/
│   │   │   └── ueba-main.conf           — ГЛАВНЫЙ файл обработки событий
│   │   └── patterns/                    — grok-паттерны (пустая директория, .gitkeep)
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
│   │   ├── fluent-bit/
│   │   │   ├── fluent-bit.conf          — сбор sys/app логов
│   │   │   ├── parsers.conf
│   │   │   └── flatten.lua              — нормализация osquery JSON
│   │   ├── osquery/osquery.conf         — запросы и интервалы
│   │   └── auditd/audit.rules           — правила аудита
│   └── deploy/
│       ├── agents-deploy.yml            — Ansible плейбук (apt online + конфиги)
│       ├── ansible.cfg
│       ├── inventory.ini
│       └── group_vars/all.yml           — logstash_host, apt_mirror_url, версии
│
├── dev_stand/
│   ├── README.md                        — инструкции по стенду
│   ├── docker-compose.yml               — OpenSearch + Dashboards + Logstash
│   ├── opensearch/opensearch.yml
│   └── scripts/                         — семплы событий для ручной отправки по TCP
│       ├── send-auditd.sh
│       ├── send-sshd.sh
│       └── send-osquery.sh
│
├── ueba_event_pipeline_map.md           — схема обработки событий (актуальная)
├── README.md
└── .gitignore
```

## Ключевые файлы по темам

| Тема | Файлы | Назначение |
|------|-------|-----------|
| **Пайплайн (прод)** | `logstash/configs/pipeline/ueba-main.conf` | Парсинг и обогащение событий |
| **Конфиги Logstash** | `logstash/configs/logstash.yml`, `pipelines.yml` | Настройки рантайма |
| **Деплой Logstash** | `logstash/deploy/logstash-deploy.yml` | Ansible: docker pull + copy + up |
| **Переменные Logstash** | `logstash/deploy/group_vars/all.yml` | opensearch_url, SSL, image, bind_addr |
| **Конфиги агентов** | `agents/configs/fluent-bit/`, `osquery/`, `auditd/` | Конфиги на целевых машинах |
| **Деплой агентов** | `agents/deploy/agents-deploy.yml` | Ansible: apt repos + install + конфиги |
| **Переменные агентов** | `agents/deploy/group_vars/all.yml` | logstash_host, apt_mirror_url |
| **Dev-стенд** | `dev_stand/docker-compose.yml` | Локальный прогон без агентов |
| **Тестовые события** | `dev_stand/scripts/` | Семплы для nc / socat |

## Инструкции по сокращению токенов

### 1. Поиск по проекту
- **Файлы**: `Glob` с паттерном (напр., `logstash/configs/**/*.conf`)
- **Содержимое**: `Grep` с регулярным выражением вместо чтения всего файла
- **Не читайте без цели**: если нужно найти что-то конкретное — сначала Grep

### 2. Чтение больших конфигов
- Для файлов > 50 строк указывайте `limit` и `offset` в Read
- Используйте **line ranges** в ссылках: `[ueba-main.conf:407-424]`
- Сначала Grep для поиска нужного участка, потом Read 5–10 строк вокруг него

### 3. Параллельное выполнение
- Читайте несвязные файлы в одном вызове Read
- Это уменьшает количество обходов туда-сюда

### 4. Документирование
- **Изменения конфигов**: комментарий в README.md
- **Новые пайплайны**: обновить `ueba_event_pipeline_map.md`
- **Переменные деплоя Logstash**: `logstash/deploy/group_vars/all.yml`
- **Переменные деплоя агентов**: `agents/deploy/group_vars/all.yml`

## Оптимизация для частых операций

### Изменить логику пайплайна Logstash
```
1. Grep в logstash/configs/pipeline/ueba-main.conf: найти нужный блок
2. Read 10–15 строк вокруг найденного
3. Edit — изменить конкретный участок
4. В dev-стенде: cd dev_stand && docker compose restart logstash
5. В проде: cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Изменить правила сбора (fluent-bit / osquery / auditd)
```
1. Read agents/configs/<subsystem>/<file> целиком (все < 200 строк)
2. Edit нужный блок
3. cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

### Развернуть Logstash на новом хосте
```
1. Обновить logstash/deploy/inventory.ini (hostname/IP)
2. Положить CA-сертификат в logstash/deploy/files/opensearch-ca.pem
3. ansible-vault create logstash/deploy/host_vars/<host>.yml (пароль)
4. cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Развернуть агентов на новых VM
```
1. Обновить agents/deploy/inventory.ini
2. Задать logstash_host в agents/deploy/group_vars/all.yml
3. cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass
```

## Команды для быстрого старта

```bash
# Dev-стенд
cd dev_stand
docker compose up -d
docker compose logs -f logstash
bash scripts/send-auditd.sh      # тестовое событие → process-events-*

# Перезапустить Logstash после правки конфига (dev)
docker compose restart logstash

# Проверка индексов OpenSearch
curl -s http://localhost:9200/_cat/indices?v | head -20

# Деплой Logstash в прод (из корня репо)
cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass

# Деплой агентов
cd agents/deploy && ansible-playbook agents-deploy.yml --ask-become-pass

# Syntax-check плейбуков
ansible-playbook --syntax-check logstash/deploy/logstash-deploy.yml
ansible-playbook --syntax-check agents/deploy/agents-deploy.yml
```

## Ключевые метрики

- **OpenSearch индексы**: `host-metrics-*`, `auth-events-*`, `process-events-*`, `config-events-*`, `network-events-*`
- **fluent-bit порты Logstash**: auditd→5045, sshd→5047, osquery→5048, suricata→5049, beats→5044
- **osquery интервалы**: snapshot 30–120 сек, diff 30–120 сек
- **Logstash throughput**: `curl http://localhost:9600/_node/stats` (events.out)

## Что НЕ читать

- `.git/` — используйте `git log` вместо чтения объектов
- `*.log` — используйте `docker compose logs -n 50` или `journalctl -n 50`
- `dev_stand/docker-compose.yml` целиком — ищите сервис по Grep, потом читайте 10 строк

---

**Последнее обновление:** 2026-05-12
**Версия проекта:** refactor/prod-ready
