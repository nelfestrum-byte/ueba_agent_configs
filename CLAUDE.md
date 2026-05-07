# CLAUDE.md — UEBA Stand проект

**Цель:** минимизировать потребление токенов через оптимизированную навигацию по проекту и точные инструкции.

## Структура проекта

```
ueba-stand/                          — UEBA система сбора и анализа поведения
├── docker-compose.yml               — основной compose (полный стенд)
├── README.md                        — инструкции запуска
├── ueba_event_pipeline_map.md       — схема обработки событий
│
├── opensearch/                      — хранилище данных (ElasticSearch-compatible)
│   └── opensearch.yml               — конфигурация индексов и кластера
│
├── logstash/                        — ETL pipeline (нормализация логов)
│   ├── config/logstash.yml          — основной конфиг
│   ├── config/pipelines.yml         — определение пайплайнов
│   ├── pipeline/ueba-main.conf      — ГЛАВНЫЙ файл обработки событий
│   └── patterns/                    — grok-паттерны парсинга
│
├── fluent-bit/                      — агент сбора логов и метрик
│   ├── fluent-bit.conf              — сбор sys/app логов
│   ├── parsers.conf                 — парсеры для fluent-bit
│   └── flatten.lua                  — нормализация osquery JSON
│
├── osquery/                         — agentless сбор системных метрик
│   └── osquery.conf                 — запросы и интервалы
│
├── auditd/                          — Linux аудит (syscall события)
│   └── audit.rules                  — правила аудита
│
├── debian-agent/                    — Docker контейнер-эмулятор
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── scripts/emulator.sh          — генератор поведения (normal/anomaly/attack)
│
├── deploy/logstash/                 — Ansible плейбуки развертывания на удаленном хосте
│   ├── logstash-deploy.yml          — основной плейбук (Docker + SSH)
│   ├── inventory.ini                — хосты для развертывания
│   ├── ansible.cfg
│   └── group_vars/all.yml           — переменные плейбука
│
└── _offline-bundle/                 — пакеты для offline развертывания
    └── deploy.yml                   — Ansible плейбук для offline install
```

## Ключевые файлы по темам

| Тема | Файлы | Назначение |
|------|-------|-----------|
| **Сбор данных** | `fluent-bit/`, `osquery/osquery.conf` | Агенты на целевом хосте |
| **Обработка/нормализация** | `logstash/pipeline/ueba-main.conf` | Парсинг и обогащение событий |
| **Хранилище** | `opensearch/opensearch.yml` | Индексирование и поиск |
| **Эмуляция поведения** | `debian-agent/scripts/emulator.sh` | Генерирует события для тестирования |
| **Развертывание** | `deploy/logstash/logstash-deploy.yml` | Автоматизирует setup на удаленных хостах |

## Инструкции по сокращению токенов

### 1. Поиск по проекту
- **Ищите файлы** перед чтением: `Glob` для файлов по паттерну (напр., `*.yml` или `**/*logstash*`)
- **Ищите в содержимом**: `Grep` с регулярным выражением вместо чтения всего файла
- **Не читайте без цели**: если нужно найти что-то конкретное, используйте поиск

### 2. Чтение больших конфигов
- Для файлов > 50 строк указывайте `limit` и `offset` в Read: `Read(..., limit=20, offset=10)`
- Используйте **line ranges** в ссылках: `[logstash config:20-40]`
- При необходимости прочитать весь файл: используйте Grep сначала, чтобы найти нужный участок

### 3. Стандартные паттерны работы
- **Конфиги**: используйте Grep для поиска параметра, потом Read 5 строк вокруг него
- **Логика обработки**: читайте в `ueba_event_pipeline_map.md` вместо разбора кода
- **Структура данных**: смотрите в README под "Проверка данных" (примеры индексов)

### 4. Параллельное выполнение
- Читайте несвязные файлы (разные модули) в одном вызове Read
- Grep по разным файлам в одном вызове
- Это уменьшает обходы туда-сюда

### 5. Документирование
- **Изменения конфигов**: добавляйте комментарий в README.md о новом параметре
- **Новые пайплайны**: обновляйте `ueba_event_pipeline_map.md`
- **Переменные развертывания**: документируйте в `deploy/logstash/group_vars/all.yml`

### 6. Что НЕ читать
- `dist/` — это временные артефакты (gitignore'd)
- `.git/` — используйте `git log` вместо чтения объектов
- `*.log` файлы — используйте `tail` в Bash если нужны последние строки
- `docker-compose.yml` целиком — ищите сервис по Grep, потом читайте 10 строк

## Git workflow

- **branch**: `master` — это основная ветка (нет других веток)
- **коммиты**: смотрите `git log --oneline` для истории
- **изменения**: `git diff` перед коммитом для проверки

## Оптимизация для частых операций

### Добавить переменную в Logstash пайплайн
```
1. Grep в logstash/pipeline/ueba-main.conf: если параметр уже есть
2. Если нет — Read нужную секцию (10 строк), добавить переменную
3. Обновить deploy/logstash/group_vars/all.yml если это параметр развертывания
```

### Изменить правила сбора (fluent-bit/osquery)
```
1. Read fluent-bit.conf или osquery.conf целиком (они < 100 строк)
2. Modify нужный блок
3. Протестировать через docker compose exec
```

### Развернуть на новом хосте
```
1. Обновить deploy/logstash/inventory.ini (hostname/IP)
2. Обновить deploy/logstash/group_vars/all.yml если параметры другие
3. Запустить ansible-playbook
```

## Команды для быстрого старта
```bash
# Просмотр активных сервисов и их логов
docker compose ps
docker compose logs -f logstash

# Проверка конкретного пайплайна (без перезагрузки)
grep -n "if \[source_type\]" logstash/pipeline/ueba-main.conf

# Просмотр индексов в OpenSearch
curl -s http://localhost:9200/_cat/indices?v | head -20

# Перезапустить только Logstash после изменения конфига
docker compose restart logstash
```

## Ключевые метрики для понимания
- **OpenSearch indices**: `host-metrics-*`, `auth-events-*`, `process-events-*`, `config-events-*`
- **Fluent-bit sources**: syslog, access.log, auth.log, auditd
- **osquery intervals**: обычно 30-60 сек для host-metrics
- **Logstash throughput**: смотрите на http://localhost:9600 (events processed)

---

**Последнее обновление:** 2026-05-07  
**Версия проекта:** initial commit (bb6ff15)
