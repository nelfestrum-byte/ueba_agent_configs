# UEBA dev-стенд

Локальный стенд для разработки и отладки пайплайна Logstash.  
Поднимает OpenSearch + Dashboards + Logstash — без агентских контейнеров.  
Logstash монтирует конфиги из `../logstash/configs/` — те же файлы, что уходят в прод.

## Требования

- Docker 24+ и Docker Compose v2
- 4 GB RAM (2 GB — OpenSearch, 512 MB — Logstash)
- Порты 9200, 5601, 5044–5049 свободны

## Запуск

```bash
cd dev_stand
docker compose up -d
docker compose logs -f logstash   # следить за обработкой
```

Dashboards: http://localhost:5601

## Тестовая отправка событий

Скрипты в `scripts/` шлют JSON-семплы на TCP-порты Logstash через `nc`:

```bash
bash scripts/send-auditd.sh    # auditd SYSCALL → порт 5045
bash scripts/send-sshd.sh      # sshd журнал → порт 5047
bash scripts/send-osquery.sh   # osquery diff → порт 5048
```

После отправки откройте Dashboards → Dev Tools:

```
GET /process-events-*/_search?size=3
GET /auth-events-*/_search?size=3
GET /host-metrics-*/_search?size=3
```

## Остановка

```bash
docker compose down           # остановить, сохранить данные
docker compose down -v        # остановить и удалить тома (сброс данных)
```
