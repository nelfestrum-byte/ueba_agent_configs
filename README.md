# UEBA стенд — руководство по запуску

## Структура

```
ueba-stand/
  docker-compose.yml          — основной compose файл (полный стенд)
  opensearch/
    opensearch.yml            — конфиг OpenSearch
  logstash/
    pipeline/ueba-main.conf   — пайплайн нормализации
    config/logstash.yml
    config/pipelines.yml
  fluent-bit/
    fluent-bit.conf           — сбор метрик и логов
    parsers.conf
    flatten.lua               — нормализация osquery
  osquery/
    osquery.conf              — запросы метрик и diff
  auditd/
    audit.rules               — правила аудита Linux
  debian-agent/
    Dockerfile
    entrypoint.sh
    scripts/
      emulator.sh             — эмулятор поведения
  deploy/
    logstash/
      logstash-deploy.yml     — плейбук развертывания Logstash
      inventory.ini           — инвентарь хостов
      ansible.cfg             — настройки Ansible
      group_vars/all.yml      — переменные
      docker-compose.logstash.yml — compose-файл для удаленного хоста
  dist/                       — артефакты сборки (gitignore'd)
    logstash-image.tar.gz     — образ Docker (создается плейбуком)
```

## Требования

- Docker 24+
- Docker Compose v2
- RAM: 4GB минимум (OpenSearch требует 2GB)
- Disk: 5GB свободного места

## Запуск

```bash
# 1. Клонировать / скопировать директорию ueba-stand
cd ueba-stand

# 2. Поднять стенд (первый запуск ~5 мин — скачивание образов)
docker compose up -d

# 3. Следить за запуском
docker compose logs -f

# 4. Дождаться готовности (все сервисы healthy)
docker compose ps
```

## Проверка готовности

```bash
# OpenSearch
curl http://localhost:9200/_cluster/health?pretty

# Logstash
curl http://localhost:9600

# OpenSearch Dashboards
open http://localhost:5601
```

## Эмулятор

```bash
# Нормальная активность (для baseline AD детекторов)
docker compose exec debian-agent bash /scripts/emulator.sh --scenario normal

# Аномальные события (поднимает score)
docker compose exec debian-agent bash /scripts/emulator.sh --scenario anomaly

# Цепочка атаки (критический score)
docker compose exec debian-agent bash /scripts/emulator.sh --scenario attack

# Постепенное наращивание (тест decay)
docker compose exec debian-agent bash /scripts/emulator.sh --scenario buildup

# Все сценарии по очереди
docker compose exec debian-agent bash /scripts/emulator.sh --scenario all

# Повторить аномалию 5 раз
docker compose exec debian-agent bash /scripts/emulator.sh --scenario anomaly --repeat 5
```

## Проверка данных в OpenSearch

Открыть Dev Tools в Dashboards (http://localhost:5601):

```json
// Метрики хоста от osquery
GET host-metrics-*/_search
{ "size": 5, "sort": [{"@timestamp": "desc"}] }

// События аутентификации
GET auth-events-*/_search
{ "size": 5, "sort": [{"@timestamp": "desc"}] }

// Запуски процессов
GET process-events-*/_search
{ "size": 5, "sort": [{"@timestamp": "desc"}] }

// Конфигурационные изменения
GET config-events-*/_search
{ "size": 5, "sort": [{"@timestamp": "desc"}] }

// Все индексы
GET _cat/indices?v&s=index
```

## Порядок настройки AD детекторов

После того как накопится 30+ минут данных normal сценария:

1. Открыть OpenSearch Dashboards → Anomaly Detection
2. Создать детектор:
   - Index: `host-metrics-*`
   - Timestamp: `@timestamp`
   - Category field: `entity_id`
   - Feature: `value`, aggregation: `max`
   - Detector interval: 5 минут
3. Start detector → дать обучиться ~1 час
4. Запустить `anomaly` сценарий → наблюдать `anomaly_grade`

## Остановка стенда

```bash
# Остановить без удаления данных
docker compose down

# Полная очистка (удалить все данные)
docker compose down -v
```

## Развертывание Logstash на удаленном хосте (Ansible)

Плейбук разворачивает Logstash через Docker Compose на хосте без доступа к интернету.
Docker-образ скачивается на хосте управления и передается по SSH.

### Требования

- **Хост управления:** Docker, Ansible 2.12+, SSH-ключ для пользователя `installer`
- **Удаленный хост:** Docker 24+, Docker Compose v2, пользователь `installer` в группе `docker`
  (или `sudo` без пароля — см. комментарии в `ansible/inventory.ini`)

### Первое развертывание

```bash
cd deploy/logstash

# Шаг 1 — подготовить SSH-ключ (если ещё не сделано)
ssh-copy-id installer@10.202.77.81

# Шаг 2 — запустить плейбук
# Плейбук сам скачает образ (~600 MB), сохранит в dist/ и передаст на хост
ansible-playbook logstash-deploy.yml
```

Или из корня проекта:

```bash
ansible-playbook deploy/logstash/logstash-deploy.yml
```

### Обновление конфигов

После правки файлов в `logstash/` достаточно перезапустить плейбук:

```bash
# Из deploy/logstash/
ansible-playbook logstash-deploy.yml

# Или из корня проекта
ansible-playbook deploy/logstash/logstash-deploy.yml
```

Плейбук обнаружит изменения, скопирует обновленные файлы и перезапустит контейнер.
Повторная передача образа **не** происходит — только файлы конфигов.

### Принудительное пересоздание архива образа

```bash
# Из deploy/logstash/
ansible-playbook logstash-deploy.yml -e force_image_rebuild=true

# Или из корня проекта
ansible-playbook deploy/logstash/logstash-deploy.yml -e force_image_rebuild=true
```

### Структура на удаленном хосте после развертывания

```
/opt/ueba-logstash/
  docker-compose.yml
  logstash/
    config/logstash.yml
    config/pipelines.yml
    pipeline/ueba-main.conf
    patterns/
```

### Проверка после развертывания

```bash
# Статус контейнера
ssh installer@10.202.77.81 docker compose -f /opt/ueba-logstash/docker-compose.yml ps

# Логи
ssh installer@10.202.77.81 docker logs ueba-logstash -f

# API Logstash
curl http://10.202.77.81:9600
```

---

## Известные ограничения стенда

- auditd в Docker контейнере работает с ограничениями — часть syscall событий
  может не перехватываться без `--privileged`. Для полного аудита используй VM.
- osquery kernel_modules недоступен внутри контейнера без privileged режима.
- sshd в контейнере пишет в /var/log/auth.log — fluent-bit читает этот файл напрямую.
