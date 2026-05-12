# UEBA — система сбора и анализа поведения

Два прод-сценария и локальный dev-стенд:

1. **Logstash** — разворачивается на выделенном хосте через Docker, пишет в внешний OpenSearch (HTTPS + Security plugin).
2. **Агенты** — osquery, fluent-bit, auditd на Debian 12 VM; события идут по TCP в Logstash.
3. **Dev-стенд** — локальный прогон пайплайна: OpenSearch + Dashboards + Logstash, без агентских контейнеров.

---

## 1. Развертывание Logstash на прод-хосте

### Требования на целевом хосте

- Debian/Ubuntu, Docker 24+, Docker Compose v2
- Пользователь `installer` в группе `docker` (sudo не требуется)
- Доступ к Docker Hub или внутреннему registry (для `docker pull`)
- Сеть: TCP 5044–5049 доступны агентским машинам

### Подготовка

1. **CA-сертификат OpenSearch** — положить в `logstash/deploy/files/opensearch-ca.pem` (gitignore'd).

2. **Пароль OpenSearch** — сохранить через ansible-vault:
   ```bash
   ansible-vault create logstash/deploy/host_vars/<hostname>.yml
   # Содержимое: opensearch_password: "<пароль>"
   ```

3. **Инвентарь** — указать целевой хост в `logstash/deploy/inventory.ini`:
   ```ini
   [logstash]
   logstash-prod  ansible_host=10.0.0.5
   ```

4. **Переменные** — проверить `logstash/deploy/group_vars/all.yml`:
   - `opensearch_url` — HTTPS-эндпоинт OpenSearch
   - `opensearch_user` — пользователь для записи индексов
   - `logstash_bind_addr` — интерфейс для биндинга портов (по умолчанию `0.0.0.0`)

### Первое развертывание

```bash
cd logstash/deploy
ansible-playbook logstash-deploy.yml --ask-vault-pass
```

Плейбук создаст `~/ueba-logstash/` на целевом хосте, скопирует конфиги, CA-сертификат, `.env` и запустит контейнер через `docker compose up -d`.

### Обновление конфигов

Повторный запуск плейбука достаточен: он обнаружит изменённые файлы и перезапустит контейнер автоматически.

```bash
# Изменить logstash/configs/pipeline/ueba-main.conf, затем:
cd logstash/deploy && ansible-playbook logstash-deploy.yml --ask-vault-pass
```

### Проверка после деплоя

```bash
# На целевом хосте:
docker ps --filter name=ueba-logstash
curl -sf http://localhost:9600/_node/stats | python3 -m json.tool | grep -A2 '"events"'
```

---

## 2. Развертывание агентов на Debian VM

### Требования

- Debian 12 (bookworm)
- Пользователь `deploy` с правами sudo
- Интернет-доступ к `pkg.osquery.io` и `packages.fluentbit.io`
  (или внутреннее зеркало — см. `apt_mirror_url` ниже)

### Настройка

1. **Инвентарь** — указать VM в `agents/deploy/inventory.ini`:
   ```ini
   [ueba_agents]
   agent01  ansible_host=10.0.1.11
   agent02  ansible_host=10.0.1.12
   ```

2. **Переменные** в `agents/deploy/group_vars/all.yml`:
   - `logstash_host` — hostname или IP Logstash-хоста
   - `apt_mirror_url` — (опционально) внутреннее зеркало apt:
     ```yaml
     apt_mirror_url: http://mirror.example.local/apt
     osquery_apt_repo_url: "{{ apt_mirror_url }}/osquery"
     fluent_bit_apt_repo_url: "{{ apt_mirror_url }}/fluent-bit"
     ```

### Установка

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

Плейбук: добавляет apt-репозитории → устанавливает osquery, fluent-bit, auditd → раскладывает конфиги из `agents/configs/` → настраивает systemd → запускает сервисы.

### Проверка на агентской машине

```bash
systemctl status osqueryd
systemctl status fluent-bit
systemctl status auditd

# Убедиться, что события доходят до Logstash:
journalctl -u fluent-bit -n 20 --no-pager
```

### Проверка в OpenSearch

```
GET /process-events-*/_count
GET /auth-events-*/_count
GET /host-metrics-*/_count
```

---

## 3. Локальный dev-стенд

Только для разработки и отладки пайплайна Logstash — без агентских контейнеров.

```bash
cd dev_stand
docker compose up -d
docker compose logs -f logstash
```

Dashboards: http://localhost:5601

Тестовая отправка событий:
```bash
bash dev_stand/scripts/send-auditd.sh    # → process-events-*
bash dev_stand/scripts/send-sshd.sh      # → auth-events-*
bash dev_stand/scripts/send-osquery.sh   # → config-events-*
```

Подробнее: [dev_stand/README.md](dev_stand/README.md)

---

## Известные ограничения

- **TLS-сертификаты**: CA-сертификат не отслеживается git'ом — нужно вручную разложить перед первым деплоем Logstash.
- **Права пользователя installer**: должен быть в группе `docker`; если нет — включить `ansible_become=true` в inventory.
- **Версии пакетов**: по умолчанию устанавливается latest из репозитория; чтобы зафиксировать — раскомментировать `osquery_version` / `fluent_bit_version` в `agents/deploy/group_vars/all.yml`.
- **auditd в контейнерах**: полный аудит syscall требует привилегированного режима; dev-стенд не эмулирует агентские машины.
