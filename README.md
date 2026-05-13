# UEBA — система сбора и анализа поведения

Два прод-сценария и локальный dev-стенд:

1. **Logstash** — разворачивается на выделенном хосте через Docker, пишет во внешний OpenSearch (HTTPS + Security plugin).
2. **Агенты** — osquery, fluent-bit, auditd на Debian/Ubuntu VM; события идут по TCP в Logstash.
3. **Dev-стенд** — локальный прогон пайплайна: OpenSearch + Dashboards + Logstash, без агентских контейнеров.

---

## 1. Развертывание Logstash на прод-хосте

### Требования на целевом хосте

- Debian/Ubuntu, Docker 24+, Docker Compose v2
- Пользователь `installer` в группе `docker` (sudo не требуется)
- Доступ к Docker Hub или внутреннему registry (для `docker pull`)
- Сеть: TCP 5044–5049 доступны агентским машинам

### Первоначальная настройка (один раз)

Файлы `inventory.ini` и `group_vars/all.yml` не хранятся в репозитории — создайте их из примеров:

```bash
cd logstash/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
```

Отредактируйте `inventory.ini` — укажите целевой хост:
```ini
[logstash]
logstash-prod  ansible_host=10.0.0.5
```

Отредактируйте `group_vars/all.yml` — укажите параметры вашего OpenSearch:
```yaml
opensearch_url: "https://opensearch.prod.example.com:9200"
opensearch_user: "logstash_writer"
# logstash_bind_addr: 10.0.0.5  # раскомментировать для биндинга на конкретный интерфейс
```

**CA-сертификат OpenSearch** — положить в `logstash/deploy/files/opensearch-ca.pem` (gitignore'd).

**Пароль OpenSearch** — сохранить через ansible-vault:
```bash
ansible-vault create logstash/deploy/host_vars/<hostname>.yml
# Содержимое файла: opensearch_password: "<пароль>"
```

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

## 2. Развертывание агентов на Debian/Ubuntu VM

### Требования

- Debian/Ubuntu (apt required)
- Пользователь `deploy` с правами sudo
- Доступ к Debian-репозиторию (базовые пакеты)
- Для osquery и fluent-bit: интернет к `pkg.osquery.io` / `packages.fluentbit.io`
  **или** офлайн-установка из локальных `.deb` (см. ниже)

### Первоначальная настройка (один раз)

Файлы `inventory.ini` и `group_vars/all.yml` не хранятся в репозитории — создайте их из примеров:

```bash
cd agents/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
```

Отредактируйте `inventory.ini` — укажите VM:
```ini
[ueba_agents]
agent01  ansible_host=10.0.1.11
agent02  ansible_host=10.0.1.12
```

Отредактируйте `group_vars/all.yml` — укажите адрес Logstash:
```yaml
logstash_host: 10.0.0.5   # hostname или IP хоста с Logstash
```

Для внутреннего зеркала apt — раскомментировать и заполнить:
```yaml
apt_mirror_url: http://mirror.example.local/apt
osquery_apt_repo_url: "{{ apt_mirror_url }}/osquery"
fluent_bit_apt_repo_url: "{{ apt_mirror_url }}/fluent-bit"
```

### Офлайн-установка (vendor-репозитории недоступны)

Если целевые VM не имеют доступа к `pkg.osquery.io` / `packages.fluentbit.io`,
скачайте пакеты на машине с доступом через Docker:

```powershell
# Windows (Docker Desktop required)
.\agents\deploy\fetch-packages\fetch.ps1

# Если fluent-bit для trixie недоступен — взять из bookworm
.\agents\deploy\fetch-packages\fetch.ps1 -FbDist bookworm
```

Скрипт соберёт образ `debian:trixie`, скачает `.deb` и положит их в `agents/deploy/files/`.
После этого включите офлайн-режим в `group_vars/all.yml`:

```yaml
use_local_packages: true
osquery_local_deb: "osquery_5.12.1-1.linux_amd64.deb"   # точное имя из files/
fluent_bit_local_deb: "fluent-bit_3.3.5_amd64.deb"
```

Плейбук скопирует `.deb` на целевые VM и установит через `apt` (зависимости из Debian-репо).
Файлы `*.deb` не хранятся в git.

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

- **TLS-сертификаты**: CA-сертификат не отслеживается git'ом — нужно положить вручную перед первым деплоем Logstash.
- **Права пользователя installer**: должен быть в группе `docker`; если нет — включить `ansible_become=true` в `inventory.ini`.
- **Версии пакетов**: в онлайн-режиме устанавливается `latest`; в офлайн-режиме версия определяется скачанным `.deb` файлом.
- **Офлайн-пакеты**: `agents/deploy/files/*.deb` не хранятся в git; при смене версии перезапустите `fetch.ps1` и обновите имена в `group_vars/all.yml`.
- **auditd в контейнерах**: полный аудит syscall требует привилегированного режима; dev-стенд не эмулирует агентские машины.
