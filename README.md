# UEBA — система сбора и анализа поведения

Два прод-сценария и локальный dev-стенд:

1. **Logstash** — разворачивается на выделенном хосте через Docker, пишет во внешний OpenSearch (HTTPS + Security plugin).
2. **Агенты** — auditbeat, filebeat, osquery на Debian/Ubuntu VM; события идут по beats-протоколу в Logstash.
3. **Dev-стенд** — локальный прогон пайплайна: OpenSearch + Dashboards + Logstash, без агентских контейнеров.

---

## 1. Развертывание Logstash на прод-хосте

### Требования на целевом хосте

- Debian/Ubuntu, Docker 24+, Docker Compose v2
- Пользователь `installer` в группе `docker` (sudo не требуется)
- Доступ к Docker Hub или внутреннему registry (для `docker pull`)
- Сеть: TCP 5044 доступен агентским машинам; 5046 (Windows), 5049 (Suricata) — по необходимости

### Первоначальная настройка (один раз)

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

### Обновление конфигов

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

### Стек агентов

| Сервис | Роль |
|--------|------|
| **auditbeat** | Заменяет auditd демон; читает события ядра через netlink (execve, sudo, auth, файловые изменения) |
| **filebeat** | Читает osquery results.log + /var/log/auth.log (sshd) |
| **osquery** | Источник данных для filebeat (diff: процессы, соединения, пользователи, модули, сервисы) |

### Требования

- Debian/Ubuntu (apt required)
- Пользователь с правами sudo
- auditd и fluent-bit должны быть удалены до деплоя (см. ниже)

### Очистка старого стека (один раз на каждом хосте)

```bash
systemctl stop auditd fluent-bit
systemctl disable auditd fluent-bit
apt remove --purge auditd audispd-plugins fluent-bit -y
rm -rf /etc/audit /etc/fluent-bit /etc/default/fluent-bit
rm -rf /var/lib/fluent-bit /etc/systemd/system/fluent-bit.service.d
systemctl daemon-reload
```

### Первоначальная настройка (один раз)

```bash
cd agents/deploy
cp inventory.ini.example inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
```

Отредактируйте `inventory.ini`:
```ini
[ueba_agents]
agent01  ansible_host=10.0.1.11
agent02  ansible_host=10.0.1.12
```

Отредактируйте `group_vars/all.yml`:
```yaml
logstash_host: 10.0.0.5      # hostname или IP Logstash
elastic_version: "9.4.1"
auditbeat_arch: "amd64"      # или arm64
filebeat_arch:  "amd64"
osquery_version: "5.23.0"
```

### Подготовка пакетов (офлайн-режим)

Скачайте `.deb` на машине с доступом в интернет через Docker:

```powershell
# Windows (Docker Desktop required)
.\agents\deploy\fetch-packages\fetch.ps1

# Указать конкретные версии:
.\agents\deploy\fetch-packages\fetch.ps1 -ElasticVersion 9.4.1 -OsqueryVersion 5.23.0
```

Скрипт положит файлы в `agents/deploy/files/` и покажет, что прописать в `group_vars/all.yml`.

Пакеты (`*.deb`) в git не хранятся.

### Установка

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass
```

Плейбук: добавляет apt-репозитории (или устанавливает из локальных `.deb`) → устанавливает auditbeat, filebeat, osquery → раскладывает конфиги → настраивает keystores → выставляет права доступа → запускает сервисы.

### Проверка на агентской машине

```bash
systemctl status auditbeat filebeat osqueryd

# Проверить соединение с Logstash:
auditbeat test output
filebeat test output

# Логи агентов:
journalctl -u auditbeat -n 30 --no-pager
journalctl -u filebeat  -n 30 --no-pager
```

### Проверка в OpenSearch

```bash
# Через ~60 сек после запуска агентов:
curl -s 'opensearch:9200/_cat/indices?v&index=*-events-*,host-metrics-*' | sort

# Первые события:
# ssh <host>           → auth-events-*    (filebeat system/auth)
# sudo <cmd>           → auth-events-*    (auditbeat auditd, event.action: privilege_use)
# любой execve         → process-events-* (auditbeat auditd)
# osquery diff (60 сек)→ process-events-*, network-events-*, config-events-*
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

Тестирование пайплайна требует реальных агентов, направленных на `<host>:5044`.

Подробнее: [dev_stand/README.md](dev_stand/README.md)

---

## Известные ограничения

- **TLS-сертификаты**: CA-сертификат не отслеживается git'ом — нужно положить вручную перед первым деплоем Logstash.
- **Права пользователя installer**: должен быть в группе `docker`; если нет — включить `ansible_become=true` в `inventory.ini`.
- **Версии пакетов**: в онлайн-режиме устанавливается `latest`; в офлайн-режиме версия определяется скачанным `.deb` файлом.
- **Офлайн-пакеты**: `agents/deploy/files/*.deb` не хранятся в git; при смене версии перезапустите `fetch.ps1` и обновите переменные в `group_vars/all.yml`.
- **auditbeat требует root**: для доступа к audit netlink; конфликтует с auditd демоном — auditd должен быть остановлен и отключён до запуска auditbeat.
- **index templates**: поля ECS (process.args[], user.audit.id, file.hash.sha256) используют динамический маппинг OpenSearch — для прода рекомендуется задать явные index templates.
