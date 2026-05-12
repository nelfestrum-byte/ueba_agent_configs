# Logstash — продакшн-развертывание

Logstash разворачивается на удаленном bare-metal хосте через Docker Compose и
пишет в продовый OpenSearch (TLS + Security plugin).

## Где что лежит

| Что | Где | Чем читается |
|---|---|---|
| URL/пользователь OpenSearch | `group_vars/all.yml` (`opensearch_url`, `opensearch_user`) | плейбук → `.env` через `templates/.env.j2` |
| Пароль OpenSearch | `host_vars/<host>.yml` (ansible-vault) | плейбук → `.env`, `no_log: true` |
| CA-сертификат OpenSearch | `files/opensearch-ca.pem` (gitignored) | копируется в `{{ deploy_dir }}/certs/` |
| Bind-адрес портов приёма | `group_vars/all.yml` (`logstash_bind_addr`) | подставляется в `docker-compose.yml` |

## Как .env попадает в контейнер

`templates/.env.j2` → рендерится в `{{ deploy_dir }}/.env` (mode 0600).
`docker-compose.yml` указывает `env_file: .env` — переменные становятся доступны
в Logstash как `${OPENSEARCH_URL}`, `${OPENSEARCH_USER}`, `${OPENSEARCH_PASSWORD}`,
`${OPENSEARCH_CA_CERT}` и используются в `output { opensearch { ... } }`.

## Первая раскатка

```bash
# 1. Положить реальный CA-сертификат
cp /path/to/opensearch-ca.pem deploy/logstash/files/opensearch-ca.pem

# 2. Создать host_vars с паролем под vault
ansible-vault create deploy/logstash/host_vars/<host>.yml
# в файле: opensearch_password: "<пароль>"

# 3. Раскатить
ansible-playbook deploy/logstash/logstash-deploy.yml --ask-vault-pass
```

Повторные запуски плейбука обновляют конфиги, `.env` или CA и перезапускают
контейнер только при их изменении.
