# P1-03. mTLS канал fluent-bit → Logstash

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор.
- [README_FOR_AI.md](../README_FOR_AI.md) — справочник; раздел 2 (Архитектура) обновится с указанием TLS на портах.
- [HARDENING_PLAN.md, раздел P1-03](HARDENING_PLAN.md) — обоснование, грабли, PKI-стратегия.

## Цель итерации

Обернуть все TCP-входы Logstash (5045 audit, 5047 osquery, 5048 system-auth) в **mTLS**: TLS-шифрование + клиентская аутентификация по сертификату. Без cert/ключа подключение к Logstash отвергается.

**Value сразу:**

- Закрывается перехват `json_lines` событий в plaintext (включает командные строки пользователей, source IP).
- Закрывается возможность инъекции фейковых событий в SIEM от третьих лиц с доступом к сети.
- Появляется аутентификация источника: Logstash отличает легитимного агента от посторонних.

**Независимая ценность:** даже без других задач плана — канал становится безопасным сегодня.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Есть ли в инфраструктуре internal CA?**
   - Да — использовать её, получить server-cert для Logstash + client-cert per-host.
   - Нет — создать self-signed CA на control-node (внутри Ansible Vault или вне git).
2. **Стратегия rollout** для переходного периода (часть агентов с TLS, часть без)?
   - **Recommended:** временно второй порт (5045-tls на 5145, 5047-tls на 5147, 5048-tls на 5148) параллельно plain, потом переключение и снос plain.
   - Альтернатива: одномоментный rollout всех агентов через Ansible parallel forks (рискованнее, требует window).
3. **Срок действия client-certs:** 1 год / 2 года / другой?
4. **TLS на каких портах** — все три (5045, 5047, 5048) или только активные на момент работы (например, если P0-02 ещё не сделан, 5048 не нужен)?

## Pre-flight проверки

1. Проверить, что openssl установлен на control-node:

   ```bash
   openssl version
   ```

2. Проверить версию Logstash на dev-стенде:

   ```bash
   docker compose -f dev_stand/docker-compose.yml exec logstash logstash --version
   ```

   `tcp { ssl_enabled => true ... }` поддерживается на Logstash >= 7.x. Если используется старая версия — проверить синтаксис (`ssl_enable` vs `ssl_enabled`).

3. Проверить, что NTP активен на агентах (TLS чувствителен к расхождению времени):

   ```bash
   ansible all -m shell -a "timedatectl | grep -E 'NTP|synchronized'"
   ```

4. Снимок текущего входящего трафика на Logstash (для сравнения "до/после"):

   ```bash
   curl -s http://logstash-host:9600/_node/stats/pipeline | jq '.pipelines.main.events.in'
   ```

## Реализация

### Шаг 1. Создать PKI (если нет internal CA)

На control-node, в `agents/deploy/files/ca/` (gitignored):

```bash
mkdir -p agents/deploy/files/ca agents/deploy/files/server agents/deploy/files/clients
cd agents/deploy/files/ca

# Корневой CA (10 лет)
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=UEBA Stack CA/O=UEBA/C=RU" -days 3650

# Server cert для Logstash (1 год; CN = hostname Logstash)
LOGSTASH_HOST=logstash.your-domain.example
cd ../server
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=${LOGSTASH_HOST}/O=UEBA"
openssl x509 -req -in server.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile <(printf "subjectAltName=DNS:${LOGSTASH_HOST},IP:<LOGSTASH_IP>")
rm server.csr

# Client cert на каждый хост (1 год; CN = inventory_hostname)
cd ../clients
for HOST in $(ansible all --list-hosts | tail -n +2); do
  openssl req -newkey rsa:2048 -nodes -keyout "${HOST}.key" -out "${HOST}.csr" \
    -subj "/CN=${HOST}/O=UEBA-agent"
  openssl x509 -req -in "${HOST}.csr" -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial \
    -out "${HOST}.crt" -days 365
  rm "${HOST}.csr"
done
```

**Обеспечить .gitignore:**

```text
# В .gitignore (если не покрыто)
agents/deploy/files/ca/
agents/deploy/files/server/
agents/deploy/files/clients/
```

CA-key — **критичный секрет**, копию хранить offline (внешний носитель / vault).

### Шаг 2. Logstash side — обернуть TCP-input в TLS

В [logstash/configs/pipeline/ueba-main.conf](../logstash/configs/pipeline/ueba-main.conf) к каждому TCP-input добавить:

```text
input {
  tcp {
    port  => 5045
    codec => json_lines
    ssl_enabled => true
    ssl_certificate => "/etc/logstash/certs/server.crt"
    ssl_key         => "/etc/logstash/certs/server.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    ssl_verify_mode => "force_peer"
    tags => ["fluent-bit", "auditd"]
  }
}
```

То же для 5047 (osquery) и 5048 (system-auth, если P0-02 сделан).

**Альтернатива на переходный период (если выбран dual-port rollout):** добавить параллельные ssl-input на портах 5145/5147/5148, оставив plain 5045/5047/5048. После полной раскатки клиентов — удалить plain.

### Шаг 3. Logstash deploy — копирование сертификатов

В [logstash/deploy/logstash-deploy.yml](../logstash/deploy/logstash-deploy.yml) добавить task'и:

```yaml
- name: Create Logstash certs dir
  ansible.builtin.file:
    path: /etc/logstash/certs
    state: directory
    owner: 1000          # logstash UID в official image
    group: 1000
    mode: '0750'

- name: Copy CA + server cert/key
  ansible.builtin.copy:
    src: "{{ playbook_dir }}/files/{{ item.src }}"
    dest: "/etc/logstash/certs/{{ item.dest }}"
    owner: 1000
    group: 1000
    mode: "{{ item.mode }}"
  loop:
    - { src: 'ca/ca.crt',         dest: 'ca.crt',     mode: '0644' }
    - { src: 'server/server.crt', dest: 'server.crt', mode: '0644' }
    - { src: 'server/server.key', dest: 'server.key', mode: '0600' }
  notify: Restart Logstash
```

Если Logstash в Docker — пробросить volume `/etc/logstash/certs:/etc/logstash/certs:ro` в [logstash/deploy/docker-compose.yml](../logstash/deploy/docker-compose.yml).

### Шаг 4. fluent-bit side — TLS в OUTPUT

В [agents/configs/fluent-bit/fluent-bit.conf](../agents/configs/fluent-bit/fluent-bit.conf) к каждому `[OUTPUT] tcp` добавить TLS-параметры:

```ini
[OUTPUT]
    Name              tcp
    Match             audit.*
    Host              ${LOGSTASH_HOST}
    Port              5045
    Format            json_lines
    json_date_format  iso8601
    json_date_key     @timestamp
    tls               on
    tls.verify        on
    tls.ca_file       /etc/fluent-bit/certs/ca.crt
    tls.crt_file      /etc/fluent-bit/certs/client.crt
    tls.key_file      /etc/fluent-bit/certs/client.key
```

То же для outputs на 5047, 5048.

### Шаг 5. Agents deploy — распространение per-host сертификатов

В [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml):

```yaml
- name: Create fluent-bit certs dir
  ansible.builtin.file:
    path: /etc/fluent-bit/certs
    state: directory
    owner: fluent-bit
    group: fluent-bit
    mode: '0750'

- name: Copy CA + client cert/key for this host
  ansible.builtin.copy:
    src: "{{ playbook_dir }}/files/{{ item.src }}"
    dest: "/etc/fluent-bit/certs/{{ item.dest }}"
    owner: fluent-bit
    group: fluent-bit
    mode: "{{ item.mode }}"
  loop:
    - { src: 'ca/ca.crt',                       dest: 'ca.crt',      mode: '0644' }
    - { src: 'clients/{{ inventory_hostname }}.crt', dest: 'client.crt', mode: '0644' }
    - { src: 'clients/{{ inventory_hostname }}.key', dest: 'client.key', mode: '0600' }
  notify: Restart fluent-bit
```

**Failsafe**: pre-task проверить, что нужный per-host cert существует:

```yaml
- name: Verify client cert exists for host
  ansible.builtin.stat:
    path: "{{ playbook_dir }}/files/clients/{{ inventory_hostname }}.crt"
  delegate_to: localhost
  register: client_cert_stat
- name: Fail if client cert missing
  ansible.builtin.fail:
    msg: "Client cert for {{ inventory_hostname }} missing in files/clients/. Generate it first."
  when: not client_cert_stat.stat.exists
```

### Шаг 6. Smoke на dev-стенде

```bash
# 1. Раскатать обе стороны
ansible-playbook logstash/deploy/logstash-deploy.yml --tags ssl --ask-vault-pass
ansible-playbook agents/deploy/agents-deploy.yml --limit=test-host --ask-become-pass --tags ssl

# 2. Проверить, что входящие соединения шифрованы
ansible test-host -m shell -a "ss -tn | grep ':5045' | head -3"
# Активные соединения должны быть

ansible test-host -m shell -a "timeout 5 tcpdump -i any -A 'port 5045' 2>/dev/null | head -50"
# Не должно быть plain-JSON; видим только TLS handshake байты

# 3. Проверить отказ без сертификата
ansible test-host -m shell -a "openssl s_client -connect ${LOGSTASH_HOST}:5045 -CAfile /etc/fluent-bit/certs/ca.crt </dev/null 2>&1 | tail -10"
# Должна быть ошибка SSL alert (без -cert/-key)

# 4. Проверить, что события доходят в индексы
curl -s 'http://localhost:9200/fluent-audit-*/_count?q=@timestamp:[now-5m+TO+now]' | jq '.count'
# Должно быть > 0 (приход не сломан)
```

### Шаг 7. Раскатка по флоту

После 1-2 часов наблюдения на test-хосте — раскатить на остальные:

```bash
ansible-playbook agents/deploy/agents-deploy.yml --ask-become-pass --tags ssl
```

## Что НЕ делать в этой итерации

- **НЕ хранить CA private key в git.** Никогда. Pre-commit hook на проверку — не лишним, но это отдельная подзадача.
- **НЕ менять Format с `json_lines` на `forward`/`beats`.** Принято в плане: минимум вмешательства, формат остаётся.
- **НЕ добавлять Vault для сертификатов** на этой итерации. Файлы лежат в `agents/deploy/files/`, gitignored. Vault — отдельная задача.
- **НЕ настраивать автоматическую ротацию** сертификатов (cert-manager / step-ca / acme). Сейчас — 1 год вручную; автоматизация в будущем.
- **НЕ переключать beats 5044** на TLS. Этот порт не используется агентами (закладка под winlogbeat), его трогать не надо.
- **НЕ задавать `ssl_verify_mode => "peer"`** (только верификация, без принуждения). Используем `force_peer` — обязательная клиентская аутентификация.

## Проверка готовности

Из [HARDENING_PLAN.md P1-03 → Критерий готовности](HARDENING_PLAN.md):

- `tcpdump -A 'port 5045'` показывает только TLS handshake байты, plaintext JSON отсутствует.
- `openssl s_client -connect logstash:5045 -CAfile ca.crt -cert client.crt -key client.key` подключается; без cert — `SSL alert` в Logstash логах.
- В индексах `fluent-audit-*`, `fluent-osquery-*`, `system-auth-*` события продолжают появляться (smoke).
- `output_errors_total{name="tcp"}` в метриках fluent-bit остаётся 0.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел 2 (Архитектура пайплайна): обновить таблицу — указать "TLS" на портах 5045/5047/5048.
   - Добавить новый раздел "TLS / PKI" (рядом с разделом 7 или 8): где лежат CA/server/client сертификаты, какой алгоритм/срок, что обязательно при добавлении нового хоста.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - Добавить раздел/пункт "TLS канал" в "Известные особенности и грабли": NTP обязателен; CA-key не в git; ротация раз в год вручную; при добавлении нового агента — выпустить cert и положить в `agents/deploy/files/clients/`.
   - В "Команды для быстрого старта" добавить:

     ```bash
     # Выпустить client-cert для нового хоста <name>:
     bash agents/deploy/files/issue-client-cert.sh <name>
     ```

     (опционально создать этот helper-скрипт, если хочется автоматизации; пока — описать команду openssl в CLAUDE.md).

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P1-03 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить** (CA private key НЕ коммитить!):

   ```
   P1-03: mTLS for fluent-bit → Logstash channel

   - Self-signed CA + server cert + per-host client certs (gitignored)
   - Logstash ueba-main.conf: ssl_enabled=true with force_peer mode on 5045/5047/5048
   - fluent-bit: tls on with verify on all OUTPUT tcp
   - Ansible: deploy certs as part of logstash-deploy and agents-deploy
   - Verified on test-host: encrypted handshake, plaintext rejection, no event loss
   - .gitignore: agents/deploy/files/{ca,server,clients}/
   - README_FOR_AI: added TLS/PKI section
   - CLAUDE.md: TLS gotchas + new-host enrollment doc
   ```

5. **Сообщить пользователю**: канал зашифрован, аутентификация принудительная, дата истечения сертификатов (через год); добавить календарное напоминание о ротации.
