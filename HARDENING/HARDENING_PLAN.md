# HARDENING_PLAN — план улучшения UEBA-stand

Подробное описание реализованных задач v0.9: [docs/RELEASE_NOTES_0.9.md](../docs/RELEASE_NOTES_0.9.md).

## Шкала приоритетов

- **P0** — критично для UEBA-скоринга или закрытие современного bypass-вектора.
- **P1** — стабильность, безопасность канала, гигиена данных.
- **P2** — расширение покрытия.
- **P3** — CI/lint/fuzz, технический долг.
- **P4 (Extras)** — расширения за пределы core hardening. Не входят в основной план.

---

## Выполнено в v0.9

| ID | Задача | Дата | Описание |
|----|--------|------|----------|
| P0-01 | `process.entity_id` + `process.parent.entity_id` | 2026-05-18 | FNV-1a(host:pid:start_time) — стабильный ID процесса, переключается при PID reuse; LRU-кэш pid→start_time |
| P0-02 | `user.session.id` — сквозной ID сессии | 2026-05-18 | FNV-1a(host:btime:ses) — совпадает auditd↔osquery для одного логина |
| ~~P0-03~~ | ~~SSH pipeline (filebeat)~~ | Удалено | Дублировало auditd; последний коммит `960bdb2`, удалено в `6aeaf16` |
| P0-04 | Auditd syscall rules: bypass vectors | 2026-05-22 | io_uring, ptrace, process_vm, memfd_create, bpf |
| P1-01 | Neo23x0 gap-analysis Tier A + Tier B | 2026-05-22 | 12+16 правил: anti-forensics, persistence, container escape, timestomp, supply chain |
| P1-02 | ECS Index Templates v2.0 | 2026-05-22 | fluent-audit-*, fluent-osquery-*; ip/wildcard/constant_keyword типы |
| P2-01 | osquery BPF backend + container.entity_id | 2026-05-21 | bpf_process_events, bpf_socket_events, docker_containers; container_cache в enrich |
| P2-02 | Расширение osquery-запросов | 2026-05-21 | shell_history, last_logins, preload_envs, packages, kernel_keys, acpi, suspicious_mmap, browser extensions |

---

## Текущий backlog

### QA-FIX-13. execve: PROCTITLE leakage → command_line мисматч

**Приоритет:** P0 (ломает UEBA-скоринг по cmdline)  
**Стоимость:** 5 мин (одна строка)  
**Статус:** не начато  
**Промпт:** [QA-FIX-13-execve-cmdline-proctitle.md](../testing/QA-FIX-13-execve-cmdline-proctitle.md)  
**Суть:** 650+ execve событий имеют `process.command_line="runc init"` при несовпадающем exe/args. Убрать `if not record["process.command_line"]` условие — EXECVE-args всегда точнее PROCTITLE.

---

### QA-FIX-14. USER_CMD: user.name / command_line / event.action отсутствуют + DAEMON_START без action

**Приоритет:** P0 (sudo-мониторинг слеп)  
**Стоимость:** ~1 ч  
**Статус:** не начато  
**Промпт:** [QA-FIX-14-user-cmd-fields.md](../testing/QA-FIX-14-user-cmd-fields.md)  
**Суть:** 166 user_cmd событий без user.name/target/cmdline (uid_name/auid_name не берутся для USER_* типов; cmd= hex из inner msg не парсится). Плюс 9 host событий без event.action (DAEMON_START не обработан).

---

### QA-FIX-15. setuid/setgid: user.target.id отсутствует

**Приоритет:** P1 (privilege escalation tracking неполный)  
**Стоимость:** ~2 ч (правки merge.lua + enrich.lua + index template)  
**Статус:** не начато  
**Промпт:** [QA-FIX-15-iam-user-target-id.md](../testing/QA-FIX-15-iam-user-target-id.md)  
**Суть:** Syscall аргументы a0/a1/a2 не извлекаются из SYSCALL-записи → целевой UID после setuid неизвестен. Нужно сохранить sc_a0/a1/a2 в merge.lua и декодировать в enrich.lua.

---

### QA-FIX-16. osquery bpf_socket nonip: network.type отсутствует

**Приоритет:** P1 (AF_UNIX / AF_NETLINK неразличимы)  
**Стоимость:** 5 мин (три строки)  
**Статус:** не начато  
**Промпт:** [QA-FIX-16-osquery-nonip-network-type.md](../testing/QA-FIX-16-osquery-nonip-network-type.md)  
**Суть:** В else-ветке bpf_sockets (non-IP) не выставляется `network.type`. Добавить `if fam=="1" then "unix" elseif fam=="16" then "netlink" ...` после реклассификации category.

---

### P1-03. mTLS канал fluent-bit → Logstash

**Приоритет:** P1 (безопасность канала)  
**Стоимость:** ~1 день  
**Статус:** не начато  
**Промпт:** [P1-03-mtls-channel.md](P1-03-mtls-channel.md)

### Зачем

Сейчас fluent-bit отправляет события в Logstash через **plaintext TCP** (5045 audit, 5047 osquery). Риски: перехват событий (имена пользователей, команды, IP), инъекция фейковых событий в SIEM, нет аутентификации источника.

mTLS закрывает всё разом: шифрование + двусторонняя аутентификация (server-cert на Logstash + client-cert на каждом агенте).

### Что делать

**1. PKI.** Self-signed CA или использовать internal CA:
- Корневой CA-cert + key — хранится в `agents/deploy/files/ca/` (gitignored), резервная копия offline.
- Server-cert для Logstash (CN = hostname, SAN с IP).
- Client-certs per-host для агентов (CN = agent hostname).

**2. Logstash side** — [logstash/configs/pipeline/ueba-main.conf](../logstash/configs/pipeline/ueba-main.conf), к каждому `tcp` input:
```text
ssl_enabled => true
ssl_certificate => "/etc/logstash/certs/server.crt"
ssl_key => "/etc/logstash/certs/server.key"
ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
ssl_verify_mode => "force_peer"
```

**3. fluent-bit side** — [agents/configs/fluent-bit/fluent-bit.conf](../agents/configs/fluent-bit/fluent-bit.conf), к каждому OUTPUT tcp:
```ini
tls               on
tls.verify        on
tls.ca_file       /etc/fluent-bit/certs/ca.crt
tls.crt_file      /etc/fluent-bit/certs/client.crt
tls.key_file      /etc/fluent-bit/certs/client.key
```

**4. Ansible:** [logstash/deploy/logstash-deploy.yml](../logstash/deploy/logstash-deploy.yml) — копирует server-cert; [agents/deploy/agents-deploy.yml](../agents/deploy/agents-deploy.yml) — копирует per-host client-cert.

**5.** `.gitignore` — добавить `agents/deploy/files/ca/`, `agents/deploy/files/clients/`.

### Точки изменений

- `logstash/configs/pipeline/ueba-main.conf`
- `agents/configs/fluent-bit/fluent-bit.conf`
- `logstash/deploy/logstash-deploy.yml`
- `agents/deploy/agents-deploy.yml`
- `.gitignore`

### Критерий готовности

- `tcpdump -A 'port 5045'` на агенте: виден только TLS-payload, plaintext JSON отсутствует.
- `openssl s_client -connect logstash:5045 -cert client.crt -key client.key` подключается; без cert — Logstash отвергает.
- Индексы продолжают расти (smoke).

### Грабли

- fluent-bit не перезагружает TLS-материал на лету — после замены cert нужен `systemctl reload fluent-bit`.
- NTP обязателен: без синхронизации TLS handshake падает по validity.
- Logstash в Docker: volume-mount `/etc/logstash/certs/`, проверить UID процесса.
- CA private key — только в Ansible Vault или вне репозитория, никогда в git.
- Mixed-state переход: Logstash на одном порту не умеет одновременно plain + TLS. Решение: параллельный порт `5045-tls` при раскатке, затем снос `5045-plain`.

---

### P1-04. auditd-trigger.yml — тестовый плейбук срабатываний

**Приоритет:** P1 (защита от регрессов)  
**Стоимость:** ~1 день  
**Статус:** не начато  
**Промпт:** [P1-04-auditd-trigger-playbook.md](P1-04-auditd-trigger-playbook.md)  
**Зависимости:** после P0-04 и P1-01 Tier A — чтобы покрыть все ключи разом.

### Зачем

End-to-end smoke: правило в audit.rules → kernel → audit.log → fluent-bit merge → enrich → Logstash → OpenSearch → ECS-документ. Аналог уже существующего [tests/osquery/osquery-trigger.yml](../tests/osquery/osquery-trigger.yml). Без него любая правка в audit.rules или enrich — игра "проверим в проде".

### Что делать

Создать `tests/auditd/auditd-trigger.yml` с тегами `apply` / `assert` / `rollback`.

Минимальный набор триггеров:

| Действие | Ожидаемый ключ |
|----------|----------------|
| `useradd test-aud && userdel -f test-aud` | `user_changes` |
| `sudo -u nobody true` | `sudo_exec` |
| `python3 -c "import os; os.memfd_create('x', 0)"` | `fileless_exec` |
| C-loader `ptrace(PTRACE_TRACEME)` | `process_injection` |
| C-loader `bpf(BPF_PROG_LOAD)` | `ebpf_use` |
| C-loader `io_uring_setup` | `io_uring` |
| `touch /tmp/x && touch -d '2020-01-01' /tmp/x` | `timestomp` |
| `unshare -U /bin/bash` | `container_escape` |
| `echo test >> /etc/ld.so.preload; rm /etc/ld.so.preload` | `preload_inject` |
| Триггеры под Tier A правил P1-01 | каждый соответствующий ключ |

**Структура:**
- Tag `apply` — выполняет триггеры последовательно.
- Tag `assert` — ждёт ~10 сек propagation, проверяет через OpenSearch `_search` наличие документов с ожидаемым `auditd.key`.
- Tag `rollback` — чистит созданное, `failed_when: false` для каждого cleanup.
- C-loaders для ptrace/bpf/io_uring — компилируются на месте через `gcc` inline, лежат в `tests/auditd/fixtures/`.

### Точки изменений

- Новый каталог `tests/auditd/` с `auditd-trigger.yml` и `fixtures/`.
- Возможно общий helper OpenSearch assertion в `tests/_lib/`.

### Критерий готовности

- `ansible-playbook tests/auditd/auditd-trigger.yml --tags apply,assert` на dev-хосте: все assert зелёные за < 60 секунд.
- `--tags rollback` идемпотентен (повторный запуск не падает на отсутствии артефактов).

### Грабли

- Race condition propagation: между триггером и проверкой ~5-10 сек (merge 2 сек + Logstash batch + OpenSearch refresh). Заложить `wait_for` или explicit `sleep 10`.
- ptrace/bpf через Python ctypes — ненадёжно из-за seccomp. Лучше C-loader.
- Module loading требует unsigned-load разрешения — документировать в требованиях к тест-хосту.
- `userdel -f` если пользователь залогинен во время теста.

---

### P3-01. Unit-тесты Lua-скриптов

**Приоритет:** P3 (отложено)  
**Стоимость:** ~1 день  
**Статус:** не начато  
**Триггер для возврата:** появление бага в merge/enrich, который не заметили при ревью; либо 3+ правки Lua подряд без тестов.

### Зачем

Lua-фильтры — самый хрупкий узел стека. Регресс там не падает шумно, а тихо ломает ECS-поля. `auditd_merge.lua` держит stateful буфер по serial; `auditd_enrich.lua` и `osquery_enrich.lua` делают много табличных преобразований.

### Подход

Lua 5.1 + busted в Docker-образе `nickblah/lua:5.1-luajit-alpine` (тот же LuaJIT, что у fluent-bit). Запуск: `docker run --rm -v $PWD:/work -w /work <image> busted tests/lua/spec`.

### Структура

```
tests/lua/
  Dockerfile
  run.sh
  spec/
    auditd_merge_spec.lua
    auditd_enrich_spec.lua
    osquery_enrich_spec.lua
  fixtures/
    auditd/{execve_simple, execve_no_eoe, sudo_cmd, serial_split}.lua
    osquery/{process_added, socket_added}.lua
  helpers/
    load_script.lua    # мокает io.popen до dofile
    ecs_assert.lua
```

### Минимальный набор сценариев

**auditd_merge:** одиночный execve → один merged; полная серия SYSCALL+EXECVE+PATH+CWD+PROCTITLE; серия без EOE (auditd 4.x) → timeout-флаш; два overlapping serial → два независимых документа.

**auditd_enrich:** syscall→event.action (execve/connect/setuid); file.path (absolute + relative+CWD); event.outcome из `success=yes/no`; очистка служебных полей.

**osquery_enrich:** processes → `process.*` маппинг; diff-action added/removed → event.action.

### Грабли

- `_hostname` кэш через `io.popen("hostname -f")` — мокать до `dofile()`, иначе зависимость от реального хоста.
- Не брать PUC-Rio Lua 5.1 или lua:5.4 — поведение `bit32`/`tostring` отличается от LuaJIT.
- Фикстуры писать с реального fluent-bit (`out_file`), не синтезировать руками.

---

### P3-02. CI: статический анализ + syntax-check

**Приоритет:** P3 (гигиена)  
**Стоимость:** ~4 часа  
**Статус:** не начато

### Что делать

Workflow в `.github/workflows/lint.yml`:

| Проверка | Команда |
|----------|---------|
| Lua | `luacheck agents/configs/fluent-bit/scripts/*.lua` |
| Ansible syntax | `ansible-playbook --syntax-check logstash/deploy/logstash-deploy.yml agents/deploy/agents-deploy.yml` |
| fluent-bit config | `fluent-bit --dry-run -c fluent-bit.conf` (в Docker) |
| Logstash pipeline | `logstash -t -f ueba-main.conf` (в Docker) |
| osquery config | `osqueryi --config_path=osquery.conf.j2 --config_check` (после рендера) |
| JSON templates | `python -m json.tool opensearch/templates/*.json` |
| YAML | `yamllint logstash/ agents/` |

Базовый `.luacheckrc` в корне: разрешить `_ENV`, fluent-bit globals, отключить line-length warnings.

### Критерий готовности

- PR со сломанным Lua — CI красный с понятным сообщением.
- PR с валидными изменениями — зелёный, < 2 минут.

---

### P3-03. Property-based fuzz для merge-buffer

**Приоритет:** P3 (edge-case защита)  
**Стоимость:** ~0.5 дня  
**Статус:** не начато  
**Зависимости:** требует P3-01 (Lua-runner в Docker).

### Зачем

`auditd_merge.lua` собирает auditd-серии по serial. Kernel пишет последовательно, но fluent-bit читает чанками — порядок записей внутри пакета произвольный. Инвариант: **итоговый merged-документ независим от порядка прихода строк одной серии**.

### Что делать

Скрипт `tests/property/merge_fuzz.lua`:
1. Зафиксировать "канонический" merged-результат для SYSCALL+EXECVE+PATH+CWD+PROCTITLE.
2. Сгенерировать N=1000 случайных перестановок.
3. Проверить: все 1000 результатов изоморфны каноническому.
4. Вторая property: timeout-флаш разделяет серии правильно (два документа при искусственном sleep > timeout).

### Критерий готовности

- 1000 перестановок без расхождений с каноническим.
- В CI — опционально (`--with-property` только на main или вручную).

### Грабли

- Сравнение "изоморфно" — рекурсивное по ключам, не `==` таблиц.
- `PROCTITLE` обычно идёт последней в реальном auditd-выводе; перестановки с ней в начале — синтетика, задокументировать как known limitation.

---

## P4 — Extras (за пределами core roadmap)

Описаны в [CONTAINER_BEHAVIOR_PLAN.md](CONTAINER_BEHAVIOR_PLAN.md):
- OpenSearch Anomaly Detection (RCF) по `container.entity_id`
- Alerting rule-based сигналы → `ueba-signals-*`
- DNS-видимость контейнеров
- Container-to-container трафик (overlay network)
