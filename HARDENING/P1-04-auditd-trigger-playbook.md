# P1-04. auditd-trigger.yml — тестовый плейбук срабатываний правил

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор.
- [README_FOR_AI.md](../README_FOR_AI.md), разделы 3.1 и 3.4 — какие auditd-ключи и event.action существуют в системе.
- Существующий аналог: [tests/osquery/osquery-trigger.yml](../tests/osquery/osquery-trigger.yml) — структура apply/rollback/assert тегов. Прочитать целиком, использовать как template.
- [HARDENING_PLAN.md, раздел P1-04](HARDENING_PLAN.md) — таблица триггеров, грабли (race condition propagation, lockdown kernel).

## Цель итерации

Создать `tests/auditd/auditd-trigger.yml` — Ansible-плейбук, который:

1. Запускает действия, гарантированно триггерящие каждое auditd-правило (apply).
2. Через OpenSearch `_search` проверяет, что событие с ожидаемым `auditd.key` появилось в `fluent-audit-*` за окно 10 секунд (assert).
3. Откатывает созданные артефакты idempotently (rollback).

**Value сразу:**

- Любая правка `audit.rules` или `auditd_enrich.lua` верифицируется одной командой `ansible-playbook tests/auditd/auditd-trigger.yml --tags apply,assert`.
- Регрессы в end-to-end цепочке (kernel → fluent-bit → Logstash → OpenSearch → ECS) ловятся до прод-раскатки.
- Аналог уже работающего [osquery-trigger.yml](../tests/osquery/osquery-trigger.yml), команда привыкла к этому формату.

**Независимая ценность:** работает уже сейчас на существующих ключах audit.rules; покрытие новых ключей (P0-03, P1-01) добавляется по мере их появления — без блокировки.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **На каком тестовом хосте гонять плейбук?**
   - Из `agents/deploy/inventory.ini` — название группы или конкретного хоста.
   - Должно быть НЕ workstation пользователя (rollback может задеть существующих юзеров с именами `test-aud`).
2. **Какие из P0-03 / P1-01 правил уже сделаны?** Это влияет на то, какие триггеры включать в плейбук:
   - Если P0-03 сделан — триггер для memfd_create / ptrace / bpf / io_uring обязателен.
   - Если P1-01 сделан — триггеры для Tier A (mount/unshare/etc) обязательны.
3. **Включать ли C-loaders** для ptrace/bpf/io_uring сразу или сделать минимальную версию без них (Python-ctypes часто работает, хоть и менее надёжно)?
   - **Recommended:** включить minimal C-loaders, компилируются один раз на месте через gcc heredoc.

## Pre-flight проверки

1. Прочитать [tests/osquery/osquery-trigger.yml](../tests/osquery/osquery-trigger.yml) полностью — взять оттуда:
   - Структуру tags (apply/assert/rollback).
   - Способ обращения к OpenSearch (если уже есть — переиспользовать; если нет — добавить новый).
   - Стиль idempotent rollback (`failed_when: false`).

2. Прочитать [audit.rules](../agents/configs/auditd/audit.rules) — собрать актуальный список существующих `-k <key>` значений. Только под них пишем триггеры (не задним числом для несуществующих).

3. Проверить, что на тестовом хосте:
   - `gcc` доступен (для C-loaders),
   - kernel lockdown НЕ установлен в integrity/confidentiality (иначе `insmod` для module_load триггера упадёт):

     ```bash
     ansible test-host -m shell -a "cat /sys/kernel/security/lockdown 2>/dev/null"
     ```

     Ожидаем `[none]` (квадратные скобки вокруг "none") либо файл отсутствует.

4. Подтвердить доступ к OpenSearch (URL/credentials/CA-cert) для assert-этапа. Если P1-03 (mTLS) сделан и Logstash защищён, OpenSearch обычно отдельный — проверить отдельно.

## Реализация

### Шаг 1. Создать каталог и базовую структуру

```bash
mkdir -p tests/auditd/fixtures
touch tests/auditd/auditd-trigger.yml
```

### Шаг 2. Скелет плейбука

`tests/auditd/auditd-trigger.yml`:

```yaml
---
# Тестовый плейбук срабатываний auditd-правил.
# Гарантирует end-to-end: kernel → audit.log → fluent-bit → Logstash → OpenSearch.
#
# Запуск:
#   ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
#     --tags apply,assert --limit=test-host --ask-become-pass
#
# Откат:
#   ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
#     --tags rollback --limit=test-host --ask-become-pass
#
- name: Auditd trigger tests
  hosts: all
  become: yes
  gather_facts: yes

  vars:
    # OpenSearch endpoint (переопределить в group_vars или -e)
    opensearch_url: "https://opensearch.example.com:9200"
    opensearch_user: admin
    opensearch_password: "{{ vault_opensearch_password }}"
    opensearch_ca: "{{ playbook_dir }}/../../logstash/deploy/files/opensearch-ca.pem"

    # Window для assertion: время propagation (audit.log → fluent-bit merge timeout=2с →
    # Logstash batch ~1с → OpenSearch refresh 1с). +5с запас.
    assert_window_sec: 10
    assert_query_window: "now-1m"

    # Тестовый пользователь — должен быть уникальным
    test_user: "aud-trig-test"

    # Каталог для C-loaders
    fixture_dir: "/tmp/auditd-trigger-fixtures"

  tasks:
    # ════════════════════════════════════════════════════════════════════
    # APPLY: запуск триггеров
    # ════════════════════════════════════════════════════════════════════

    - name: Prepare fixture dir
      ansible.builtin.file:
        path: "{{ fixture_dir }}"
        state: directory
        mode: '0755'
      tags: [apply]

    # ── Trigger: user_changes ─────────────────────────────────────────
    - name: "[apply] Create test user (trigger: user_changes)"
      ansible.builtin.user:
        name: "{{ test_user }}"
        state: present
      tags: [apply, key_user_changes]

    # ── Trigger: sudo_exec ─────────────────────────────────────────────
    - name: "[apply] Run sudo trivial (trigger: sudo_exec)"
      ansible.builtin.command: sudo -u nobody true
      changed_when: false
      tags: [apply, key_sudo_exec]

    # ── Trigger: ssh_keys ─────────────────────────────────────────────
    - name: "[apply] Generate SSH keypair (trigger: ssh_keys)"
      ansible.builtin.command: ssh-keygen -t ed25519 -f /tmp/aud-trig-key -N ""
      args: { creates: /tmp/aud-trig-key }
      tags: [apply, key_ssh_keys]
    - name: "[apply] Add key to root authorized_keys"
      ansible.builtin.shell: |
        mkdir -p /root/.ssh && cat /tmp/aud-trig-key.pub >> /root/.ssh/authorized_keys
      args: { executable: /bin/bash }
      tags: [apply, key_ssh_keys]

    # ── Trigger: tmp_write + suspicious_exec ──────────────────────────
    - name: "[apply] Write SUID-like file to /tmp (trigger: tmp_write)"
      ansible.builtin.shell: |
        touch /tmp/aud-trig-suid && chmod 4755 /tmp/aud-trig-suid
      args: { executable: /bin/bash }
      tags: [apply, key_tmp_write]
    - name: "[apply] Copy and execute from /tmp (trigger: suspicious_exec)"
      ansible.builtin.shell: |
        cp /usr/bin/true /tmp/aud-trig-bin && /tmp/aud-trig-bin
      args: { executable: /bin/bash }
      tags: [apply, key_suspicious_exec]

    # ── Trigger: socket_bind, socket_listen ───────────────────────────
    - name: "[apply] Bind+listen on 127.0.0.1 (trigger: socket_bind, socket_listen)"
      ansible.builtin.shell: |
        python3 -c "
        import socket
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        s.close()
        "
      tags: [apply, key_socket_bind, key_socket_listen]

    # ── Trigger: fileless_exec (memfd_create) — нужен P0-03 ──────────
    - name: "[apply] memfd_create (trigger: fileless_exec) [P0-03]"
      ansible.builtin.command: python3 -c "import os; fd=os.memfd_create('aud-trig', 0); os.close(fd)"
      changed_when: false
      tags: [apply, key_fileless_exec, p0_03]

    # ── Trigger: process_injection (ptrace) — нужен P0-03 ────────────
    # strace использует ptrace под капотом
    - name: "[apply] ptrace via strace (trigger: process_injection) [P0-03]"
      ansible.builtin.command: strace -f -e trace=none -- /bin/true
      changed_when: false
      tags: [apply, key_process_injection, p0_03]

    # ── Trigger: ebpf_use (bpf) — нужен P0-03 ────────────────────────
    # Минимальный C-loader, который вызывает bpf(BPF_PROG_LOAD) с заведомо
    # неверной программой — syscall срабатывает, kernel вернёт EINVAL, audit пишет.
    - name: "[apply] Compile bpf-loader C fixture"
      ansible.builtin.copy:
        dest: "{{ fixture_dir }}/bpf_loader.c"
        content: |
          #include <linux/bpf.h>
          #include <sys/syscall.h>
          #include <unistd.h>
          int main() {
              union bpf_attr attr = {0};
              syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
              return 0;
          }
        mode: '0644'
      tags: [apply, key_ebpf_use, p0_03]
    - name: "[apply] Build bpf-loader"
      ansible.builtin.command: gcc -o {{ fixture_dir }}/bpf_loader {{ fixture_dir }}/bpf_loader.c
      args: { creates: "{{ fixture_dir }}/bpf_loader" }
      tags: [apply, key_ebpf_use, p0_03]
    - name: "[apply] Run bpf-loader (trigger: ebpf_use) [P0-03]"
      ansible.builtin.command: "{{ fixture_dir }}/bpf_loader"
      changed_when: false
      failed_when: false  # syscall возвращает -1, это ожидаемо
      tags: [apply, key_ebpf_use, p0_03]

    # ── Trigger: io_uring (io_uring_setup) — нужен P0-03 ─────────────
    - name: "[apply] Compile io_uring-loader C fixture"
      ansible.builtin.copy:
        dest: "{{ fixture_dir }}/iouring_loader.c"
        content: |
          #include <sys/syscall.h>
          #include <unistd.h>
          int main() {
              syscall(425, 8, (void *)0);  // io_uring_setup; вернёт -1, нам нужен сам syscall
              return 0;
          }
        mode: '0644'
      tags: [apply, key_io_uring, p0_03]
    - name: "[apply] Build io_uring-loader"
      ansible.builtin.command: gcc -o {{ fixture_dir }}/iouring_loader {{ fixture_dir }}/iouring_loader.c
      args: { creates: "{{ fixture_dir }}/iouring_loader" }
      tags: [apply, key_io_uring, p0_03]
    - name: "[apply] Run io_uring-loader (trigger: io_uring) [P0-03]"
      ansible.builtin.command: "{{ fixture_dir }}/iouring_loader"
      changed_when: false
      failed_when: false
      tags: [apply, key_io_uring, p0_03]

    # ── Триггеры P1-01 Tier A (раскомментировать после внедрения P1-01) ───
    # - name: "[apply] mount tmpfs (trigger: mount_action) [P1-01]"
    #   ansible.builtin.shell: mount -t tmpfs none /tmp/aud-trig-mnt && umount /tmp/aud-trig-mnt
    #   tags: [apply, key_mount_action, p1_01]
    # - name: "[apply] unshare new pid namespace (trigger: container_escape) [P1-01]"
    #   ansible.builtin.command: unshare --pid --fork /bin/true
    #   tags: [apply, key_container_escape, p1_01]
    # - name: "[apply] touch /etc/ld.so.preload (trigger: preload_inject) [P1-01]"
    #   ansible.builtin.file: { path: /etc/ld.so.preload, state: touch }
    #   tags: [apply, key_preload_inject, p1_01]

    # ════════════════════════════════════════════════════════════════════
    # ASSERT: проверка через OpenSearch
    # ════════════════════════════════════════════════════════════════════

    - name: "[assert] Wait for propagation"
      ansible.builtin.pause:
        seconds: "{{ assert_window_sec }}"
      tags: [assert]

    - name: "[assert] Query OpenSearch for each expected key"
      ansible.builtin.uri:
        url: "{{ opensearch_url }}/fluent-audit-*/_count"
        method: POST
        body_format: json
        body:
          query:
            bool:
              must:
                - term: { "auditd.key": "{{ item }}" }
                - range:
                    "@timestamp":
                      gte: "{{ assert_query_window }}"
        user: "{{ opensearch_user }}"
        password: "{{ opensearch_password }}"
        force_basic_auth: yes
        ca_path: "{{ opensearch_ca }}"
        return_content: yes
      register: assert_results
      loop:
        - user_changes
        - sudo_exec
        - ssh_keys
        - tmp_write
        - suspicious_exec
        - socket_bind
        - socket_listen
        # Если P0-03 сделан:
        - fileless_exec
        - process_injection
        - ebpf_use
        - io_uring
      failed_when: assert_results.json.count | int < 1
      tags: [assert]

    - name: "[assert] Summary"
      ansible.builtin.debug:
        msg: "Key '{{ item.item }}' → {{ item.json.count }} document(s) in last minute"
      loop: "{{ assert_results.results }}"
      loop_control: { label: "{{ item.item }}" }
      tags: [assert]

    # ════════════════════════════════════════════════════════════════════
    # ROLLBACK: чистка
    # ════════════════════════════════════════════════════════════════════

    - name: "[rollback] Remove test user"
      ansible.builtin.user:
        name: "{{ test_user }}"
        state: absent
        remove: yes
        force: yes
      failed_when: false
      tags: [rollback]

    - name: "[rollback] Remove SSH test key from authorized_keys"
      ansible.builtin.lineinfile:
        path: /root/.ssh/authorized_keys
        regexp: 'aud-trig-key'
        state: absent
      failed_when: false
      tags: [rollback]

    - name: "[rollback] Remove test artifacts"
      ansible.builtin.file:
        path: "{{ item }}"
        state: absent
      loop:
        - /tmp/aud-trig-key
        - /tmp/aud-trig-key.pub
        - /tmp/aud-trig-suid
        - /tmp/aud-trig-bin
        - "{{ fixture_dir }}"
        - /etc/ld.so.preload  # ТОЛЬКО если был создан плейбуком — проверить вручную!
      failed_when: false
      tags: [rollback]
```

**ВНИМАНИЕ:** Удаление `/etc/ld.so.preload` в rollback — рискованно (на проде он может существовать осмысленно). Сделать через `lineinfile` с regexp по тестовому содержимому, либо вообще не удалять, а оставлять пустой touch как rollback. На dev-стенде это OK.

### Шаг 3. Запуск smoke

```bash
cd tests/auditd
# С минимальным набором (без P0-03/P1-01 ключей если они ещё не сделаны):
ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
  --limit=test-host --tags=apply,assert --ask-become-pass --ask-vault-pass \
  --skip-tags=p0_03,p1_01
```

Все assert-таски должны вернуть `count >= 1` для соответствующих ключей.

Затем чистый rollback:

```bash
ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
  --limit=test-host --tags=rollback --ask-become-pass
```

Двойной запуск rollback должен пройти без ошибок (idempotent).

### Шаг 4. Документация

Создать `tests/auditd/README.md` с описанием:

- Когда запускать (после правок audit.rules или enrich.lua).
- Как ограничивать выполнение тегами (`--tags=key_<name>` для одного триггера).
- Известные ограничения (lockdown kernel, NTP, OpenSearch access).

## Что НЕ делать в этой итерации

- **НЕ интегрировать в CI** (gitlab/github actions) автоматический запуск этого плейбука. Это P3-02 задача. Сейчас — ручной запуск разработчиком.
- **НЕ покрывать триггерами правила, которых ЕЩЁ нет в audit.rules.** Только существующие + P0-03 + P1-01 (если сделаны). Если правило `mount_action` ещё не добавлено — соответствующий task закомментирован (как показано в скелете).
- **НЕ делать через CI/контейнер.** Этот плейбук гоняется на настоящем bare-metal/VM хосте, потому что многие триггеры требуют kernel-level операций (insmod, bpf, io_uring), которые не работают в Docker без extra capabilities.
- **НЕ удалять `/etc/ld.so.preload` в rollback** без явного указания, что он был создан плейбуком. На production может быть legit-содержимое.
- **НЕ заводить в плейбук триггеры P3-01 / P2-x правил** — это уже за пределами P1-04.

## Проверка готовности

Из [HARDENING_PLAN.md P1-04 → Критерий готовности](HARDENING_PLAN.md):

- `ansible-playbook tests/auditd/auditd-trigger.yml --tags apply,assert` на dev-стенде: все assertion-таски зелёные за <60 секунд (включая 10-секундный pause).
- `--tags rollback` чисто откатывает; повторный запуск idempotent.
- Каждый существующий audit-ключ покрыт триггером.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - В разделе 8 ("Файлы, критичные для AI-агентов") добавить строку: `tests/auditd/auditd-trigger.yml` — Ansible-плейбук для верификации end-to-end auditd-пайплайна.

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе "Оптимизация для частых операций" добавить под-раздел "Проверить auditd-пайплайн после правок":

     ```bash
     cd tests/auditd
     ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
       --tags=apply,assert --limit=test-host --ask-become-pass --ask-vault-pass
     ansible-playbook -i ../../agents/deploy/inventory.ini auditd-trigger.yml \
       --tags=rollback --limit=test-host --ask-become-pass
     ```

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P1-04 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить:**

   ```
   P1-04: auditd-trigger.yml end-to-end test playbook

   - tests/auditd/auditd-trigger.yml with apply/assert/rollback tags
   - Triggers for existing keys (user_changes, sudo_exec, ssh_keys, tmp_write,
     suspicious_exec, socket_bind/listen) + P0-03 keys (fileless_exec,
     process_injection, ebpf_use, io_uring) + P1-01 keys (commented until done)
   - C-loaders for bpf and io_uring under fixtures/
   - OpenSearch _count assertion with 10s propagation pause
   - Idempotent rollback (failed_when: false on cleanup)
   - README_FOR_AI: added to critical files list
   - CLAUDE.md: usage in frequent-ops section
   ```

5. **Сообщить пользователю**: плейбук работает, какие ключи покрыты прямо сейчас, какие ждут раскомментирования после P0-03 / P1-01.
