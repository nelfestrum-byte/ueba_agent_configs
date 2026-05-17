# P0-03. Auditd syscall rules: io_uring/ptrace/memfd_create/bpf/process_vm

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор по проекту.
- [README_FOR_AI.md](../README_FOR_AI.md), раздел 3 — текущая ECS-схема auditd-источника. Эта задача расширяет таблицу `event.action` пятью новыми значениями.
- [HARDENING_PLAN.md, раздел P0-03](HARDENING_PLAN.md) — обоснование и решения.

## Цель итерации

Добавить в auditd-правила и Lua-enrich пять современных bypass-векторов: `io_uring_setup`, `ptrace`, `process_vm_readv/writev`, `memfd_create`, `bpf`.

**Value сразу, даже без остальных задач:**

- Закрываются 4 класса слепых зон (fileless exec, process injection, BPF-rootkits, io_uring-bypass).
- UEBA получает 5 новых `event.action` значений для скоринга — высокосигнальных, низкошумных.
- На типичном prod-сервере добавит +2-3% к объёму audit.log (workstation до +10% из-за gdb/strace).

Задача **независима** от P0-01, P0-02 — реализуется автономно.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Архитектура целевых хостов** — x86_64 везде или есть arm64?
   - Эти syscall-номера верны для x86_64. Если есть arm64 — нужно сделать второй блок правил с `arch=b32`/`arm64-номерами` (отдельная подзадача, заносим в TODO для P0-03 extension).
2. **Применять `-F auid>=1000 -F auid!=unset` ко всем 5 правилам** (как рекомендовано в плане), или есть исключения, которые пользователь хочет фильтровать иначе?
3. **Готов ли пользователь к небольшому росту объёма на workstation-хостах** (~+10%) или нужно сразу whitelist'ить `gdb`, `strace` и подобные?

## Pre-flight проверки

1. Прочитать [audit.rules](../agents/configs/auditd/audit.rules) полностью — найти блок "Подозрительные пути выполнения" (туда вставлять).
2. Прочитать [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua), строки 6-23 (таблица `SYSCALLS`) и блок категоризации на строках ~176-202 (`elseif sc_name == ...`).
3. Подтвердить номера syscall'ов на тестовом хосте:

   ```bash
   for s in io_uring_setup ptrace process_vm_readv process_vm_writev memfd_create bpf; do
     printf "%-22s = %s\n" "$s" "$(ausyscall x86_64 "$s" 2>/dev/null || echo MISSING)"
   done
   ```

   Ожидаем: `io_uring_setup=425`, `ptrace=101`, `process_vm_readv=310`, `process_vm_writev=311`, `memfd_create=319`, `bpf=321`.

4. Проверить, что блок правил после "Подозрительные пути выполнения" свободен и не конфликтует с уже существующими правилами.

5. Baseline объёма за 24ч ДО внесения правил:

   ```bash
   ansible test-host -m shell -a "wc -l /var/log/audit/audit.log"
   ```

   Запиши значение — после внедрения сравнить.

## Реализация

### Шаг 1. Правила в [audit.rules](../agents/configs/auditd/audit.rules)

Добавить блок после "Подозрительные пути выполнения" (перед "Повышение привилегий"):

```text
# ── Современные bypass-векторы (P0-03) ───────────────────────────────────────
# io_uring — RingReaper-class bypasses, видим только setup (не операции внутри)
-a always,exit -F arch=b64 -S io_uring_setup -F auid>=1000 -F auid!=unset -k io_uring

# Process injection: ptrace + чтение/запись чужой памяти
-a always,exit -F arch=b64 -S ptrace -F auid>=1000 -F auid!=unset -k process_injection
-a always,exit -F arch=b64 -S process_vm_readv,process_vm_writev -F auid>=1000 -F auid!=unset -k process_injection

# Fileless execution через memfd_create (T1620)
-a always,exit -F arch=b64 -S memfd_create -F auid>=1000 -F auid!=unset -k fileless_exec

# Любая загрузка eBPF-программы. ВНИМАНИЕ: при включении P2-01 (osquery BPF backend)
# osqueryd создаст feedback loop — добавить -F exe!=/usr/bin/osqueryd когда P2-01 будет
# в работе. Сейчас фильтр не нужен.
-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=unset -k ebpf_use
```

### Шаг 2. Дополнить SYSCALLS в [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua)

В блоке `local SYSCALLS = {...}` (строки 6-23) добавить:

```lua
["101"]="ptrace",
["310"]="process_vm_readv",
["311"]="process_vm_writev",
["319"]="memfd_create",
["321"]="bpf",
["425"]="io_uring_setup",
```

Можешь поместить их в конец таблицы (после `["322"]="execveat"`), сохраняя стиль.

### Шаг 3. Категоризация event.type/event.category в enrich

В блоке `if sc_name == "execve" or ...` (строки ~176-202) добавить ветки:

```lua
elseif sc_name == "ptrace"
    or sc_name == "process_vm_readv"
    or sc_name == "process_vm_writev" then
    record["event.type"]     = "change"
    record["event.category"] = "process"
elseif sc_name == "memfd_create" then
    record["event.type"]     = "creation"
    record["event.category"] = "process"
elseif sc_name == "bpf" then
    record["event.type"]     = "info"
    record["event.category"] = "process"
elseif sc_name == "io_uring_setup" then
    record["event.type"]     = "info"
    record["event.category"] = "process"
```

Вставлять перед закрывающим `end` блока if/elseif sc_name.

### Шаг 4. Раскатка через Ansible

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass --limit=test-host --tags=auditd,fluent-bit
```

После раскатки на тестовом хосте проверить:

```bash
ansible test-host -m shell -a "auditctl -l | grep -E 'io_uring|ptrace|memfd|bpf' | wc -l"
# Ожидаем: 5
```

### Шаг 5. Триггер-тесты

Запустить на test-хосте под обычным (non-root, auid >= 1000) пользователем:

```bash
# memfd_create
python3 -c "import os; fd = os.memfd_create('test', 0); os.close(fd)"

# ptrace (через strace — он использует ptrace под капотом)
strace -e trace=none -- /bin/true

# bpf (загрузка тривиальной программы — нужен root, поэтому через sudo)
sudo bpftool prog load /dev/null /sys/fs/bpf/test 2>/dev/null || true

# io_uring (нужен short C-loader — собрать в /tmp)
cat > /tmp/iouring_test.c <<'EOF'
#include <sys/syscall.h>
#include <unistd.h>
int main() { syscall(425, 8, (void *)0); return 0; }
EOF
gcc /tmp/iouring_test.c -o /tmp/iouring_test && /tmp/iouring_test
```

Через 10 секунд проверить в OpenSearch:

```bash
curl -s 'http://localhost:9200/fluent-audit-*/_search?size=20' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"terms":{"auditd.key":["io_uring","process_injection","fileless_exec","ebpf_use"]}},"sort":[{"@timestamp":"desc"}]}' \
  | jq '.hits.hits[]._source | {key: .["auditd.key"], action: .["event.action"], cat: .["event.category"]}'
```

Должно быть минимум 4 документа с правильно заполненными `event.action` (имя syscall) и `event.category=process`.

### Шаг 6. Замер дельты объёма

Через 24 часа после раскатки на test-хосте:

```bash
ansible test-host -m shell -a "wc -l /var/log/audit/audit.log"
```

Сравнить с baseline. Если рост > +10% на сервере или > +20% на workstation — есть проблема. Скорее всего — Chrome/IDE генерируют много memfd_create на workstations. Решение: whitelist через `-F exe!=` (отдельная подзадача, не блокирующая).

## Что НЕ делать в этой итерации

- **НЕ добавлять `io_uring_enter`/`io_uring_register`.** Только `io_uring_setup`. Остальное — тысячи событий на один setup без дополнительного сигнала.
- **НЕ добавлять whitelist для osqueryd `-F exe!=/usr/bin/osqueryd`.** Это нужно ТОЛЬКО когда будет включён P2-01 (osquery BPF backend). Сейчас bpf-правило без whitelist'а корректно ловит ручные `bpftool`/`bcc` вызовы. Закомментировать намерение в audit.rules (как показано в Шаге 1).
- **НЕ трогать arm64.** Если есть arm64-хосты — указать в финальном отчёте, что нужна отдельная подзадача "P0-03 arm64 extension".
- **НЕ переименовывать существующие audit ключи.** Только добавление новых: `io_uring`, `process_injection`, `fileless_exec`, `ebpf_use`.
- **НЕ создавать триггер-плейбук.** Это P1-04. Здесь — только ручной smoke.

## Проверка готовности

Из [HARDENING_PLAN.md P0-03 → Критерий готовности](HARDENING_PLAN.md):

- `auditctl -l | grep -E 'io_uring|ptrace|memfd|bpf'` — 5 правил.
- Триггер `python3 -c "import os; os.memfd_create('x', 0)"` → событие с `event.action=memfd_create`, `auditd.key=fileless_exec`.
- Аналогичные триггеры для остальных 4 ключей дают `event.action=<syscall_name>` и `event.category=process`.
- Объём `audit.log` после включения вырос не более чем на +2-3% на типичном prod-сервере (workstation допустимо до +10%).

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел **3.1** ("Что собирается"): добавить пункты — io_uring_setup, ptrace + process_vm_readv/writev, memfd_create, bpf.
   - Раздел **3.4** ("Типичные event.action для UEBA"): добавить строки:

     ```
     | `memfd_create` | Fileless execution; в baseline почти нет → высокий скор |
     | `ptrace` | Process injection; редко вне debugger'ов → подозрение |
     | `process_vm_writev` | Memory injection; критичный сигнал |
     | `bpf` | Загрузка eBPF-программы; rootkit-индикатор |
     | `io_uring_setup` | Использование io_uring; редко на prod-серверах → flag |
     ```

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе "Известные особенности и грабли" добавить пункт про P2-01 cross-task требование: "Когда будет включаться osquery BPF backend (P2-01), обязательно добавить `-F exe!=/usr/bin/osqueryd` к auditd-правилу `bpf` — иначе feedback loop".

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P0-03 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить:**

   ```
   P0-03: auditd rules for modern bypass vectors

   - audit.rules: io_uring, ptrace, process_vm_readv/writev, memfd_create, bpf
   - auditd_enrich.lua: 6 new SYSCALLS entries + event categorization
   - All rules filtered by auid>=1000 to skip kernel/systemd noise
   - Verified on test-host: 5 rules loaded, all triggers produce ECS events
   - README_FOR_AI: extended event.action UEBA table
   - CLAUDE.md: noted P2-01 cross-dependency on bpf rule
   ```

5. **Сообщить пользователю**: 5 правил активны, измеренная дельта объёма, есть ли необходимость whitelist'инга на workstation, готов следующий шаг (P1-01 / P1-04).
