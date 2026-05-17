# P1-01. Gap-анализ audit.rules против Neo23x0 ruleset (Tier A + Tier B)

## Контекст для AI

Ты — AI-ассистент в проекте UEBA-стенда. Перед началом работы ОБЯЗАТЕЛЬНО прочитай:

- [CLAUDE.md](../CLAUDE.md) — навигатор.
- [README_FOR_AI.md](../README_FOR_AI.md), раздел 3 — текущая схема auditd. Эта задача добавит ~26 новых audit-ключей.
- [HARDENING_PLAN.md, раздел P1-01](HARDENING_PLAN.md) — **обязательно**, там полные Tier A/B/C списки правил с готовыми формулировками и обоснованиями.

## Цель итерации

Добавить в [audit.rules](../agents/configs/auditd/audit.rules) 12 правил Tier A (высокий сигнал) и 14 правил Tier B (средний сигнал), отобранные cherry-pick из эталонного ruleset Neo23x0/auditd. Дополнить таблицу `SYSCALLS` в [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) номерами новых syscall'ов.

**Value сразу:**

- Закрываются persistence-векторы (LD_PRELOAD, ld.so.conf, init/rc.local, env, shell profiles, fstab, udev).
- Появляется anti-forensics видимость (audit_log_tamper, timestomp, reboot, acct).
- Покрытие container escape (unshare/setns/pivot_root/mount).
- Возможность детектировать exploitation primitives (userfaultfd, af_alg).

**Независимая ценность:** каждое правило добавляет конкретное observable в UEBA, не требуя ничего другого из плана.

## Вопросы перед стартом

В первом ответе пользователю задать (через AskUserQuestion):

1. **Раскатывать Tier A + Tier B одним коммитом** или разделить на два (сначала Tier A, понаблюдать сутки, потом Tier B)?
   - Recommended: **раздельно**, по 1 коммиту на Tier, чтобы изолировать рост объёма от каждого тира.
2. **Включать `pkg_mgmt_change`** (watch на `/etc/apt/`, `/etc/dnf/`, `/etc/yum.repos.d/`)? На активно обновляющихся хостах даёт регулярный фон. — рекомендуется ДА (supply-chain сигнал ценный).
3. **Включать `sshd_config` расширение** до `-w /etc/ssh/`? Нужно проверить, не пишет ли fail2ban/ssh-agent в подкаталоги `/etc/ssh/` — на dev-стенде это легко выявится.

## Pre-flight проверки

1. Прочитать [audit.rules](../agents/configs/auditd/audit.rules) — текущий набор ключей. Свериться, что **никакой из 26 предложенных ключей не дублирует существующий по смыслу** (например, наш `audit_config_change` уже покрывает `/etc/audit/` — не дублируем).

2. Прочитать [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) — найти таблицу `SYSCALLS`. Найти блок категоризации.

3. Подтвердить номера syscall'ов для новых правил (x86_64):

   ```bash
   for s in mount umount2 reboot acct kexec_load kexec_file_load unshare utimensat \
            userfaultfd setns mknod mknodat sethostname setdomainname; do
     printf "%-20s = %s\n" "$s" "$(ausyscall x86_64 "$s")"
   done
   ```

   Сравнить со списком в плане: `mount=165, umount2=166, reboot=169, acct=163, kexec_load=246, unshare=272, utimensat=280, userfaultfd=282, setns=308, kexec_file_load=320, mknod=133, mknodat=259`.

4. Замер baseline объёма `audit.log` за 24ч ДО внесения правил.

## Реализация

### Шаг 1. Tier A — высокий сигнал

Добавить блок в [audit.rules](../agents/configs/auditd/audit.rules) **перед** блоком "Иммутабельный режим" (если P0-03 уже сделан — после его блока):

```text
# ── Tier A: anti-forensics, persistence, container escape (P1-01) ────────────
# Anti-forensics
-w /var/log/audit/ -p wa -k audit_log_tamper
-a always,exit -F arch=b64 -S reboot -k power_state
-a always,exit -F arch=b64 -S acct -k process_accounting_tamper
-a always,exit -F arch=b64 -S utimensat,utimes,futimesat -F auid>=1000 -F auid!=unset -k timestomp

# LD_PRELOAD / library path persistence
-w /etc/ld.so.preload -p wa -k preload_inject
-w /etc/ld.so.conf    -p wa -k libpath_change
-w /etc/ld.so.conf.d/ -p wa -k libpath_change

# Container / namespace escape
-a always,exit -F arch=b64 -S unshare,setns,pivot_root -F auid>=1000 -F auid!=unset -k container_escape
-a always,exit -F arch=b64 -S mount,umount2,move_mount,open_tree,fsopen,fsconfig,fsmount -F auid>=1000 -F auid!=unset -k mount_action

# Kernel hot-replace / exploit primitives
-a always,exit -F arch=b64 -S kexec_file_load,kexec_load -k kexec_hot_replace
-a always,exit -F arch=b64 -S userfaultfd -F auid>=1000 -F auid!=unset -k userfaultfd_use

# Crypto bypass
-a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg

# Swap manipulation (LD_PRELOAD prep, persistence)
-a always,exit -F arch=b64 -S swapon,swapoff -k swap_modify
```

### Шаг 2. SYSCALLS таблица в enrich (для Tier A)

В [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua) дополнить таблицу `SYSCALLS`:

```lua
["133"]="mknod",
["163"]="acct",
["165"]="mount",
["166"]="umount2",
["169"]="reboot",
["246"]="kexec_load",
["259"]="mknodat",
["272"]="unshare",
["280"]="utimensat",
["282"]="userfaultfd",
["308"]="setns",
["310"]="process_vm_readv",  -- если P0-03 ещё не сделан, добавить тоже
["311"]="process_vm_writev",
["320"]="kexec_file_load",
-- Если P0-03 сделан, эти уже есть:
-- ["101"]="ptrace", ["319"]="memfd_create", ["321"]="bpf", ["425"]="io_uring_setup"
```

Сверь с текущим состоянием файла — добавляй только отсутствующие.

### Шаг 3. Категоризация в enrich (для Tier A syscalls)

В блоке if/elseif sc_name в [auditd_enrich.lua](../agents/configs/fluent-bit/scripts/auditd_enrich.lua):

```lua
elseif sc_name == "mount" or sc_name == "umount2" then
    record["event.type"]     = "change"
    record["event.category"] = "host"
elseif sc_name == "unshare" or sc_name == "setns" then
    record["event.type"]     = "change"
    record["event.category"] = "process"
elseif sc_name == "reboot" or sc_name == "kexec_load" or sc_name == "kexec_file_load" then
    record["event.type"]     = "change"
    record["event.category"] = "host"
elseif sc_name == "acct" or sc_name == "swapon" or sc_name == "swapoff" then
    record["event.type"]     = "change"
    record["event.category"] = "host"
elseif sc_name == "utimensat" or sc_name == "utimes" or sc_name == "futimesat" then
    record["event.type"]     = "change"
    record["event.category"] = "file"
elseif sc_name == "userfaultfd" then
    record["event.type"]     = "info"
    record["event.category"] = "process"
```

### Шаг 4. Раскатать Tier A, наблюдать 24 часа

```bash
cd agents/deploy
ansible-playbook agents-deploy.yml --ask-become-pass --limit=test-host --tags=auditd,fluent-bit
ansible test-host -m shell -a "auditctl -l | wc -l"
```

Через 24 часа сравнить объём `audit.log` с baseline — рост допустим до **+10%**.

Smoke на test-хосте:

```bash
sudo touch /etc/ld.so.preload   # → preload_inject
sudo mount -t tmpfs none /mnt   # → mount_action
sudo umount /mnt
unshare --pid --fork /bin/true  # → container_escape
```

В `fluent-audit-*` должны быть документы с этими ключами и заполненным `event.action`.

### Шаг 5. Tier B — средний сигнал

Только после успешного Tier A. Добавить блок:

```text
# ── Tier B: persistence, network/DNS, package mgmt (P1-01) ───────────────────
-w /etc/environment       -p wa -k env_change
-w /etc/selinux/          -p wa -k mac_policy_change
-w /etc/apparmor/         -p wa -k mac_policy_change
-w /etc/apparmor.d/       -p wa -k mac_policy_change
-w /etc/profile.d/        -p wa -k shell_profile_change
-w /etc/profile           -p wa -k shell_profile_change
-w /etc/bashrc            -p wa -k shell_profile_change
-w /etc/inittab           -p wa -k init_change
-w /etc/init.d/           -p wa -k init_change
-w /etc/rc.local          -p wa -k init_change
-w /etc/fstab             -p wa -k fstab_change
-w /etc/udev/rules.d/     -p wa -k udev_change
-w /etc/apt/              -p wa -k pkg_mgmt_change
-w /etc/dnf/              -p wa -k pkg_mgmt_change
-w /etc/yum.repos.d/      -p wa -k pkg_mgmt_change
-w /etc/nftables.conf     -p wa -k firewall_change
-w /etc/iptables/         -p wa -k firewall_change
-w /etc/issue             -p wa -k issue_change
-w /etc/issue.net         -p wa -k issue_change
-w /etc/sssd/             -p wa -k user_changes
-w /etc/openldap/         -p wa -k user_changes
-w /etc/krb5.conf         -p wa -k user_changes
-w /etc/polkit-1/         -p wa -k pam_changes
-w /etc/ssh/              -p wa -k sshd_config

-a always,exit -F arch=b64 -S sethostname,setdomainname -k hostname_dns_change
-w /etc/hosts             -p wa -k hostname_dns_change
-w /etc/resolv.conf       -p wa -k hostname_dns_change

-a always,exit -F arch=b64 -S mknod,mknodat -F auid>=1000 -F auid!=unset -k specialfile_create
```

Категоризацию для `sethostname/setdomainname/mknod/mknodat` в enrich можно добавить, но не обязательно — у нас они на watch-only кроме `mknod`. Для `mknod`:

```lua
elseif sc_name == "mknod" or sc_name == "mknodat" then
    record["event.type"]     = "creation"
    record["event.category"] = "file"
elseif sc_name == "sethostname" or sc_name == "setdomainname" then
    record["event.type"]     = "change"
    record["event.category"] = "host"
```

### Шаг 6. Раскатать Tier B, наблюдать 24 часа

Замер дельты объёма. Должен оставаться в пределах **+10%** относительно baseline после Tier A.

Если `/etc/ssh/` watch генерирует много шума (fail2ban пишет ban-файлы), сузить обратно до `-w /etc/ssh/sshd_config`.

## Что НЕ делать в этой итерации

- **НЕ брать Tier C** (см. план — `bin_writes`, `delete`, `perm_mod`, `docker`, IPC). Они шумные и не оправдывают объём.
- **НЕ переименовывать существующие ключи.** Только добавление новых; `user_changes` и `pam_changes` расширяются дополнительными watch-строками с теми же ключами.
- **НЕ дублировать правила P0-03**, если он уже сделан. Если P0-03 ещё не сделан — НЕ затаскивать его правила сюда (это отдельная задача с отдельными ключами).
- **НЕ включать иммутабельный режим** (`-e 2`) — это вне scope этой задачи, отдельное решение пользователя.
- **НЕ автоматизировать триггер-тесты** — только manual smoke. Триггер-плейбук — P1-04, отдельная задача.

## Проверка готовности

Из [HARDENING_PLAN.md P1-01 → Критерий готовности](HARDENING_PLAN.md):

- Все Tier A + Tier B правила в `audit.rules`, прошли `augenrules --check`.
- `auditctl -l` на test-хосте показывает все новые правила (число строк выросло на ~26).
- В `fluent-audit-*` для каждого нового ключа есть хотя бы один документ с правильно заполненным `event.action`.
- Объём `audit.log` после Tier A + Tier B вырос не более чем на **+10%** относительно baseline.

## Финал

1. **Обновить [README_FOR_AI.md](../README_FOR_AI.md):**
   - Раздел **3.1** ("Что собирается"): добавить под-список "Tier A: anti-forensics + persistence + container escape" и "Tier B: extended persistence + network config + package mgmt" с кратким описанием.
   - Раздел **3.4** ("Типичные event.action для UEBA"): расширить таблицу новыми ключами (хотя бы 5-7 наиболее ценных: `mount_action`, `container_escape`, `preload_inject`, `pkg_mgmt_change`, `firewall_change`, `timestomp`).

2. **Обновить [CLAUDE.md](../CLAUDE.md):**
   - В разделе "Правила auditd" (Ключевые файлы по темам) — упомянуть, что audit.rules расширен Tier A + Tier B из P1-01 на основе Neo23x0.

3. **Обновить статус задачи в [HARDENING_PLAN.md](HARDENING_PLAN.md):** P1-01 → "**Статус:** выполнено YYYY-MM-DD".

4. **Закоммитить** (два коммита — Tier A и Tier B раздельно, если согласовано с пользователем):

   ```
   P1-01 Tier A: anti-forensics, persistence, container escape rules

   - 12 new audit keys: audit_log_tamper, power_state, process_accounting_tamper,
     timestomp, preload_inject, libpath_change, container_escape, mount_action,
     kexec_hot_replace, userfaultfd_use, af_alg, swap_modify
   - auditd_enrich.lua: SYSCALLS extended with mount/umount2/reboot/acct/kexec/
     unshare/utimensat/userfaultfd/setns/process_vm
   - Verified delta volume <+10% on test-host after 24h
   ```

   ```
   P1-01 Tier B: extended persistence, network config, package mgmt

   - 14 watch rules: env_change, mac_policy_change, shell_profile_change, init_change,
     fstab_change, udev_change, pkg_mgmt_change, firewall_change, hostname_dns_change,
     issue_change, specialfile_create + extended user_changes/pam_changes/sshd_config
   - Verified delta volume <+10% on test-host after Tier A baseline
   ```

5. **Сообщить пользователю**: что добавлено, дельта объёма по факту, есть ли необходимость whitelist'ить шумные правила (например `/etc/apt/`, `/etc/ssh/`).
