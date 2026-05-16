# osquery diff trigger test

Ansible-плейбук для ручного тестирования diff-событий osquery.  
Создаёт (apply) и удаляет (rollback) тестовые артефакты — по одному на каждую мониторируемую таблицу osquery.

## Запуск

### Локально (на машине с osquery)

```bash
cd tests/osquery

# Применить — создать артефакты
ansible-playbook osquery-trigger.yml -e mode=apply --ask-become-pass

# Откатить — удалить артефакты
ansible-playbook osquery-trigger.yml -e mode=rollback --ask-become-pass
```

### Удалённый хост

```bash
cd tests/osquery

ansible-playbook osquery-trigger.yml \
  -i ../../agents/deploy/inventory.ini \
  -e mode=apply \
  --ask-become-pass
```

### Проверка результата

```bash
# Ждать max 300s (интервал самой медленной таблицы: startup_items, iptables)
# Затем смотреть diff-события:
sudo grep osq-test /var/log/osquery/osqueryd.results.log

# Удобочитаемый вывод:
sudo grep osq-test /var/log/osquery/osqueryd.results.log | python3 -m json.tool

# В реальном времени (во время apply/rollback):
sudo tail -f /var/log/osquery/osqueryd.results.log
```

Каждое событие имеет поле `"action": "added"` (apply) или `"action": "removed"` (rollback).

---

## Покрытие таблиц osquery.conf

### Покрыто (13 / 23)

| Таблица | Интервал | Артефакт |
|---|---|---|
| `processes` | 30s | `/tmp/osq-test-sleep infinity` (via systemd service) |
| `logged_in_users` | 30s | — *не покрыта* |
| `process_connections` | 30s | — *не покрыта* |
| `usb_devices` | 30s | — *не покрыта* |
| `listening_ports` | 60s | python3 TCP listener на порту 19876 |
| `crontabs` | 60s | `/etc/cron.d/osq-test` |
| `ssh_authorized_keys` | 60s | `~osq-test-user/.ssh/authorized_keys` |
| `kernel_modules` | 60s | — *не покрыта* |
| `services` | 60s | systemd unit `osq-test.service` |
| `process_open_files` | 60s | — *не покрыта* |
| `arp_cache` | 60s | — *не покрыта* |
| `users` | 120s | пользователь `osq-test-user` |
| `groups` | 120s | группа `osq-test-group` |
| `user_groups` | 120s | `osq-test-user` → `osq-test-group` |
| `sudoers` | 120s | `/etc/sudoers.d/osq-test` |
| `routes` | 120s | — *не покрыта* |
| `dns_resolvers` | 120s | — *не покрыта* |
| `mounts` | 120s | bind-mount `/tmp` → `/mnt/osq-test-mount` |
| `etc_hosts` | 120s | `198.51.100.1 osq-test.internal` |
| `iptables` | 300s | `INPUT RETURN --comment osquery-test` |
| `startup_items` | 300s | `/etc/init.d/osq-test` (LSB init script) |
| `suid_bins` | 3600s | `/tmp/osq-test-sleep` с битом SUID (mode 4755) |
| `pci_devices` | 300s | — *не покрыта* |
| `certificates` | 3600s | — *не покрыта* |

### Не покрыто (10 / 23) — причины

| Таблица | Причина |
|---|---|
| `logged_in_users` | Требует реального login-сеанса (utmp/wtmp) |
| `process_connections` | Требует исходящего соединения во внешний IP |
| `kernel_modules` | `modprobe` меняет состояние ядра, риск дестабилизации |
| `process_open_files` | Определяется самими запущенными процессами, нестабильно |
| `arp_cache` | Пассивная таблица ядра, заполняется трафиком |
| `routes` | Требует реального сетевого интерфейса для dummy-маршрута |
| `dns_resolvers` | Изменение `/etc/resolv.conf` ломает DNS |
| `pci_devices` | Физическое железо |
| `usb_devices` | Физическое железо, интервал 30s — слишком шумит |
| `certificates` | Требует обновления системного CA store (`update-ca-certificates`) |

---

## Идемпотентность

- Повторный `mode=apply` ничего не сломает — Ansible-модули (`user`, `group`, `authorized_key`, `copy`, `lineinfile`) идемпотентны по природе.  
- Shell-таски (листенер, mount, iptables) проверяют состояние перед действием (`mountpoint -q`, `iptables -C`, PID-файл).  
- Повторный `mode=rollback` безопасен — `ignore_errors: true` там, где артефакт может уже отсутствовать.
