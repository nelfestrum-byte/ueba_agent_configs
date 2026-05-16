# osquery diff trigger test

Ansible-плейбук для ручного тестирования diff-событий osquery на удалённых хостах.  
Создаёт (apply) и удаляет (rollback) тестовые артефакты — по одному на каждую мониторируемую таблицу.

## Первый запуск — подготовка

```bash
cd tests/osquery

# Скопировать и заполнить инвентори
cp inventory.ini.example inventory.ini
# Прописать IP/hostname хостов и ansible_user
```

Формат `inventory.ini`:

```ini
[ueba_agents]
agent01  ansible_host=10.0.0.11
agent02  ansible_host=10.0.0.12

[ueba_agents:vars]
ansible_user=deploy
ansible_become=true
ansible_python_interpreter=/usr/bin/python3
```

> `inventory.ini` добавлен в `.gitignore` — в репозиторий не попадает.

---

## Запуск

```bash
cd tests/osquery

# Применить — создать артефакты на всех хостах
ansible-playbook osquery-trigger.yml -e mode=apply --ask-become-pass

# Только на одном хосте
ansible-playbook osquery-trigger.yml -e mode=apply --limit agent01 --ask-become-pass

# Откатить — удалить все артефакты
ansible-playbook osquery-trigger.yml -e mode=rollback --ask-become-pass
```

---

## Проверка результата

Дождаться истечения самого долгого интервала из тестируемых таблиц — **300s** (`startup_items`, `iptables`).

```bash
# SSH на целевой хост, затем:

# Все diff-события теста
sudo grep osq-test /var/log/osquery/osqueryd.results.log

# Читаемый вывод
sudo grep osq-test /var/log/osquery/osqueryd.results.log | python3 -m json.tool

# В реальном времени во время apply/rollback
sudo tail -f /var/log/osquery/osqueryd.results.log

# Быстрая проверка — только таблицы и action
sudo grep osq-test /var/log/osquery/osqueryd.results.log \
  | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(e['action'], e['name'], json.dumps(e.get('columns', {}), ensure_ascii=False))
"
```

Каждое событие содержит поле `"action": "added"` (apply) или `"action": "removed"` (rollback).

---

## Покрытие таблиц osquery.conf

### Покрыто — 13 / 23 таблиц

| Таблица | Интервал | Артефакт | Что проверяет |
|---|---|---|---|
| `processes` | 30s | `/tmp/osq-test-sleep infinity` (via systemd) | Процессы из нестандартных путей |
| `listening_ports` | 60s | python3 TCP listener на порту 19876 | Новые прослушиваемые порты |
| `crontabs` | 60s | `/etc/cron.d/osq-test` | Появление cron-заданий |
| `ssh_authorized_keys` | 60s | `~osq-test-user/.ssh/authorized_keys` | Добавление SSH-ключей |
| `services` | 60s | systemd unit `osq-test.service` | Новые/изменённые сервисы |
| `users` | 120s | пользователь `osq-test-user` | Создание учётных записей |
| `groups` | 120s | группа `osq-test-group` | Создание групп |
| `user_groups` | 120s | `osq-test-user` → `osq-test-group` | Изменения в составе групп |
| `sudoers` | 120s | `/etc/sudoers.d/osq-test` | Изменения прав sudo |
| `etc_hosts` | 120s | `198.51.100.1 osq-test.internal` | Изменения `/etc/hosts` |
| `mounts` | 120s | bind-mount `/tmp` → `/mnt/osq-test-mount` | Монтирование ФС |
| `iptables` | 300s | `INPUT RETURN --comment osquery-test` | Изменения правил фаервола |
| `startup_items` | 300s | `/etc/init.d/osq-test` (LSB init script) | Новые скрипты автозапуска |
| `suid_bins` | 3600s | `/tmp/osq-test-sleep` mode 4755 | Появление SUID-бинарей |

### Не покрыто — 10 / 23 таблиц

| Таблица | Причина |
|---|---|
| `logged_in_users` | Требует реального login-сеанса (utmp/wtmp) |
| `process_connections` | Требует исходящего соединения во внешний IP |
| `process_open_files` | Определяется процессами, нестабильный состав |
| `kernel_modules` | `modprobe` меняет состояние ядра — риск |
| `arp_cache` | Пассивная таблица ядра, заполняется трафиком |
| `routes` | Требует реального интерфейса для тестового маршрута |
| `dns_resolvers` | Изменение `/etc/resolv.conf` нарушает DNS на хосте |
| `pci_devices` | Физическое железо |
| `usb_devices` | Физическое железо |
| `certificates` | Требует обновления системного CA store |

---

## Идемпотентность

Плейбук безопасно запускать повторно в любом режиме:

- Ansible-модули (`user`, `group`, `authorized_key`, `copy`, `lineinfile`) идемпотентны нативно.
- Shell-таски проверяют состояние перед действием: `mountpoint -q`, `iptables -C`, PID-файл листенера.
- `mode=rollback` с уже удалёнными артефактами завершается без ошибок (`ignore_errors: true` там, где объект может отсутствовать).
