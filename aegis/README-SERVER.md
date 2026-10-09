# АЕГИС Relay 0.3.0 — staging, protocol 1

Это optional staging-пакет для профилей и mutual friends 1.1.0. Production Relay 0.2.0 не требует замены для обычной почты. **Не запускайте installer/upgrade на production без разрешения владельца.** Аддитивная SQLite миграция и старые клиенты проверены локально; Debian VPS/Tor/reboot native acceptance не выполнена. Подробности — [RELAY-0.3-STAGING.md](RELAY-0.3-STAGING.md).

Новый staging сервер:

```sh
unzip AEGIS-0.3.0-server-debian13-staging.zip
cd AEGIS-server
sudo ./install-server.sh
```

Installer устанавливает только `tor ufw python3 sqlite3 ca-certificates`; Java 21 входит в пакет. Он создаёт системного пользователя, каталоги, systemd unit, onion service, включает автозапуск и выполняет doctor. Никогда не запускает full-upgrade/dist-upgrade, grub-install/update-grub, не меняет DNS/разделы диска.

Firewall: сохраняет существующие правила, определяет текущий SSH-порт по SSH_CONNECTION либо sshd и разрешает его, задаёт deny incoming / allow outgoing, включает UFW. Нестандартный порт можно явно задать `sudo AEGIS_SSH_PORT=2222 ./install-server.sh`. Порт 19110 не открывается. Installer не удаляет произвольные старые правила администратора; doctor сообщит об обнаруженном разрешении 19110.

Права создаются сразу:

| Путь | Владелец | Режим |
|---|---|---|
| /opt/aegis/relay | root:root | каталог 755 |
| /etc/aegis | root:aegis-relay | 750 |
| /etc/aegis/relay.properties | root:aegis-relay | 640 |
| /var/lib/aegis-relay | aegis-relay:aegis-relay | 700 |
| Onion identity | debian-tor:debian-tor | каталог 700 |

Перед запуском relay проверяется `runuser -u aegis-relay -- … version …`. Java API слушает только 127.0.0.1:19110. Tor публикует его на onion-порту 80. Закрытые onion-ключи не выводятся.

Tor использует настоящий `tor@default.service`. `tor.service active (exited)` не считается готовностью. Аутентифицированный контроль проверяет bootstrap 100%. Через 180 секунд неудачного bootstrap включается поставляемый Lyrebird/Snowflake; ещё 240 секунд даётся на подключение. Публичного fallback нет. Совместимые bridge-строки извлекаются из официального Expert Bundle 15.0.24; применяется `fronts=…`, а не ошибочный `front=…,…`.

Дополнение Tor находится в `/etc/tor/aegis-relay.conf`; основной torrc сохраняется и получает `%include`. Если существующая конфигурация уже публикует 19110, installer переиспользует её onion identity. Проверка Tor запускается под debian-tor. Для ограничивающего AppArmor-профиля добавляется узкое разрешение на запуск поставляемого `/opt/aegis/tor/lyrebird`; AppArmor не отключается.

Повторный обычный install выполняет doctor. Для обновления используйте отдельный upgrade. Свежий сервер: `registrationMode=open`, `maxUsers=32`. Любой знающий onion может зарегистрировать свободный корректный ник. Режим closed отключает регистрацию. Invite-режим не реализован; старые `allowRegistration/allowedNicknames` поддержаны только при отсутствии registrationMode.

```sh
sudo aegis-server doctor
sudo aegis-server onion
sudo aegis-server status
sudo aegis-server start
sudo aegis-server stop
sudo aegis-server restart
sudo aegis-server stats
sudo aegis-server cleanup
```

Doctor проверяет Java, процесс, доступ к конфигу, владельцев/режимы, SQLite quick_check, localhost listener, tor@default, SAFECOOKIE bootstrap, Snowflake config, hostname onion, UFW и autostart. Наличие hostname не доказывает доступность onion из другого города: это проверяет реальный клиент.

Обновление:

```sh
cd AEGIS-server
sudo ./upgrade-server.sh
```

Relay останавливается; SQLite Backup API создаёт согласованную копию БД. В `/var/backups/aegis/upgrade-*` сохраняются конфиги, предыдущие бинарники и состояние Tor. Каталог доступен только root. Копия содержит onion private identity — защищайте её как секрет и не публикуйте. Действующие onion-ключи при обновлении не меняются.

При миграции 0.1.0, если registrationMode отсутствует, upgrade явно добавляет open/maxUsers=32 согласно новой политике 0.2.0. Остальные настройки сохраняются; уже заданный режим 0.2.0 не меняется. Откат:

```sh
sudo ./rollback-server.sh /var/backups/aegis/upgrade-XXXXXXXX
```

Откат возвращает предыдущие relay, конфиг и БД; новые onion-ключи никогда не генерируются. При rollback сообщения/аккаунты после backup будут потеряны, поэтому выполняйте его сразу после неудачного обновления. Прежде чем удалить старые backups, убедитесь в успешном запуске.

По умолчанию вложения до 16 MiB, очередь 256 MiB на пользователя, доставка до 7 суток. При свободном месте меньше 512 MiB плюс запас на транзакцию новые STORE отклоняются. Для лимита 100 MiB увеличьте heap/MemoryMax и проверьте нагрузку; этот режим не испытан на сервере с 512 MB RAM.

Обязательная приёмка на VPS после установки: `sudo reboot`, затем `sudo aegis-server doctor`, обмен двумя клиентами, offline-доставка и файл. В данной среде такой VPS отсутствовал; reboot-тест не заявлен выполненным.
