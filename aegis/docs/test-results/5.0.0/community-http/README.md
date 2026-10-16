# Целевые проверки HTTP/CLI 5.0.0

Реальный локальный прогон: 18 тестов, 18 успешных, 0 пропущенных. Время, XML и SHA-256 входных исходников приведены в `RESULTS.json`. Исходники common-protocol/community-server не менялись между компиляцией и завершением тестов. Это отдельный source cut, а не окончательный общий прогон релизного commit.

Проверяются настоящие Ed25519-подписи HTTP, nonce/replay/audience/request binding, серверный ACL/SQLite, невозможность чтения закрытого графа, ограничения worker identity, строгий JSON, атомарный двухадминистраторский bootstrap с TOTP и запуск дочернего `CommunityMain --serve`. Mock HTTP/SQL не используется.

Это **не** Tor/onion, DNS/WebRTC/IP-leak, Windows 11, CachyOS KDE, два физических устройства или updater E2E. `productionReady=false`.

Для точного воспроизведения нужны Java 21 и проверенные JAR, перечисленные в `INPUTS-SHA256.json` (расположение inputs500/deps и inputs250/squashfs-root/app). Изменения исходников после source cut требуют нового общего прогона:

```sh
python3 reproduce.py --repo /path/to/aegis/aegis --inputs-root /path/to/verified-inputs --output /path/to/new-http-results
```

Скрипт удаляет только собственные classes/tests/XML внутри указанного output, компилирует весь текущий common-protocol/community-server, запускает выбранные настоящие JUnit классы, читает свежие XML и отвергает изменившиеся во время прогона исходники. Native acceptance старой версии здесь не переносится на 5.0.0.
