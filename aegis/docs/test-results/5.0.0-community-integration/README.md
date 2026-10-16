# Межмодульная локальная интеграция 5.0.0

Реальный прогон: 6 тестов, 6 успешных, 0 пропущенных. Время, свежие XML и SHA входных исходников приведены в `RESULTS.json`. Все текущие common-protocol/client-core/community-server исходники собраны Java 21 и не менялись во время этого прогона. Это отдельный source cut, а не финальное доказательство готовности всех релизных бинарников.

Используются production `CommunityClient` и `TorTransport`, реальный Ed25519 HTTP/SQLite сервер, отдельные настоящие зашифрованные vault identities, реальные TOTP/bootstrap, archive, AES-GCM sidecar, migration/snapshot/rekey. Транспорт проходит через **ограниченный тестовый loopback SOCKS5 fixture**: только одно зафиксированное вымышленное onion-имя и один loopback порт, без разрешения DNS и без произвольного перенаправления.

Проверены:

1. Подписанные capabilities, получение публичного документа, зашифрованный offline кэш и прекращение выдачи/сброс кэша после отзыва ACL/смены epoch.
2. Исключение закрытых узлов/названий/связей из графа и отдельность личного архива.
3. Заявка одного пользователя, одобрение другим после реальной повторной аутентификации, вступление, серверное групповое разрешение звонка и отзыв после выхода.
4. Fail-closed при выключенном TorTransport или неверном закреплённом сервисном ключе, без прямого HTTP fallback.
5. Большой (около 1,44 МиБ) реальный community cache при mail quota 1 МиБ, rekey vault с сохранением identity и отдельного архива, `ClientUpgrade.beforeVersionOpen("5.0.0")`, проверка backup/idempotence, намеренная порча только тестового sidecar и полное восстановление snapshot/данных.

6. Подписанная публикация nickname в собственном профиле, запрет массового присваивания actor/admin-полей, сохранение identity и отсутствие новых полномочий. Это не проверка Relay avatar sync.

Это **не** настоящий Tor/onion, доказательство DNS/IP/WebRTC isolation, Windows/CachyOS native acceptance, два физических устройства или updater E2E. `productionReady=false`. Локальный SOCKS fixture прямо обозначен в тесте и не выдаётся за Tor.

Для воспроизведения нужны Java 21, JAR из `INPUTS-SHA256.json` и комплектные проверенные libsodium native files из базовой установки (расположение inputs250/squashfs-root). Все тестовые профили и backup создаются в JUnit TempDir, исходные профили пользователя не используются:

```sh
python3 reproduce.py --repo /path/to/aegis/aegis --inputs-root /path/to/verified-inputs --output /path/to/new-integration-results
```

Скрипт очищает только собственные classes/tests/XML внутри output, пересобирает текущие исходники и отвергает изменение source input во время тестирования. Окончательный общий прогон и проверка зафиксированного релизного commit выполняются отдельно.
