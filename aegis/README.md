# АЕГИС 1.5.0

АЕГИС — Автономная Единая Гибридная Информационная Система. Локальный Java21/JavaFX почтовый клиент с E2EE, Tor и независимым Relay. Это продолжение опубликованного 1.2.0, не новый проект.

**Статус: release candidate, productionReady=false.** Сборка не заменяет обязательную нативную приёмку. Stable/feed/production Relay и signing keys этой работой не изменяются.

Windows: распакуйте полный portable ZIP и запустите AEGIS.exe либо установите Setup. CachyOS: сделайте AppImage исполняемым и откройте его. Java21 и Tor включены. Tor подключается автоматически; адрес Relay вводится только как v3 .onion. Офлайн-доступ требует пароль локального хранилища.

Раздел «Архив» создаётся только по действию пользователя, пустым, с отдельным паролем. Он работает без сети. Имена и документы не хранятся в открытом виде. Необязательный recovery key сохраните отдельно; скрытого восстановления/мастер-ключа нет. Подробности: ARCHIVE-1.5.0.md и ARCHIVE-THREAT-MODEL-1.5.0.md.

## Код и сборка

common-protocol — protocol 1; client-core — E2EE, vault, Tor, lifecycle, updater, архив; client-ui — JavaFX; relay-server — неизменённая staging-реализация. Клиент совместим с production Relay0.2.0. Сервер не имеет библиотек расшифровки пользовательских сообщений.

Обычная сборка: `./gradlew build`. Явная упаковка с проверенными входами: `python3 tools/build-archive.py --jdk /path/to/jdk21 --work /path/to/build-inputs --out /path/to/candidates`. BUILD-1.5.0.md перечисляет зависимости и проверки. Подпись/публикация отделены от сборки.

## Все возможные сетевые соединения

| Источник | Назначение | Передаваемые данные |
|---|---|---|
| Клиент Java | 127.0.0.1 SOCKS19050 | Только v3 onion Relay/проверенного peer; protocol1 authentication, публичные identity/routing данные, E2EE ciphertext, ACK |
| Клиент Java | 127.0.0.1 Control19051 | SAFECOOKIE authentication и управление собственным ephemeral onion service; не пароли аккаунта/письма |
| Updater Java | 127.0.0.1 SOCKS19052 | HTTPS github.com, raw.githubusercontent.com, release-assets.githubusercontent.com, objects.githubusercontent.com; публичные manifest/signature/artifacts, range-resume |
| Встроенный Tor | Tor relays/authorities/directories | Транспорт Tor; внешние IP видит Tor-инфраструктура, HTTP user profile не отправляется |
| Snowflake/lyrebird, только при fallback/выборе | Официальные broker/front/rendezvous/STUN, указанные в комплектном pt_config/bridge-конфиге | Обход блокировки Tor; транспортные метаданные, не archive keys |
| Peer service Java | Только loopback, через свой Tor onion | Подписанный capability challenge и encrypted DELIVER/receipt; публичный TCP listener не создаётся |
| Relay | Локальный SQLite/loopback Tor service | Ciphertext и необходимые routing/account/delivery метаданные; Relay не расшифровывает письма |
| PDF worker/архив/поиск/темы | Сеть не используется | Локальные memory pipes/шифрованные файлы |
| Явная сборка разработчика | GitHub releases, Maven Central, Apache/официальные build inputs | Скачивание исходников/библиотек/инструментов; установленный клиент эти build scripts не запускает |

Прямого clearnet fallback для операций АЕГИС нет. Нет телеметрии, аналитики, рекламных SDK, облачного crash reporting и скрытого updater. Проверка/загрузка обновлений следуют сохранённым пользовательским настройкам; установка подтверждается пользователем. PDFBox — единственная новая группа runtime-библиотек: локальный просмотр PDF, Apache2, без внешнего сервиса.

Документы: README-WINDOWS.md, README-CACHYOS.md, MIGRATION-1.2.0-TO-1.5.0.md, TEST-REPORT-1.5.0.md, P2P-VERIFICATION-1.5.0.md, OWNER-OFFLINE-SIGNING-1.5.0.md. Безопасность и ограничения перечислены явно; независимый security audit не проводился.
