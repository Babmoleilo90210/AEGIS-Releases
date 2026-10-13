# АЕГИС 1.2.0 — lifecycle candidate

Client-only Friends, signed receipts и device-bound disappearing добавлены без обновления Relay protocol 1. productionReady=false до native/E2E приёмки. LIFECYCLE-1.2.0.md описывает новые encrypted events, local device key/guard и conservative expiry после reboot. Все обычные сетевые операции остаются Tor-only; дополнительно используется только account-signed peer onion virtual port 81 через существующий mail SOCKS. Прямые IP/HTTP/fallback не добавлены.

> АЕГИС 1.2.0: незавершённый клиентский кандидат. productionReady=false.
> Friends на Relay0.2.0, receipts и timer-after-read ожидают архитектурного решения.
> См. AUDIT-1.2.0-RU.md, RELAY-LIFECYCLE-PROPOSAL-1.2.0.md и TEST-REPORT-1.2.0.md.

# АЕГИС 1.2.0 — клиентский кандидат

Автономная Единая Гибридная Информационная Система. Локальные Java 21 клиенты Windows/CachyOS и заменяемый protocol-1 relay. Продолжает фактически опубликованную 1.1.5 Stable: исправления подключения, интерфейса и обновлений, с сохранением идентичности и protocol 1. Lifecycle часть ждёт архитектурного согласования.

Текущая сборка — **unsigned candidate**, `productionReady=false`. Реализация, JavaFX регрессии и staging совместимость проверяются отдельно от настоящих Windows/KDE/Tor/VPS испытаний. Production Relay, onion identity, опубликованные релизы и pinned release public key не изменены.

Начало работы: [Windows](README-WINDOWS.md), [CachyOS](README-CACHYOS.md), [переход с 1.1.5](MIGRATION-1.1.5-TO-1.2.0.md). Для разработчика: [сборка](BUILD-1.2.0.md), [изменения](CHANGELOG-1.2.0.md), [отчёт тестирования](TEST-REPORT-1.2.0.md), [optional staging Relay](RELAY-0.3-STAGING.md), [угрозы](THREAT_MODEL.md).


## Приложения и данные

`common-protocol` — модели, wire codecs и protocol 1; `client-core` — E2EE, ciphertext vault, доставка, local features и updater; `client-ui` — JavaFX desktop; `relay-server` — адресация, временный ciphertext и минимальные подписанные публичные данные. Relay не подключает client-core или криптографию расшифровки сообщений.

Письма всегда имеют TTL. Неизвестные отправители доставляются без автоматического добавления/доверия; подпись и наличие проверенного контакта показываются раздельно. Вложение сохраняется только вручную. Публичный профиль скрыт по умолчанию. Об аватарах, mutual friends, replies/chains, pins/search/offline и обновлениях — в CHANGELOG.

## Все сетевые соединения

| Компонент | Куда и для чего | Какие данные |
|---|---|---|
| Java клиент, почта | localhost SOCKS 19050 собственного Tor, только onion Relay/peer | протокол регистрации/входа; nickname, публичная identity/route; ciphertext, ACK; согласованные публичные profile/consent |
| Java клиент, P2P | localhost listener 19120, опубликованный только через onion Tor | подписанный ciphertext и ACK; IP пользователя не передаётся Relay |
| Java клиент, управление Tor | localhost Control 19051, SAFECOOKIE | bootstrap/публикация ephemeral onion; cookie не логируется |
| Java клиент, updater | localhost SOCKS 19052 → GitHub HTTPS | manifest, Ed25519 подпись, release assets; профиль/пароли/переписка туда не отправляются |
| Встроенный Tor | Tor directory/relays; при Snowflake официальные broker/front/STUN/WebRTC transport endpoints | сетевой транспорт Tor; настройки bridge перечислены в поставляемых pt_config.json/snowflake-bridges.txt |
| Java Relay | localhost listener 19110; исходящих пользовательских HTTP/SaaS запросов нет | зашифрованная очередь, ACK, публичные идентификаторы |
| Серверный Tor | сеть Tor/Snowflake, onion service → localhost Relay | транспорт; secret onion keys остаются у системного Tor |

Updater HTTPS допускает только `raw.githubusercontent.com`, `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, ограниченные redirect и обязательную TLS hostname проверку. Почтовый SOCKS сохраняет `OnionTrafficOnly`. Прямого подключения Java к публичному IP/HTTPS, DNS fallback, телеметрии, аналитики, скрытого updater или cloud crash reporting нет.

Сборка — отдельное явное действие разработчика: Gradle/Maven Central, GitHub release inputs и SHA-pinned официальные репозитории шрифтов, официальный JDK/Tor через перечисленные build scripts. Установщик Debian ставит только необходимые пакеты через настроенный apt; ОС/GRUB/DNS не перенастраивает. Эти developer/admin соединения не запускаются пользовательским клиентом.

Кандидат 1.2.0 не опубликован; 1.1.5 Stable уже опубликована. Ветка разработки: https://github.com/Babmoleilo90210/AEGIS-Releases/tree/development/aegis-1.2.0 . Финальные проверки, offline подпись владельца и публикация требуют отдельного завершения приёмки.

Пять новых лицензированных шрифтов находятся внутри client-ui JAR; установленное приложение не загружает их из сети. Предложение Friends/receipts/исчезновение: [отдельное архитектурное ТЗ](RELAY-LIFECYCLE-PROPOSAL-1.2.0.md). Не считать legacy TTL-after-delivery исчезновением-after-read.
