# АЕГИС 1.1.0

Автономная Единая Гибридная Информационная Система. Локальные Java 21 клиенты Windows/CachyOS и заменяемый protocol-1 relay. Это продолжаемый исходный код 1.0.0 с изменениями 1.1.0, не новая identity или новый wire protocol.

Текущая сборка — **unsigned candidate**, `productionReady=false`. Реализация, JavaFX регрессии и staging совместимость проверяются отдельно от настоящих Windows/KDE/Tor/VPS испытаний. Production Relay, onion identity, опубликованные релизы и pinned release public key не изменены.

Начало работы: [Windows](README-WINDOWS.md), [CachyOS](README-CACHYOS.md), [переход с 1.0.0](MIGRATION-1.0-TO-1.1.md). Для разработчика: [сборка](BUILD-1.1.0.md), [изменения](CHANGELOG-1.1.0.md), [отчёт тестирования](TEST-REPORT-1.1.0.md), [optional staging Relay](RELAY-0.3-STAGING.md), [угрозы](THREAT_MODEL.md).

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

Сборка — отдельное явное действие разработчика: Gradle/Maven Central, GitHub release inputs, официальный JDK/Tor через перечисленные build scripts. Установщик Debian ставит только необходимые пакеты через настроенный apt; ОС/GRUB/DNS не перенастраивает. Эти developer/admin соединения не запускаются пользовательским клиентом.

Production release не опубликован. Ветка разработки: https://github.com/Babmoleilo90210/AEGIS-Releases/tree/development/aegis-1.1.0 . Финальные проверки, offline подпись владельца и публикация требуют отдельного завершения приёмки.
