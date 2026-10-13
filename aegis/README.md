# АЕГИС 1.2.0 — release candidate

АЕГИС — Автономная Единая Гибридная Информационная Система. Обновление Stability, Reliability & Message Lifecycle продолжает кодовую базу 1.1.5.

**productionReady=false.** Клиентские функции собраны и прошли автоматические и настоящее Tor staging проверки. Windows 11, CachyOS KDE Wayland/X11 и полный подписанный updater/install/restart/rollback должны пройти нативную приёмку владельцем. Этот комплект не является опубликованным Stable.

## Файлы

- AEGIS-Setup-1.2.0-x64.exe — установка Windows под обычной учётной записью.
- AEGIS-1.2.0-Windows-x64.zip — portable Windows; распаковать полностью и открыть AEGIS.exe.
- AEGIS-1.2.0-CachyOS-x86_64.AppImage — Java 21, Tor и Snowflake внутри.
- AEGIS-1.2.0-source.zip и client-source.zip — исходники и build scripts; версия общего протокола/Relay сохранена намеренно.
- AEGIS-1.2.0-native-acceptance.zip — набор тестов, сценариев и матрица для владельца.
- AEGIS-1.2.0-offline-signing.zip — неподписанные Stable/Beta manifest inputs, существующий публичный ключ и инструкция. Private key отсутствует.
- SHA256SUMS и SIGNING-INPUT-SHA256 — проверка release assets и точных байтов manifest.
- TEST-REPORT-1.2.0.md и evidence/ — результаты и ограничения проверок.

Начните с README-WINDOWS.md или README-CACHYOS.md, затем MIGRATION-1.1.5-TO-1.2.0.md и NATIVE-ACCEPTANCE-1.2.0.md. Изменения перечислены в CHANGELOG-1.2.0.md.

## Что изменилось

Подписанные взаимные Friends и durable delivery/read receipts передаются через прежние encrypted письма, без обновления production Relay 0.2.0. Исчезающие письма используют одно проверенное устройство и timer после отображения. Обычные письма сохраняют прежний TTL после доставки; старым письмам не добавляются новые timers/read statuses. Обновлены Tor state card, повторное подключение, адаптивная компоновка, локальные кириллические шрифты, встроенный просмотр аватара и изоляция updater helper.

**Ограничение исчезающих писем:** reboot ОС, недостоверный ledger или неоднозначный прерванный reveal могут закрыть уже открытое письмо раньше срока. Перезапуск приложения в рамках того же boot сохраняет countdown. Это явно консервативная модель, не гарантия точного времени через reboot. См. LIFECYCLE-1.2.0.md. Экспортированные файлы/скриншоты не уничтожаются.

## Все сетевые направления

Код Java обращается к собственным Tor SOCKS и Control на localhost. Почта — только к настроенному relay onion и account-signed peer onion; virtual ports 80/81 ведут в локальный клиентский сервис, публичный IP-порт не открывается. Control управляет только собственным Tor/onion и не получает приватные account/device/message keys. HTTPS updater использует отдельный localhost SOCKS Tor для подписанных GitHub feeds/assets и их разрешённых HTTPS redirect hosts. TLS, pinned Ed25519, размер, SHA-256 и anti-rollback обязательны. Прямого clearnet fallback в Java нет.

Сам официальный Tor создаёт исходящие соединения Tor Direct, а Snowflake — документированные transport/broker/rendezvous/WebRTC соединения. Выбор режима и диагностические детали доступны в приложении; внешнего SaaS для писем нет. Существующий Debian Relay слушает loopback и получает только encrypted payload; новый server deployment не требуется и не входит в этот клиентский комплект. Полный прежний privacy/protocol/deployment код и документация находятся в source ZIP.

Нет телеметрии, аналитики, рекламных SDK или автоматической публикации. Independent security audit не проводился. Production Relay/onion/feed и pinned release key не изменены.

## Подпись и публикация

OWNER-OFFLINE-SIGNING-1.2.0.md описывает owner-only офлайн Ed25519 подпись и отдельный Beta E2E тест. Stable публикуется только после обязательной приёмки. Подписи самостоятельно не созданы; существующая подпись другого manifest не подходит. GitHub URL v1.2.0 в manifest — будущие адреса, файлы по ним станут доступны после публикации владельцем.
