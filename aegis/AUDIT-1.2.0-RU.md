# Дополнение реализации client-only lifecycle

E2EE workaround реализован в development/aegis-1.2.0 после разрешения владельца продолжать без production Relay изменений. Friends/receipts больше не заблокированы серверными операциями. Signed port-81 capabilities и device-bound expiry описаны в LIFECYCLE-1.2.0.md. Нативные проверки и conservative reboot policy явно отделены от unit/staging. Ниже сохранён исходный аудит, его предварительные архитектурные варианты не являются текущим implementation status.

# АЕГИС 1.2.0 — технический аудит перед реализацией

Дата: 12.10.2026. Проверена действительная база 1.1.5, проект не создаётся заново. Это внутренний технический анализ, независимый security audit не проводился.

## Источники и состояние

- GitHub Release v1.1.5 опубликован, draft=false/prerelease=false; текущий main f1dacb5aedd8a99fadcc6f80c28229fce1cb7e4e. Signed feed указывает version=1.1.5.
- Исходники Release и восстановленный source ZIP имеют одинаковый SHA-256: 9a564f5bb0638a55d1378d2601e5f8949012a725409a19792c6dd7630c74efd9. Действительный source commit кандидата 1.1.5: 281a0c5e1a67d0b5abf44e26a2248eee1a5ef252.
- Исходники содержат клиент 1.1.5, общий модуль 0.2.0/protocol 1 и staging Relay 0.3.0. Это **не доказательство обновления production Relay 0.2.0**.
- По прежней shared-ссылке открыт чат планирования, прочитаны итоговые решения 1.1.5, single-window ограничения и просмотрен визуальный пример: графитовый почтовый центр, отдельная компактная навигация, карточки с отступами, мягкие радиусы и ясная иерархия. Доступная публичная копия заканчивается обсуждением 1.1.5, не содержит 1.2.0. Поиск предыдущих разговоров вернул часть решений 1.2.0, но не полное продолжение Work Prompt. Основным источником является новое ТЗ владельца.
- Полученное сообщение 1.2.0 обрывается в Definition of Done на пункте 4. Не восстановленные требования не считаются прочитанными или реализованными.
- Сохранённые результаты 1.1.5: 121 JUnit PASS/1 SKIP, 16 release/security PASS, 7 headless JavaFX suites PASS; Windows Server 2025/Ubuntu не заменяют нативную приёмку Windows 11/CachyOS. Повторные проверки 1.2.0 фиксируются отдельно.

## Карта компонентов и причины

| Требование | Реальные файлы | Вывод |
| --- | --- | --- |
| BUG-12 Friends | client-core/.../ClientSession.java, storage/LocalFeatures.java, net/NetworkService.java; common-protocol/.../ContactAssertion.java, Operation.java; client-ui/.../MessengerApp.java | Отдельного FriendsService нет. Дружба зависит от capability bit 2 и CONTACT_PUT/GET. На Relay 0.2.0 capability=0: взаимный локальный trust не создаёт подтверждений. Есть клиентские ошибки: blockSender не исключён из friend/consent, профиль синхронизируется до дружбы, удаление контакта выполняется после сетевого запроса и может не завершиться при сбое сети. |
| BUG-14 Tor | net/TorConnection.java, EmbeddedTor.java, BootstrapWatch.java; ui/MessengerApp.java | Есть bootstrap и fallback, но нет общей модели восьми состояний. Fallback ловит только BootstrapFailure; конкурентное close обнуляет child, пока start читает child.isAlive. Ползущий процент и Relay probe не представлены единой карточкой; во время активной попытки общий индикатор может говорить «Нет соединения». Stall Direct=30с может преждевременно оборвать медленный прогресс. |
| FEAT-15 receipts | protocol/Receipt.java; crypto/Identity.java; net/NetworkService.java; storage/LocalStore.java; relay/RelayStore.java | Подписанный ACK реально означает durable acceptance получателем. P2P проверяет его у отправителя. Relay ACK удаляет пакет, но receipts сохраняет только digest/deadline, не подпись/time/sender retrieval. Нет read-событий, durable event outbox, read/unread и выдачи подтверждений отправителю. RELAY_QUEUED не является delivered/read. |
| FEAT-16 исчезновение | protocol/Limits.java, EncryptedPacket.java; storage/LocalStore.java; ui/MailViewer.java | Legacy TTL начинается при local.accept, max=7 суток; expires привязан AEAD AAD и валидируется как received+TTL. Нельзя добавить 30-дневный timer-after-read одним изменением ComboBox или переименовать старый TTL. Старые письма должны сохранить прежнюю семантику. |
| BUG-13 панель | ui/MessengerApp.java arrangeNavigation; messenger.css | Навигация установлена напрямую в BorderPane.left, отсутствует внешний margin. Собственный padding панели не отделяет её от края окна. |
| BUG-20 максимизация | MessengerApp.java, ScaledRoot.java, AppearanceEngine.java | Пользовательский scale уже масштабирует геометрию и рисование. При росте окна только переходят жёсткие thresholds 700/850; размеры карточек/spacing не адаптируются. Нужна ограниченная геометрическая адаптация без подмены пользовательского scale и без произвольного роста шрифта. |
| BUG-18 шрифты | AppearanceEngine.java, AppearanceView.java, messenger.css | Только Font.getFamilies проверяет имена установленной ОС; пять требуемых семейств не поставляются и реальное Cyrillic coverage не проверяется. Glyph fallback может оставлять одинаковую кириллицу при разных латинских шрифтах. Нужны настоящие лицензированные TTF и JavaFX loadFont до cache Font.getFamilies. |
| FEAT-19 аватар | MessengerApp.java profile/contactProfile; AvatarView.java; InWindowDialog.java | Аватар ограничен размером 28–40px/настройкой компонентов. Нет крупного viewer/zoom. Приватность и право редактирования уже различены; сохранить их. |
| BUG-17 updater | UpdateInstaller.java, UpdaterMain.java; packaging/windows/updater.c; MessengerApp.start; PackageSanity.java | UpdaterMain — CLI, собственного Stage в исходниках нет. Но helper копирует весь app, включая client-ui/JavaFX; основной Stage показывается до подготовки первой страницы. Источник белого окна на реальном KDE **пока не воспроизведён**. Следует исключить UI/JavaFX из helper, включить AWT headless, показать оформленный startup content до Stage.show и сохранять безопасную фазовую диагностику. Нельзя объявлять нативный дефект закрытым по одному поиску new Stage. |
| MIG-01 | ClientUpgrade.java, ProfileSnapshot.java, LocalStore.java, AppearanceStore.java | Full ProfileSnapshot покрывает vault, appearance, settings, sessions, Tor state, updater floors/cache/events. Existing beforeOpen marker привязан к 1.1, поэтому 1.2 нужен отдельный подтверждённый pre-migration marker. Backup создаётся при закрытых изменяемых сервисах. Постоянных draft файлов в 1.1.5 нет — открытый draft только в памяти. |

Путь `...` в таблице означает фактический package org/securemail/client, org/securemail/ui или org/securemail/protocol внутри соответствующего src/main/java. Криптографические алгоритмы и identity keys не изменяются.

## Что разрешено независимо на клиенте

Карточка/состояния Tor, защита от конкурирующих попыток и close-race, адаптивные margins/карточки, настоящие кириллические шрифты, крупный in-window avatar viewer, изоляция helper от JavaFX, честные названия delivery status и пояснения неподдерживаемого Friends. Исправление приоритета block и локального удаления контакта не требует production Relay.

## Архитектурные блокеры

1. Подтверждённый Friends на production Relay 0.2.0 нельзя получить из двух не передаваемых локальных списков. Можно использовать уже существующие подписанные pair assertions в минимально совместимом обновлении Relay; полный список контактов не требуется. Имитация по наличию писем/маршрута недопустима.
2. Legacy ACK не возвращается offline-отправителю; отсутствие письма в очереди не является доставкой. Нужен согласованный authenticated event transport/retrieval.
3. После прочтения 30-дневные исчезающие письма конфликтуют с прежним max-7-day TTL-after-delivery. Требуются capability-gated новые lifecycle операции/модель, сохраняя legacy wire path protocol 1.
4. При нескольких устройствах и длительном offline нельзя гарантировать одно глобальное «первое прочтение» и deadline без координации. Необходим выбор владельца: primary receiver либо server-coordinated lease. Полностью offline рестарт с откатом часов/старого backup также не даёт достоверного elapsed time без дополнительного доверенного источника; безопасный режим должен закрывать доступ, а не продлевать его.

Отдельное предложение: RELAY-LIFECYCLE-PROPOSAL-1.2.0.md. Не изменяем серверный исходный код/production, legacy TTL и секретный формат до согласования этого блока. Клиентские независимые исправления продолжаются.

## Доказательства и границы

Перед изменением функциональных исходников подтверждены SHA-256 исходников/бинарников, прочитаны указанные фактические реализации, текущие операции/TTL пределы и snapshot правила. Нативные проверки 1.2.0, Tor на 1.2.0, реальный multi-account Friends/receipts/expiry, новый signed updater install/restart/rollback ещё NOT_RUN. Production feed/Relay/onion/private key не изменялись. productionReady=false.

## Дополнительный подтверждённый блокер FF1

После аудита прочитан crypto/LetterEnvelope.java: второй слой намеренно не имеет correctness oracle/authentication tag, каждый код даёт candidate, некорректный UTF8 показывается как hex. LiveCode показывает вычисление при каждом изменении кода. Поэтому «правильный FF1» нельзя проверить по non-empty text или decoder success. Автоматический READ/expiry при первом символе кода был бы ошибкой. Сам FF1/свойство отсутствия oracle не меняются. Необходимо отдельно согласовать явное действие показа окончательного candidate после ввода кода, с честной технической семантикой DISPLAYED, либо изменение формата защищённого письма — последнее не реализуется без отдельного решения.

## Обнаруженная при регрессиях гонка updater

UpdateService.failed публиковал FAILED до записи events/diagnostic.log; close лишь shutdownNow без ожидания завершения executor/periodic. В JUnit это воспроизвелось как повторная запись updates во время удаления temp profile. Изменены порядок commit→notification, cancellation/closed guards и ограниченное ожидание собственных задач; новый regression закрывает сервис во время прерванного fetch и проверяет отсутствие повторного создания удалённого тестового профиля. Проверка не отключает подпись, SHA-256 или anti-rollback.

## Поправка сборочного compatibility harness

После замены нативного input на опубликованную 1.1.5 старый build harness ошибочно использовал её staging Relay 0.3 исходник под названием relay02. Настоящая проверка capability=0 обнаружила ошибку; assertion не ослаблялся. В 1.2.0 harness отдельно загружает SHA-pinned исходник опубликованной 1.0.0 (Relay 0.2.0), компилирует его независимо и обозначает фактические client версии 1.1.5/1.2.0. Production VPS не используется.

## Проверки точных пакетов (первый прогон)

Собранный EXE/NSIS/runtime/DPAPI и 15 GUI/runtime сценариев прошли на Windows Server 2025. Client 1.2.0 на Windows Server/Ubuntu через встроенный Tor100% успешно проверил TLS и production Ed25519 manifest 1.1.5 и вернул FEED_BEHIND_CLIENT. Это не Windows11/CachyOS native PASS. Исторический DemoTorNetworkProbe ошибочно запрещал скачивание опубликованного подписанного source новее 1.1.0; ожидание актуализировано до exact SHA-pinned 1.1.5, без установки/изменения feed и без ослабления клиентской anti-rollback политики. Старый 1.1.0 Snowflake на Linux не достиг100% и перешёл к Direct; этот FAIL сохранён, новый mandatory forced Snowflake тест выполняется именно на 1.2.0 с новыми таймаутами.
