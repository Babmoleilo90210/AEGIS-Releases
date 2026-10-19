# Desktop 6.0: Core, Почта, Глас и миграция

Это отчёт об ограниченной области desktop-компонентов. Он не присваивает всему АЕГИС статус Stable. `productionReady=false`: нативные Windows 11/CachyOS, реальный Tor, два физических устройства и финальная приёмка здесь не выполнялись.

## Реализованные процессы и доверие

`DesktopProcessBroker` действительно запускает отдельные JVM только из проверенного JVM/JAR inventory. Main class, параметры JVM и виды компонентов фиксированы. У запуска есть один pending slot на компонент, сроки bootstrap/READY, отдельные ограниченные writer/reader/authorization workers, heartbeat, отмена при закрытии/блокировке Core и подтверждение фактического завершения через сохранённый `Process`. Медленный Identity RPC не держит общий monitor и не задерживает heartbeat другого ребёнка. Повторный stop не отправляет несколько команд сохранения. Чужие PID не сканируются; непроверяемый PID namespace не используется для завершения посторонних деревьев.

Билет и уникальный app proof key передаются только анонимным stdin pipe. IPC v3 проверяет PID непосредственно созданного процесса, одноразовый билет, HMAC, направление, тип, размер и монотонную последовательность. MAC также связывает публичный grant. Аргументы, окружение, файлы и журналы не содержат билет или приватный ключ. Public configuration paths передаются как обычные пути. `aegis.profile` наследуется только при явном override у родителя; сохранены XDG paths и XAUTHORITY.

Production `ComponentEntrypoint` выбирает ровно один подходящий ServiceLoader provider. Mail/Glas независимо проверяют pinned Identity signature, account, app, generation, app proof key, срок и live status. Пустые fixture credentials production-провайдеры отвергают. Простой запуск main без pipe не разрешает доступ.

## Почта

`LegacyMailComponentHost600` повторно использует существующий `MessengerApp`, архив, поиск, контакты и письма. Навигация и настройки ограничены почтовыми функциями. Существующие Appearance Engine и 16 пресетов остаются. Старый голосовой сервис в этом режиме закрывается до Relay login, без изменения сохранённой политики пользователя. Долговременный account private key открывается только в процессе Почты.

`MailComponentGate600` проверяет фактическую identity разблокированного vault до Relay authentication, polling и UI. `IdentityRelayCredentials600` устанавливаются перед LOGIN6, в том числе перед legacy vault rekey authentication. Настройка `core600/relay600.properties` содержит только `servicePublicKey`. Если доверенный Relay6 не настроен, production Mail host отказывает. Переключения на старый LOGIN нет. Сохранённый старый bearer не используется для обхода LOGIN6: локальный remember-vault сохранён, повторный сетевой вход требует LOGIN6. Полностью автоматический proof-bound RESUME6 требует отдельного серверного расширения.

Блокировка удаляет приватные controls/просмотры, запрещает независимый login и закрывает реальный LocalStore. Shutdown ждёт persistence/закрытие сессии; FLUSHED не выдаётся до завершения callback. Обычный черновик сохраняется в существующем зашифрованном lifecycle sidecar. История UUID непрочитанных писем хранится там же; Core получает только integer count. RAM-only пересылаемый FileBundle пока не превращён в долговременный attachment spool: восстановленный черновик явно предупреждает и запрещает отправку до повторного прикрепления/подтверждения удаления. Это ограничение не объявляется полной сохранностью таких вложений.

Ссылки из письма проходят существующий SafeWebUrl validator. По IPC передаётся только выбранный URL, не тело письма.

## Явное согласие в Почте

`MailPairingBroker600` запускает отдельный фиксированный `MailPairingEntrypoint600`. Это самостоятельный purpose-specific entrypoint, а не разрешение открыть обычную Почту без capability. Допустимы только регистрация устройства, step-up Identity и делегация Гласа. Нет произвольного payload-to-sign RPC.

Пользователь локально вводит пароль Почты и подтверждает точное действие. Регистрация создаёт независимый recovery Ed25519 key в зашифрованном Mail sidecar; до согласия требуется сохранить и проверить зашифрованный recovery export. Core получает только public account/recovery/device data и подпись точного домена. Новый аккаунт и его root key создаются и регистрируются в Relay только процессом Почты.

Перед отдельным consent процессом уже работающую Почту требуется остановить с FLUSHED: общий app lock не обходится. Отмена закрывает только принадлежащий broker процесс.

## Реальная миграция до первого pairing unlock

`MailProfileMigration600.beforeOpen` встроен в Mail consent unlock. Пароль vault и независимый пароль архива не попадают в Core. Сначала проверяется минимальная копия зашифрованной identity, затем `ProfileMigration600` создаёт streaming AES-GCM-HKDF encrypted backup, проверяет весь backup, копирует профиль, проверяет inventory и семантику на отдельной рабочей копии, атомарно публикует новый каталог и только после этого атомарно переключает ClientConfig.

Проверяются identity/key pair, pinned contact public keys, подписи сохранённых входящих/исходящих пакетов, целостность основного архива и точность переноса settings/themes. Защищённые письма не требуют обхода letter password: сохраняется и проверяется подписанный ciphertext. Для нового пути архива выполняется полная проверка и создаётся новый path-bound integrity guard. Старая директория vault/архива остаётся нетронутой. При ошибке/cancel config не переключается; зашифрованная копия остаётся для восстановления. Повторный запуск после переключения идемпотентен.

Ограничение: внешний/custom archive path не объявляется автоматически перенесённым. Такой профиль получает явный отказ с причиной до переключения. Нужен отдельный полный перенос внешнего архива. Дополнительные восстановленные encrypted archive directories копируются и сверяются побайтно; отдельная криптографическая приёмка каждого архива с собственным паролем не подменяется общей проверкой основного архива.

Точный опубликованный 5.0 JAR из AppImage проверен отдельным JVM fixture: identity, E2EE письмо, контакт, архив, тема и Tor settings читаются после восстановления полного pre-6 snapshot. Старый 5.0 rekey не знает новые lifecycle имена и корректно отказывает; перед downgrade нужно восстановить полный pre-6 snapshot, а не запускать старый rekey поверх изменённого 6.0 профиля.

## Самостоятельный Глас

`StandaloneGlasComponentHost600` и `GlasApp600` не создают ClientSession и не открывают Mail vault. `VoiceLocalStore600` отделяет существующий голосовой движок от legacy store, сохраняя прежний v1 адаптер для совместимости. Новый Глас использует отдельный app private key и публичную Mail-signed Delegation. Отдельный root-signed фиксированный contact export связан с delegation hash.

TLS v2 (`aegis-glas/2`) связывает account root → app delegation → подпись свежего ephemeral TLS certificate → call ID, роль и получателя. Используется стандартный SunJSSE TLS 1.3 и KeyUpdate; собственный cipher или key schedule не вводится. Прежний v1 wire остаётся неизменённым. Понижение v2 в v1 отклоняется.

`GlasOnionTransport600` создаёт loopback listener и ephemeral Tor onion через SAFECOOKIE. Исходящий connector — существующий onion-only TorTransport. Перед обеими ролями TLS выполняется свежий pinned signaling LOOKUP; входящее и исходящее разрешения проверяются в разных направлениях. Во время звонка отдельный worker обновляет разрешение, аудиопуть читает только monotonic lease ≤5 секунд. Принятый звонок продолжает требовать эту lease и при потере TLS; отзыв не маскируется циклом reconnect. Сервер сигнализации не получает аудио.

Захват/Opus/шумоподавление, ограниченные очереди и audio device UI повторно используют действующие компоненты. Аудио не открывается до принятия и аутентификации. Микрофон включается явным действием. Нет временных аудиофайлов или скрытой записи.

Отдельные settings/history шифруются AES-GCM случайным ключом из DPAPI/Secret Service, без Mail root. На обычной блокировке история и её ключ убираются из RAM; остаются только narrow voice app key, immutable public contact/policy cache и listener. Ограниченный экран принимает/отклоняет входящий после fresh authorization, не открывая список контактов/историю/outgoing. Полный выход и отзыв закрывают транспорт и voice state.

Для запуска нужны операторские публичные настройки `core600/glas600.properties`: `onion`, `port`, `servicePublicKey`; Identity берётся из уже настроенного `identity.properties`. Изменения production сервера не выполнялись. Недоступность Secret Service/Tor/pinned signaling вызывает явный fail-closed статус.

Открытые ограничения: native DPAPI/KWallet и реальная маршрутизация/качество Tor не приняты; организационные исключения VoiceOrganizationAuthorizer требуют отдельной live integration и по умолчанию DENY; аватар standalone Гласа пока показывает явную initials placeholder при отсутствии полученного изображения; contact grant ограничен 256 контактами и отказывает при превышении вместо молчаливого обрезания. TLS desktop provider не выдаётся за Android-совместимый.

## Доказательства и границы

Реальные отдельные JVM, HMAC replay/подмена, kernel exit/lock release, Crypto/AEAD, mutual TLS sockets, encrypted backup restore и exact-5 binary probes выполнялись. В audio/Tor unit fixtures используются явно обозначенные loopback/media/OS-secret seams. Они не являются испытаниями между физическими устройствами. JavaFX PNG получены снимками реально отрисованных controls в Monocle; это не нативная Windows/CachyOS приёмка.

Итоговые численные результаты и SHA256 файлов доказательств находятся в `EVIDENCE-6.0.0.json` рядом с этим отчётом. Предыдущий полный прогон обнаружил один реальный revoked-lease/reconnect дефект; он описан выше и исправлен. Ошибочный прогон не объявляется PASS.
