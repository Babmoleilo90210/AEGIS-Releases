# АЕГИС6.0.0 — отчёт о реализации

## Происхождение

Разработка продолжает прежние Java/JavaFX-модули. Опубликованный5 commit38a3e6469a40e6edcb1b0448f906a488c73feb5d отличается от source commit его бинарников37779c113553bf5e1a42642e7ca7a010db9bdd4e. Базовые1725blobs/modes были сверены. OwnerZIP SHAeb44b087e8daa42c8cbd4dc108565d2c21783550ddd4e1cb632b3bae2ace6703 и CRC повторно проверены19Oct. Восстановленный6snapshot SHA11b8b2de70c10508725c510f77c46ef10643d9bd6f867b6907b17e0a221bea2f импортирован новым commit a60162862c0f1e0e693599dc3145a2a01288c012, затем потерянные изменения восстановлены. Старые отсутствующие Git objects не имитируются. Точный итоговый commit находится во внешнем SOURCE/BUILD-PROVENANCE.

Использован утверждённый PDFAEGIS_6_WORK_FULL(1).pdf версии18.10.2026(20разделов). Недоступные chat share/прикреплённые изображения не объявляются изученными. JavaFX снимки приложения действительно получены исполнением программы, не генерацией изображений.

## Идентичность и Core

Прежний Ed25519 root key остаётся только в Почте; существующая почтовая криптография, FF1/password, архив и форматы не заменены собственным шифром. Core хранит публичные account/recovery keys и другой Ed25519 device key в Argon2id/AES-GCM vault. Приложения имеют разные proof keys. Capabilities связывают audience/account/device/app/generation/scopes/expiry. Новый активный вход атомарно отзывает прежнее поколение. Офлайн-присутствие имеет отдельный ACCOUNT_READ permit и максимум24часа с monotonic/wall-clock checks; новые привилегии офлайн не выдаются.

Восстановление требует Mail identity backup и независимый.aer6. Core сначала сохраняет новый device key, затем отправляет две фиксированные подписи Почты. Старый recovery key отвергает сервер; повтор сохраняет device secret. Публичная metadata обновляется с сохранением предыдущего encrypted vault и rollback при ошибке; fault injection питания/fsync отдельно не выполнен.

Типизированные Mail согласия охватывают привязку, step-up, голосовой grant, Owner Bootstrap, первую делегацию, передачу владельца и recovery. Универсального API root-подписи произвольных байтов нет. Через bounded MAC IPC возвращаются публичные данные/фиксированные proofs, а не пароли/private keys.

Owner Bootstrap завершается операторской CLI, не HTTP-кнопкой. Дальнейшие критические операции требуют двух независимых действующих администраторов; проверяются live session/generation, свежий step-up и exact persisted permit. criticalInspect связывает отображаемого инициатора, операцию, payload SHA, ID и срок. Revoked-admin tombstone не позволяет внешнему устаревшему источнику вернуть отозванные права. Guard сохраняет независимый кворум после отзыва/передачи Owner. Никнейм и галочка не являются административной авторизацией.

Core интегрирует реальные серверные Community/News/Library/Management/Notifications. Навигация и Appearance Engine сохранены; шестнадцать пресетов не заменены новым оформлением. Никакие почтовые пароли не вводятся в Core. Основной интерфейс и standalone entrypoints используют общий runtime inventory.

## Процессы, блокировка и откат

Core, Почта и Глас имеют ограниченные рабочие очереди и аутентифицированные дочерние процессы. Lock сразу отзывает локальную сессию/экран, очищает PasswordField и отменяет consent worker; поздний callback не восстанавливает данные. Полный выход сохраняет очередь Почты и завершает управляемые компоненты/защищённую Библиотеку. Личный Obsidian и Взор остаются независимыми.

Runtime leases удерживаются до реального выхода JVM. Они запрещают замену используемых файлов. Core-only Windows rollback проверяет fixed installation/rollback6, точные PID/образы javaw и launcher, reparse paths, SHA maintenance helper, отдельный private staging/cwd и native exclusive guard. Mail6 не запускает старый автоматический rollback1.1.5. Нативный install/restart/rollback всё ещё нуждается вWindows11.

## Взор и Библиотека

Взор использует официальный Tor Browser, OpenPGP-проверку и независимый manager. Не получает account capability, переписку или keys. Linux boundary использует bwrap/namespaces/Xephyr/slirp; Windows — поддерживаемую Sandbox. Нет молчаливого ослабления при отказе. Проверяются canonical пути Core/config/Mail/defaultarchive/guards и конфликт с браузерными каталогами. Slirp не объявляется kernelTor-onlyfirewall против полностью скомпрометированного браузера.

LibraryACL проверяется до содержимого/файла/поиска/графа. Owner не обходит закрытыйREAD. Разрешённое название закрытого узла не раскрывает тело. Для projection нужны отдельные короткие READ grants с hash/revision/epoch; expiry lane очищает plaintext даже при зависшем RPC. Cache отдельный AES-GCM с OS secret storage; при его недоступности явный online-only режим. Уже полученные офлайн-копии нельзя гарантированно стереть на чужом отключённом устройстве.

Официальный Obsidian имеет отдельные personal/protected profile/vault. Защищённому процессу выдаётся лишь одобренная projection, без сети/DBus/домашнего каталога/архива; личные плагины не считаются sandboxed. Реальный защищённый коннектор заменяет небезопасный Syncthing всего закрытого vault в рамках разрешенияPDF9. Разделение серверной службы sync и нативная синхронизация остаются ограничением приёмки. Android закрытыйvault внешнемуObsidian черезsharedstorage не выдаётся.

## Почта и Глас

Настольные вложения500МиБ реально подключены к compose/viewer/очереди и согласованию возможностей. Применён TinkAES256GCMHKDFStreaming, ограниченные чанки/квоты/TTL≤30дней/resume/cancel. Master key внутри прежнего libsodiumE2EE и protectedFF1/password envelope; сервер хранит непрозрачныйciphertext. Созданный файл не запускается автоматически. Старый протокол5 сохранён для совместимых клиентов, enrolled6 не получает небезопасный legacyloginfallback.

Глас сохраняет прежний Tor-only onion/SOCKS транспорт, TLS1.3 identity binding, разные app/sessionkeys, Opus/Speex и encryptedlocalhistory. Микрофон/аудио не включаются до принятия и аутентификации. НетICE/STUN/TURN/прямогоUDPfallback. Проверены localduplex/mute/identity/replay/revocation/cleanup с настоящими сервисами/нативным codec, но syntheticPCM/localSOCKS не является физическим звонком через публичныйTor.

## Сервер

Отдельные Identity, Community, LibraryController, opaqueAttachments, GlasSignaling, Management и MailRelay6 не изменяют старый productionRelay. NewsWorker6 имеет отдельный servicekey, namespacedactor и operatorallowlist. UserGateway отклоняет agent.worker.* доACL. Подпись связывает exactbody/audience/time/nonce; replay persistente, quotas/rates проверяются вSQLiteTX. У worker нет административных или приватных почтовых ключей. Полноценный publicRSS→реальнаямодель→autopublish всё ещё требует доступной сети/провайдера и отдельной проверки.

Debian пакет содержит sysusers/systemd/AppArmor, отдельные каталоги/ключи/лимиты, onion/WireGuard templates, fixedmanagementoperations/staging, encryptedbackup/restore и monitoring. Привилегированныйbackup не разбираетSQLite; parser изолирован отдельно. НативныйDebian13 и аварийное восстановлениеVPS не выполнялись наUbuntu. ОдинVPS сохраняет общий риск отказа.

## Android

ЧетыреAPK с разнымиUID/PackageID безsharedUID используют Binder с проверкойUID/пакета/сертификата/proof/cap/gen/scopes. FLAG_SECURE и защитаoverlaytouch действуют в доступныхAPI, не защищают от внешней камеры/rootedOS. PackageInstaller требует системного согласия. Strazh реально анализирует выбранныйAPK/manifest/signature/permissions с лимитами, не обещает обнаружитьвсеspyware.

CoreTorService, sodiumJNI, Opus/SpeexJNI и hev/lwIPTUN engine настоящие. TCP/DNSfiltering не подменяется пустымVPN. Logout security lane выполняет обязательную очистку послеpause/destroy, queued password arrays очищаются; lateMICgrant/lateLogin/Torbindingdeath/cleanupqueue races закрыты. Перед выходом не запускается новыйTor дляrevocation.

AndroidMail имеетреальныеRelay6/E2EE/send/fetch/ACK и protectedpassword/FF1. Глас имеет реальныйконтроллер/TLS/media. Полная desktop-parity архива/P2P/потоковых500МиБ/фоновыхуведомлений и полноценный per-appTorVPN остаются незавершёнными. ФизическиеART/Binder/FGS/Doze/mic/VPN/FLAG_SECURE не приняты. NativeARM64 библиотеки собраны, не заявлены запущенныминаустройстве.

## Доказательства и выпуск

TEST-REPORT6 перечисляет фактически выполненные проверки. Их counts не суммируются как уникальные, старые receipts не сертифицируют новые исходники. Итоговый clean/test/assemble фиксирует всё дерево, CRC/SHAJAR, команды иXML. WindowsSetup/Portable, CachyAppImage, Debian tar, AndroidAPK и sourceZIP должны соответствовать одномуcommit. Gitbundle позволяет владельцу получить неопубликованнуюисторию без.git/config/buildsecrets.

Manifest сохраняет Ed25519/SHA256/antirollback иstrictversion/tag/URL. Подготавливаются неподписанные документы; ownerreleasekey и отдельныйAPKsigningkey не используются. Финальная подпись/приёмка/публикация принадлежат владельцу. Productionинфраструктура/feed не менялись.

НедоступныеWindows11/CachyOS/Debian13/Android, две физические сети, publicTor/leaks/длительныйголос, updaterE2E/rollback и реальные незавершённые функции блокируют productionReady. Время ожидания и успешная сборка не доказывают готовность. Кандидат передаётся с точными файлами/хешами/ограничениями, не как фиктивно готовыйStable.
