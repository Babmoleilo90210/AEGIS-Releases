# Проверки АЕГИС 1.0.0

## Проверка первого запуска

Владелец подтвердил первоначальный процесс финальной приёмки и offline-подписи release manifest. Сам пользовательский установщик и launcher не требуют stable.json/signature. UpdatePreferences на новом профиле отключает автоматическую проверку и скачивание. Подписанные обновления по-прежнему проверяются; неподписанный код не устанавливается автоматически.

Новые результаты находятся в validation-simple. Старые результаты и SHA-256 ниже относятся к предыдущей упаковке и сохранены как история. Native Windows/CachyOS, Tor100% и реальный VPS/reboot остаются непроверенными; подпись и обычная установка не заменяют эти проверки.

## Архив предыдущего отчёта

# Проверки АЕГИС 1.0.0 — 2026-10-08

Продолжено сохранённое состояние 1.0.0, клиентские компоненты пересобраны. Relay 0.2.0/protocol1, его config, БД, registration, onion identity и installer не изменены. productionReady=false: обязательная native приёмка и два несовместимых с frozen AUTH требования не объявлены выполненными.

## Результаты

| Проверка | Результат | Доказательство |
|---|---|---|
| Сохранённый baseline | 54 tests, 0 failures/errors/skips | validation10/TEST XML и logs |
| Полный новый JUnit прогон | 86 tests: 85 PASS, 1 SKIP, 0 failures/errors | validation-final/*/TEST-*.xml, junit.log |
| Из них исходный baseline | Все 54 повторно PASS | Сопоставление suites/cases с validation10 |
| Новые проверки | 32: 31 PASS, 1 native Windows DPAPI SKIP | UpdateSecurityTest, UpdateTransportTest, RememberedLoginTest, AvatarPresetTest |
| Release/security tooling | 16 PASS | validation-final/release-security-tests.log |
| Frozen server/protocol/config/deployment | 32 SHA-256 без отличий | validation10/unchanged-server-protocol.json |
| Unified JavaFX selectors | 7 типов × 5 тем × 5 UI scales PASS | ui-selectors.log, ui-regression PNG |
| Contact picker / TTL popup | Search, Down, selection, scroll; 5 themes × 100/125/150/175/200% transforms PASS | picker smoke и PNG |
| GUI / update badge | Wrong password, live FF1, close/reopen, TTL, compact preview, verified/failed badge states PASS | ui-messenger.log, UI snapshots |
| Update progress | 34/72 MB=47%; установка запрещена до READY | clientUiRegressionSmoke |
| Bundled Tor/PT процессы | Explicit own config, localhost, fallback, state, чужой Tor сохраняется PASS | tor-and-regression.log |
| Публичный Tor bootstrap | 100% НЕ подтверждён; короткий lifecycle тест дошёл до Snowflake10% | тот же log |
| Независимый relay JVM | Bidirectional letters/files, offline/ACK/dedup/TTL/reopen/restart PASS через loopback SOCKS harness | process-exchange.log |
| Чистая Windows11/CachyOS/VPS | PENDING, среды/реальный onion не предоставлены | owner checklist ниже |

Здесь «независимый relay JVM» — отдельный процесс, собранный из неизменённых frozen 0.2.0 source, с Java21/SQLite и своей временной БД. Это не выпуск нового сервера и не утверждение о тестировании реального VPS. Сохранённые validation10 включают прежние проверки released0.3→1.0 migration и прежнего packaged relay; их provenance сохранён, они не выдаются за новый запуск недоступного 0.3 бинарника.

## Новая runtime безопасность

UpdateSecurityTest генерирует эфемерный Ed25519 key только в RAM. Positive tests проходят через package-private test seam с **тем же runtime signature/parser/state/download/transaction кодом**; production constructor всегда использует встроенный ключ владельца. Реальная positive signature именно ключом владельца ещё отсутствует и не подделывается.

Проверено: exact valid signature; JSON byte tamper; malformed unsigned data отклоняется signature до parse; wrong signature/key; duplicate/unknown fields; channel/protocol/date/URL; semver/anti-rollback; запрет same-version substitution; required только security/incompatible; dedup announcement; trusted history не принимает эфемерный или подменённый record; wrong hash/size; ZIP traversal; реальные byte progress states; interrupted/cancelled download не меняет old install и удаляет .part; install failure/no startup ack/previous .old приводят к rollback или безопасному отказу. UpdateTransportTest подтверждает loopback SOCKS и передачу hostname для remote DNS, allowlist и отсутствие direct fallback при Tor failure.

RememberedLoginTest проверяет отдельный случайный OS device secret, encrypted resume, отсутствие bearer plaintext на диске, 7-day local expiry, 12h relay expiry, clock rollback, wrong relay, AEAD tamper, явное удаление и открытие существующего modern vault. Native DPAPI test пропущен только потому, что текущий host Linux. Реальный Secret Service/KWallet round trip остаётся непроверенным: дополнительная попытка с изолированным GNOME keyring блокируется запретом Unix sockets в среде сборки; D-Bus не запускается. Это ограничение не записано как PASS.

AvatarPresetTest реально декодирует PNG/JPEG/WebP в bounded sanitized PNG, проверяет bytes/dimensions/symlink rejection, шифрование avatar и сохранность при rekey. UI preset tests проверяют CRUD, persist, JSON export/import, запрет duplicate/unknown/oversized/executable fields и неправильных значений. Старые crypto/AEAD/nonce, storage/TTL, files/ZIP, FF1, migration и relay isolation tests сохранены и повторены.

## Обнаруженные и исправленные проблемы

Сохранённый клиент не содержал runtime signed updater, отдельного updater EXE или встроенного release key. Они добавлены в production JAR/пакеты. Remembered local session, encrypted local avatars и presets ранее отсутствовали, теперь реализованы. Popup styling приведён к одному Selector. JavaFX looked-up numeric padding вызывал ClassCastException CSS warning; заменён типизированными density CSS classes, финальный GUI прогон без этих предупреждений. Legacy password field имеет label и контрастную рамку. У editable ComboBox prompt перенесён на control, поскольку skin мог перезаписать editor placeholder. Отказ после успешного startup acknowledgement больше не откатывает рабочую новую программу к частично удалённой .old из-за вторичной ошибки cleanup/shortcuts.

## Открытые функциональные условия

1. **Семидневная сетевая reauthentication без password storage** несовместима с frozen relay: token действует 12 часов и теряется при reboot. Реализован 7-day local unlock, действующий token возобновляется; при expiry/reboot запрашивается account password. Не отмечено как буквальный полный PASS требования.
2. **Client KDF AEGIS-AUTH-v1** изменил бы password material существующих server hashes; в protocol1 нет password migration/renewal API. Server auth сохранён, vault использует независимо salted/context-separated AEGIS-VAULT-v1. Не выдаётся за новый AUTH KDF.

## Owner-side native acceptance

Подготовлен отдельный `AEGIS-1.0.0-native-acceptance.zip`. Он запускается со встроенной Java готового клиента: `Run-Windows.cmd` на Windows или `bash Run-CachyOS.sh` на CachyOS. Устанавливать JDK/Gradle/Python или передавать пароль АЕГИС не нужно. Комплект создаёт искусственный временный профиль и локальный JSON-отчёт; аккаунты, рабочий профиль и relay не изменяет, данные никуда не отправляет. Подробности — README внутри комплекта и `NATIVE-ACCEPTANCE-STATUS-1.0.0.json`.

На buildhost Ubuntu этот комплект реально выполнен со встроенным Java21/libsodium: 6 checks PASS, проверка native Secret Service — FAIL_OR_UNAVAILABLE; процесс правильно вернул код 1. Проверены встроенный release public key, rejection unsigned manifest, все четыре современных AEAD, wrong password/nonces, E2EE identity binding, vault reopen и отказ сети при недоступном Tor. Test JARs не входят в production classpath; application JARs совпадают с обоими готовыми пакетами. Новые helper GUI сцены отдельно проверяются headless, что не подтверждает native DPI/Wayland/X11.

Проводите на копии профиля, обычным OS user, без глобальной Java/Tor. Не передавайте release private key клиенту или VPS. Для production positive update необходим подписанный владельцем controlled release; текущая unsigned заготовка каналом не становится.

Windows11:

1. Запустить Setup, проверить %LOCALAPPDATA%\Programs\AEGIS, один Start shortcut, original icons, отсутствие Administrator/отключения Defender. Затем проверить полный portable ZIP из user directory.
2. GUI появляется сразу; Tor/Control/P2P только localhost, второй запуск отвергается. Не разрешать публичные входящие Firewall ports.
3. Подключить реальный onion, registration open/closed/duplicate errors; создать аккаунт, выйти, перезапустить, войти одним password. На backup0.3 пройти one-time legacy vault migration, wrong-password rollback и сохранность identity/contacts/letters.
4. Включить Remember; перезапустить и reboot Windows; проверить DPAPI CurrentUser, expiry и «Завершить сохранённую сессию». После >12h или reboot relay ожидаем запрос account password для сети, local vault остаётся доступен до 7d.
5. Проверить все selectors/search/keyboard/scroll на **100/125/150/175/200% Windows DPI**, пять тем, legacy field contrast, avatarPNG/JPEG/WebP, presets CRUD/import/export.
6. Проверить Tor direct и stalled→Snowflake с реальным progress100%; отдельно запустить чужой Tor и убедиться, что закрытие АЕГИС его не завершает.
7. В Updates проверить Tor-only check, error unsigned/wrong signature, cancel/progress/notes/badge/system-letter dedup. На controlled signed update проверить AEGIS-Updater.exe detached wait, binary replacement, startup confirmation и forced-failure rollback, сохранность profile и Uninstall.exe. Это **ещё не выполнено** в текущей среде.

CachyOS/KDE:

1. Запустить AppImage без глобальной Java/Tor, проверить icon/KDE menu, XDG paths, persistent Tor state, restart и reboot.
2. Выполнить ту же account/migration/contact/letters/files/TTL/preset приёмку на **Wayland/XWayland и X11**. JavaFX21 здесь не объявляется native Wayland backend.
3. С доступным KWallet/Secret Service проверить Remember store/load/clear и locked/unavailable provider: никакого plaintext fallback. Затем reboot и 7-day expiry.
4. Проверить signed update в ~/.local/opt/aegis/AEGIS.AppImage: .new/.old, old PID exit, new startup ack, desktop Exec, failure rollback и restart. Реальная native приёмка pending.

Общий Tor/VPS сценарий:

1. Windows ↔ Tor100% ↔ существующий Debian Relay0.2.0 ↔ Tor100% ↔ CachyOS. Обменять защищённые письма туда/обратно, семь произвольных файлов, AES ZIP с letter password и incorrect-key failure.
2. Отключить получателя; relay хранит только ciphertext до ACK. Подключить; проверить ACK removal, duplicate suppression и TTL от первой confirmed delivery.
3. Полный reboot VPS с той же DB/onion, reboot обоих клиентов. Проверить localhost19110, systemd autostart, контакты и identity; ожидается необходимость нового server login после сброса RAM sessions.
4. Подтвердить отсутствие passwords/keys/plaintext/cookies в production logs/DB/transport; не публиковать dumps, private keys или control cookie как доказательство.

После приёмки обновить audit фактами и evidence hashes. До этого **не подписывать/не публиковать stable как production**. Подпись сама по себе не заменяет эту приёмку.
