# Нативная приёмка АЕГИС 1.5.0

Выполняется владельцем на копиях профиля Windows11x64, CachyOS KDE Wayland и CachyOS KDE X11. CI Windows Server/Ubuntu и Monocle не заменяют эти три платформы. Все исходные native строки — NOT_RUN. Для каждого случая сохраните PASS/FAIL/SKIP/NOT_RUN, версию/OS/DPI, безопасное доказательство. Не присылайте пароль/ключ/письма/Tor cookie/production profile.

## Запуск

ZIP kit отдельный от приложения. Run-Windows.cmd или `bash Run-CachyOS.sh <AppImage>` запускают базовые проверки встроенным runtime. Run-Appearance-* проверяет реальную JavaFX сцену архива на синтетическом профиле, а не production данных. Основную ручную приёмку проводите через обычный АЕГИС с двумя тестовыми аккаунтами; окна/масштаб/родной compositor нужно проверить глазами.

## Архив ARC-01–40

| ID | Действие и ожидаемый результат |
|---|---|
| ARC-01–06 | Создать пустой архив с независимым паролем; правильный открывает, неправильный нет; смена пароля сохраняет objects; recovery открывает, отсутствующий/отключённый нет. |
| ARC-07–09 | Таймер1мин/ручная/закрытие блокируют; поиск/preview очищаются; повторное открытие без Tor работает по паролю. |
| ARC-10–13 | Сохранить обычное и раскрытое protected письмо с FF1, attachment и свой файл; оригиналы и таймеры не изменены. |
| ARC-14–19 | 12levels folders/depth/cycle rejection; tags/star/date/type/folder/sort/fulltext; на диске индекс encrypted; повреждённый index rebuild без потери objects. |
| ARC-20–24 | JPG/PNG/WebP, UTF8/PDF preview внутри главного окна; unsupported/large export; export/external require встроенное предупреждение. |
| ARC-25–30 | Duplicate warning без замены, DnD/menu move, trash/restore/purge, quota/size/status корректны. |
| ARC-31–34 | Manual+schedule backups, archive/separate password; restore на другом устройстве отдельно/merge; conflict не перезаписывает; copied ciphertext без secrets unreadable. |
| ARC-35–36 | На копии повредить header/catalog/index/object; fail closed/repair diagnostic copy; kill process во время записи и проверить prepared-commit recovery. Физическое power-loss только на expendable VM. |
| ARC-37–39 | Explorer/Dolphin/другой OS account видит только ciphertext UUID; ACL/POSIX owner-only; перенос правильный пароль/first-device verification. |
| ARC-40 | Disappearing archivecopy после warning, countdown original сохраняется; без consent не архивируется. |

## UI-01–30

Проверьте default nav order, центрирование/hitareas/intervals; LEFT/TOP/BOTTOM и custom order; compact header nickname+accurate status; autoTor/inlinepassword/offline; noFriendsUI/contacts preserved; compose insideLetters; settingscategories; noextraStage/toasts; single retention selector; 16presets+legacygreen/custom/fonts; DPI100/125/150/200 и KDEfractional; maximum/minimumwindow; archive list/table/cards; persistence/restart; nooverlap/blankStage. Все 30 пункта оцените отдельно, а не одним «всё работает».

## P2P-01–10

Сохраните только protocol operation counts/message IDs/public route/transport status, не payload. Два устройства с разными тестовыми аккаунтами/профилями/Tor directories. ONLINE+Tor+Relay → signed peeronion preferred; Relay off после координации → direct пока lease действителен; peeroffline → Relaycipherqueue/ACK; reconnect → delivery безduplicates; разныефизические сети/OS; file; protectedFF1; signed delivery/read event; disappearingtimer. Технические сведения показывают маршрут только при его доказательстве. Отключение/отказ ACK не выдаёт ложную delivery и не сбрасывает TTL.

## Миграция и regression

Копия профиля1.2 с письмами/receipt/expired/contacts/themes/layouts/fonts/updatehistory и Secret Service/DPAPI session. First1.5 создаёт fullsnapshot до sidecar changes; identity/salt/keys не меняются, countdown не сбрасывается. Повторный старт не создаёт дубликаты. Проверить registry/login/offline/letterpassword/FF1/files/blocking/search/TorDirect/Snowflake/Relay/oldclientcompatibility. Нативный reboot каждого клиента, перенос snapshot и программа/datarollback отдельно.

## Updater E2E и rollback

Только отдельно разрешённый Beta feed, exact1.5.0 assets и offline owner Ed25519 signature. Previous установленный1.2 → Tor → signedmanifest → systemletter → download+progress/resume → SHA/size/package → consent → completebackup → helper безпустогоокна → restart → startuphealth → systemsuccessletter → keys/mail/theme/TTL/archive preserved. Второй тест моделирует failedstartup на disposable profile и подтверждает возврат прежних binary/data; не делайте fail fixture вproduction binary. Fixture verifier с временным ключом неownerSignedE2E.

Полученные evidence и native-result CSV/json приложите отдельно. Пока хотя бы mandatory gate NOT_RUN/FAIL, productionReady=false и Stable не публикуется.
