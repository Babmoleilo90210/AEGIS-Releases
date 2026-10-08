# АЕГИС 1.0.0

Клиентское обновление 0.3.0. Relay 0.2.0/common-protocol/server deployment оставлены без изменений; Debian package не выпускается.

- Один пароль входа; новый vault KDF с domain separation. Полная проверяемая миграция старого vault, backup до открытия, journal/rollback и AEB1/AEB2 identity backup.
- Регистрация без второго постоянного пароля. Пароль каждого письма и FF1 code остаются независимыми.
- Нативный searchable contact ComboBox, компактные контакты и fingerprint по отдельному действию.
- TTL ComboBox перенесён выше composer, popup оформлен для пяти тем; большой список вложений прокручивается.
- До 64 обычных файлов любых типов в одном письме. Совокупный лимит сохранён. Duplicate names получают суффикс; traversal/ADS/device names отклоняются.
- Локальное скачивание всех вложений в один WinZip AES-256 AE-2 ZIP через Zip4j 2.11.6. Пароль совпадает с паролем письма. Нет незашифрованных временных файлов, overwrite или auto-execute.
- GUI появляется до bootstrap. Сохранённый onion подключается автоматически. Tor state не удаляется, последний успешный mode запоминается. Stall watchdog: direct 30 s без роста progress, Snowflake 75 s; глобальные пределы 150/300 s. Режимы запускаются последовательно.
- Безопасная классификация настоящих Lyrebird STATUS/LOG/stderr: broker errors/connected/status, без сохранения сырого текста.
- Windows Setup обнаруживает установленную версию, делает backup и сохраняет старые binaries для rollback. HKCU/per-user installation и прежние shortcuts.
- AppImage предлагает обновление известного установленного образа и заменяет его атомарно после миграции; стабильный desktop Exec без версии.
- AppImage собирается в новый временный файл и проходит реальное извлечение, проверку ELF/SquashFS, сравнение всех payload SHA-256 и запуск Java21 до замены готового релиза.

Найдено и исправлено при разработке: рекурсия value/editor при фильтрации editable ComboBox; повторный запуск Tor во время bootstrap; устаревший ответ проверки другого сервера; прежний whitelist файлов; отсутствие полного backup mail/sent; потенциальное рекурсивное копирование backup внутрь source; несогласованный PID view при host-mounted /proc (Linux updater теперь закрепляет namespace-aware pidfd).

Проверки: TEST-REPORT-1.0.0.md. Независимый криптоаудит, настоящая Windows DPI/installer приёмка и native CachyOS/Wayland/X11 по Tor пока не выполнены.

## Завершение текущего кандидата — 2026-10-08

- Production client JAR теперь содержит pinned Ed25519 update verifier, Tor HTTPS transport, строгий manifest, anti-rollback, download/cancel/progress, optional/required policy, signed notes/history и локальные системные письма.
- Windows пакет содержит реальный AMD64 AEGIS-Updater.exe; helper запускается вне старого Job Object, ожидает PID/start time и startup confirmation. Сохраняется Windows uninstaller. CachyOS использует постоянный AppImage с атомарной заменой и rollback.
- Семидневный локальный unlock через DPAPI CurrentUser / Secret Service без password storage. Ограничение существующего relay: token 12 часов, при reboot теряется; для нового network login нужен пароль. Буквальная семидневная server reauthentication и client AEGIS-AUTH-v1 несовместимы с замороженным protocol/auth и остаются открытыми условиями.
- Локальные encrypted PNG/JPEG/WebP avatars, placeholder и contact picker avatars, лимиты bytes/dimensions, удаление metadata.
- Компактный NAV / MAIL LIST / MAIL PREVIEW; 5 presets, custom JSON CRUD/import/export, scale/density/sidebar/avatar/preview/subject/date.
- Единый Selector для всех dropdown; исправлен CSS warning плотности списка, повышен контраст старого парольного поля и ссылок в светлых темах.
- Добавлены runtime updater, session, avatar/preset и Tor HTTPS security tests; повторены исходные 54 теста и 16 release tooling tests. Native Windows/CachyOS/VPS acceptance отдельно отмечена pending, productionReady не повышен искусственно.
- Relay/common-protocol/config/installer остаются byte-identical по 32 frozen SHA-256. Никаких публикаций, live unsigned manifests и production signatures не создано.

## Дополнение к приёмке — 2026-10-08

- Отдельный native acceptance kit запускается на Windows и CachyOS со встроенной Java готового клиента. Проверяет packaged JAR hashes, шифрование, libsodium, vault reopen, OS credential store и GUI; сохраняет локальный JSON без паролей/ключей и без upload.
- Kit не входит в classpath обычного клиента и не меняет relay или рабочий профиль. Его buildhost проверка: 6 PASS, native Secret Service недоступен из-за запрета Unix sockets; это не считается native Windows/CachyOS приёмкой.
