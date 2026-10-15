# АЕГИС 1.0.0 — кандидат для финальной приёмки

Обычный запуск не требует от пользователя signing key или команд подготовки релиза. На новых профилях автоматическая проверка и скачивание обновлений выключены; существующий явно сохранённый выбор сохраняется. Подпись manifest выполняет владелец offline после приёмки.

Windows и CachyOS клиенты совместимы с неизменённым Relay 0.2.0 / protocol1. Пересобраны клиентские компоненты: signed Tor updater с встроенным Ed25519 root key и AEGIS-Updater.exe; rollback и startup confirmation; локальные avatars; компактный preview; 5 UI presets/custom JSON; device-bound remembered local unlock без account password storage. Сохранены миграция 0.3, AES/FF1 письма, arbitrary multi-files, AES-256 ZIP и TTL.

Исходные 54 JUnit и 16 release/security tests повторены, дополнены runtime updater/session/avatar/preset/Tor HTTPS тестами и JavaFX regression. ZIP/AppImage содержат Java21, Tor/Lyrebird/libsodium; source содержит код, build scripts и результаты.

Дополнительно подготовлен отдельный native acceptance kit для проверки уже готовых пакетов со встроенной Java на Windows и CachyOS. Отчёт сохраняется локально без паролей, ключей и автоматической отправки. Владелец подтвердил наличие обоих устройств; их проверки ещё не выполнены. Комплект не меняет production classpath, сервер или рабочий профиль.

**Production status: BLOCKED.** Native Windows11/DPAPI/DPI/installer/updater и CachyOS/KDE/SecretService/Wayland/X11 не доступны в текущей среде; реальный onion/VPS/Tor100% и reboot приёмка не закрыты. Relay bearer ограничен 12 часами и RAM; беспарольный 7-day сетевой login и новый client AUTH KDF требуют изменения frozen auth или хранения account password, что запрещено. Локальный 7-day unlock реализован, это ограничение отдельно раскрыто.

Release и live stable канал не опубликованы. Production signature не создана. FINAL-RELEASE-AUDIT-1.0.0.json перечисляет доказательства и открытые критерии; TEST-REPORT-1.0.0.md содержит owner-side checklist. Не публиковать stable как production до закрытия обязательной приёмки.
