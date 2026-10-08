# Подготовка АЕГИС 1.0.0 — 2026-10-08

Готовы Windows portable ZIP, Windows Setup EXE, CachyOS AppImage, полный client-source ZIP, SHA256SUMS, unsigned manifest и отдельный owner-side native acceptance kit. Java21/Tor/Lyrebird/libsodium включены в клиентские пакеты. Все три бинарных артефакта сохранены с ранее проверенными SHA-256; текущая дополнительная работа обновила тестовый комплект, исходный архив и release metadata.

Проверено:

- 54 исходных JUnit: PASS, без failures/errors/skips.
- Расширенный JUnit прогон: 86 tests, 85 PASS, 1 native Windows DPAPI SKIP, 0 failures/errors.
- 16 release/security tests: PASS.
- 32 frozen server/protocol/config/deployment файла без изменений.
- ZIP/PE/icons/AppImage/runtime/JAR identity и SHA-256 проверены.
- JavaFX сцены проверены headless; это не native Windows DPI или CachyOS Wayland/X11 приёмка.
- Native kit на buildhost со встроенным runtime: 6 PASS, Secret Service FAIL_OR_UNAVAILABLE; D-Bus блокируется запретом Unix sockets. Это не PASS системного хранилища.

Открыты native Windows11/DPAPI/DPI/installer/updater/reboot, CachyOS/KDE/SecretService/Wayland/X11/reboot, реальный Tor100% и обмен Windows ↔ действующий Debian relay ↔ CachyOS с offline/ACK/TTL/файлами.

Ограничения frozen Relay0.2.0: bearer12h в RAM не обеспечивает буквальную семидневную беспарольную сетевую reauthentication; новый client AUTH KDF несовместим с existing server password hashes. Сохраняется совместимость и отдельное семидневное локальное разблокирование, account password не сохраняется.

**productionReady=false.** Release assets ещё не загружены в GitHub Release. Release, live stable/beta и production signature не опубликованы. Private release key не запрашивался, не читался и не передавался. Подпись выполняет только владелец offline после закрытия обязательной приёмки.

Этот commit публикует документацию и changelog; он не включает binaries, stable.json или stable.json.sig. Скачивание из GitHub станет доступно после отдельной публикации подписанного и принятого v1.0.0.
