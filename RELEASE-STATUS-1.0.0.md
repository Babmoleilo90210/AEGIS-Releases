# АЕГИС 1.0.0 — установка и проверки

Для запуска используются обычные Windows Setup EXE / portable ZIP и CachyOS AppImage. Java21/Tor включены. Обычному пользователю не нужно подписывать файлы перед установкой. Для публикации stable-релиза владелец подтвердил порядок: финальная приёмка, затем offline-подпись manifest. Автоматическая проверка и скачивание обновлений на новом профиле выключены. Проверка цифровой подписи при использовании необязательного встроенного updater сохраняется.

Сборки упакованы; проверены Windows PE/иконки, ZIP, полный payload AppImage, runtime21 и совпадение общих application JAR обеих ОС. Клиент запущен со встроенным runtime и настоящим MessengerApp.start в headless Linux: первая форма появляется без manifest/signature. Это не native Windows/CachyOS тест и не подтверждение Tor100%.

Результаты: 86 JUnit, 85 PASS / 1 Windows DPAPI SKIP, 0 failures/errors. После изменения повторно выполнены 75 client-core tests; сохранены успешные результаты 11 неизменённых common/relay/integration tests. Все 54 исходных случая присутствуют. Повторены 16 release/security tests и JavaFX UI regression. Все 32 frozen server/common/protocol/config/deployment файла неизменны: Relay0.2.0 / protocol1 сохраняется.

**productionReady=false:** реальная Windows11, CachyOS/KDE, Tor100%, обмен через действующий VPS из разных сетей, offline/TTL/файлы и OS/VPS reboot ещё не подтверждены. Формальная подпись для обычной установки не является блокирующим условием. Локальное remembered unlock действует 7 дней; прежняя серверная сессия — 12 часов и сбрасывается после reboot relay.

**GitHub Release assets пока не загружены.** Пользователь получает готовые файлы в сообщении с результатом; ссылки releases/download/v1.0.0 в гайдах заработают после загрузки. GitHub содержит документацию и changelog, live update manifest/signature не публиковались.

## SHA-256 текущих сборок

| Файл | SHA-256 |
| --- | --- |
| AEGIS-Setup-1.0.0-x64.exe | `65105ce90fc1e7f8e2bf9741a484ad2c9c291d43d11065d207ed1ce44ac0dfc7` |
| AEGIS-1.0.0-Windows-x64.zip | `f8dd50b1365388a662df1ae9be30a3c14f9de3ce67db34fe53f179648e614205` |
| AEGIS-1.0.0-CachyOS-x86_64.AppImage | `1e7b22de4ba40baef552093561d99171be1e95e8d89019008ad446fd3eefc7a3` |
