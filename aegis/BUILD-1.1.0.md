# Сборка кандидата 1.1.0

Java 21 обязателен. Обычная сборка: `./gradlew build`. Зависимости и verification metadata остаются закреплены в Gradle; новые runtime-библиотеки не добавлены. `tools/build-local.py` — явно заданный offline fallback: берёт JDK 21 и проверенные JAR-файлы из указанных каталогов, ничего не скачивает.

`python3 tools/build-local.py --jdk /path/jdk21 --deps /path/verified-client-jars --deps /path/test-relay-jars --native-root /path/verified-linux-base`

`python3 tools/run-ui-regression.py --jdk /path/jdk21 --deps /path/verified-client-jars --deps /path/test-jars --native-root /path/verified-linux-base --test Aegis11UiSmoke`

Кандидаты используют проверенные runtime/Tor/libsodium из выпущенных 1.0.0 платформенных пакетов; исходный дизайн иконки сохранён. Java-компоненты 1.1 и Windows launchers собираются заново. JavaFX classifier каждой платформы берётся из соответствующего пакета, Linux JavaFX не подменяет Windows DLL.

Сборка на development branch GitHub Actions содержит только исходники и синтетические тесты. Никаких пользовательских профилей, secret keys, signing secrets и доступа к VPS. Branch build не публикует GitHub Release и не меняет main/production manifest. Действия загрузки исходников/SDK/пакетов являются явными build-only соединениями, не runtime клиента.

`packaging/package-clients.py` поддерживает NSIS, GNU MinGW или LLVM MinGW, проверенный Type 2 runtime AppImage + SquashFS. `packaging/verify_client_release.py` проверяет PE, размеры иконок, CRC и каждый файл ZIP, каждый извлечённый файл AppImage, Java 21, одинаковые application JARs и pinned Ed25519 key. Это структурная проверка, не нативная приёмка.

Результаты: Windows Setup EXE, portable ZIP, CachyOS AppImage, source ZIP и staging Relay 0.3 ZIP. Выпуск и production подпись выполняются только после обязательных native gates и отдельного разрешения владельца.
