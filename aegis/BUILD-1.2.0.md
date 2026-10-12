# Сборка АЕГИС 1.2.0

Java21; обычная сборка ./gradlew build. Пакеты повторно используют exact SHA-pinned Java21 runtime/Tor/libsodium из опубликованных 1.1.5 сборок, а все application JAR компилируются из текущих исходников.

python3 tools/build-stability.py --jdk /path/to/jdk21 --work /path/to/inputs --out /path/to/candidates

Скрипт выполняет явные build-time скачивания официальных релизных входов АЕГИС, Maven тестовых зависимостей и пяти лицензированных шрифтов из официальных репозиториев. Шрифты проверяются Git blob/SHA, исходные TTF не изменяются; лицензии включаются. Никакие пользовательские данные этим источникам не передаются. Клиент не скачивает шрифты и не создаёт дополнительные сетевые соединения.

CI runs только development/aegis-1.2.0, contents:read; upload-artifact, без Release/feed/VPS/signing. Production private key не требуется.
