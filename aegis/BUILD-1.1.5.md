# Сборка кандидата 1.1.5

Основа — полный опубликованный client source ZIP 1.1.1, SHA-256 `c6148e46d30cfa277483810fbfe64ac7f7ddcec06b13c544f4c921716c7a8a6a`. Development overlay не является заменой полного ZIP. Исходники Relay и common-protocol в нём сохраняются.

Java 21, Gradle для обычной разработки: `./gradlew build`. Для уже проверенного набора зависимостей поддерживается `tools/build-local.py --jdk <JDK21> --deps <JAR-directory> --native-root <native-bundle>`.

На отдельном Linux build host установите gcc-mingw-w64-x86-64, NSIS и squashfs-tools. Это инструменты разработки, не зависимости пользователя. Затем:

```bash
python3 tools/build-visual.py --jdk "$JAVA_HOME" --work /tmp/aegis115-inputs --out /tmp/aegis115-candidate
```

Скрипт явно скачивает SHA-pinned ранее выпущенные native inputs и тестовые зависимости, компилирует новые JAR, выполняет JUnit, UI/compatibility/security проверки, пересобирает нативные launchers/installer и AppImage, проверяет их структуру и вычисляет SHA-256. Java 21 jlink runtime, официальный Tor, pluggable transport, libsodium и иконка из прежней поставки остаются внутри пакета. Пакет не использует системную Java или пользовательский Tor.

CI workflow `aegis115-visual.yml` запускается только на `development/aegis-1.1.5`, загружает candidates как Actions artifacts и никогда не создаёт GitHub Release. Отдельные Windows Server 2025 и Ubuntu проверки проверяют реальные EXE/Tor/TLS; они не заменяют Windows 11 и CachyOS.

`tools/visual-release.py` создаёт unsigned `updates/stable.json` **в каталоге кандидата**, не в production main. В нём остаётся schema 1 и pinned release public key. Подпись выполняет только владелец после окончательных приёмочных результатов. После любого изменения бинарника вычислите новые хеши и создайте новый manifest; старая подпись неприменима.
