# Сборка с нуля

Для разработки: Java 21 JDK, Python 3.12+, make и C compiler на Linux; Pillow для технического преобразования иконок. На Windows команда клиента — `gradlew.bat :client-core:test :client-ui:build -PtargetPlatform=win`; нужны Java 21 и Python, native libsodium берётся из закреплённого официального Windows-архива. Полная серверная проверка включает Linux-права и выполняется на Linux. Это зависимости **разработчика**, не пользователя готовых пакетов.

```sh
./gradlew build
./gradlew :client-ui:build
./gradlew :relay-server:build
```

Первый тестовый запуск вызывает прозрачный `packaging/prepare-native.py`: загружает только закреплённую libsodium, проверяет SHA-256 и готовит native-библиотеку для тестов. Java-зависимости закреплены gradle.lockfile и verification-metadata.xml. Изменение upstream-файла с тем же URL вызывает ошибку проверки, а не молчаливое принятие нового файла.

Полная сборка трёх релизов выполняется на Linux x86_64:

```sh
python3 -m pip install Pillow
./packaging/build-release.sh
```

Результат — `dist/`. Можно задать `AEGIS_BUILD_INPUTS` и `AEGIS_OUTPUT` абсолютными путями. Скрипт загружает Zulu OpenJDK 21.0.12.1 для обеих ОС, официальный Tor Expert Bundle 15.0.24, libsodium 1.0.22 stable, LLVM-MinGW 20260922, AppImage tooling/runtime. Все SHA-256 закреплены в скрипте; адреса и назначения открыты. Tor берётся с официально перечисленного зеркала Umeå. Никакие пользовательские данные при сборке не используются.

AppImage upstream использует перезаписываемые continuous assets. Если его URL позднее начнёт отдавать другой хеш, сборка остановится. Обновление закреплённых входных файлов выполняется разработчиком после проверки; автоматического доверия новой версии нет.

Windows EXE компилируется LLVM-MinGW из `packaging/windows/launcher.c`, resource script и manifest. Его иконка — предоставленный PNG, преобразованный без перерисовки. Launcher запускает встроенный javaw, применяет Job Object и не требует Administrator. jlink использует Windows JMODS для Windows runtime, Linux JMODS — для AppImage/relay. Setup EXE не входит в сборку.

В AppImage включаются только runtime, клиентские JAR, native crypto, Tor/PT/GeoIP, документация и иконка. В серверном ZIP нет client-core, UI или libsodium. Relay runtime включает Java SQL/crypto и не содержит JavaFX.

`packaging/package.py` можно запускать отдельно после Gradle staging. Он использует закреплённый AppImage runtime через `--runtime-file`; packaging не обращается за новым runtime автоматически.

GUI smoke: `./gradlew :client-ui:messengerSmoke -PtargetPlatform=linux`. Это реальные JavaFX controls с тестовым local vault в Monocle, не подтверждение native Windows shell/GTK/KDE.

Полная проверка настоящей цепочки Windows → Tor → Debian → Tor → CachyOS требует этих ОС и доступного relay. Инструкция приёмки и выполненные тесты — TEST-REPORT.md.
