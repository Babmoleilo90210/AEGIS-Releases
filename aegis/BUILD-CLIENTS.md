# Сборка клиентов 1.0.0 с нуля

Поддержанный сборочный host: Linux x86_64 с bash, Python >= 3.12, gcc/make/autoconf build tools, unzip, dpkg-deb и сетевым доступом к URL из packaging scripts. Gradle wrapper закреплён SHA-256. Для разработки Java 21; готовым пользователям Java не нужна.

```sh
./gradlew :client-core:test :integration-tests:test :client-ui:stageApp -PtargetPlatform=linux
./gradlew :client-ui:stageApp -PtargetPlatform=win
```

Все три клиентских артефакта, source и SHA256SUMS:

```sh
./packaging/build-clients.sh
```

Скрипт явно скачивает закреплённые JDK Linux/Windows, Tor Expert Bundle 15.0.24, libsodium 1.0.22, LLVM MinGW, AppImage tools и NSIS. Все SHA-256 проверяются до использования. NSIS .deb только распаковываются в приватный build каталог, не устанавливаются в ОС. При изменении continuous AppImage assets сборка закрывается с checksum mismatch; обновлять закреплённый digest нужно после проверки официального release, не отключать проверку.

packaging/prepare-inputs.py собирает и тестирует libsodium. package-clients.py использует Linux jlink и Windows/Linux jmods Java 21, создаёт минимальные runtime, компилирует native Windows launcher и NSIS Setup, создаёт AppImage с явно указанным runtime. Сервер не упаковывается, системные службы не устанавливаются. Relay sources присутствуют только как замороженная основа тестов.

Выпущенная сборка использует идентичные проверенные runtime/Tor/libsodium файлы релиза 0.2.0; исходники и Java JAR клиентов собраны заново. package-clients.py также поддерживает --linux-base/--windows-base для такого обслуживания. Иконка исходного релиза сохранена без перерисовки: resources/icon.ico с 16,24,32,48,64,128,256 и Linux PNG.

Отдельные smoke проверки:

```sh
./gradlew :client-ui:messengerSmoke :client-ui:pickerSmoke -PtargetPlatform=linux
./gradlew :client-core:torProcessSmoke -PtorBundle=/absolute/client/appdir
./gradlew :integration-tests:client10Relay02Smoke -PrelayJava=/absolute/relay/runtime/bin/java -PrelayLib=/absolute/relay/lib
```

Последняя команда запускает **неизменённый упакованный relay 0.2.0** в временном профиле. Используется loopback SOCKS harness, не сеть Tor. TorProcessSmoke проверяет настоящие Linux Tor/PT процессы с коротким таймаутом, а не гарантирует подключение внешней сети. Для чистых Windows/CachyOS и настоящего VPS нужна native acceptance из отчёта.

Архив содержит все локальные исходники и scripts; сторонние библиотеки при сборке загружаются явно через закреплённые dependencies/verification metadata. Они находятся в app/ готового клиента. Автоматической загрузки компонентов при запуске клиента нет.

Миграция настоящего 0.3.0 профиля:

```sh
./gradlew :integration-tests:migration03Smoke -PrelayJava=/absolute/relay/runtime/bin/java -PrelayLib=/absolute/relay/lib -PlegacyClient=/absolute/released-0.3.AppDir
```

Fixture выполняется с released 0.3 JAR первым в classpath и регистрируется на старом packaged relay. Test class files не входят в пользовательский пакет. Zip4j 2.11.6 закреплён в dependencies, lock files и verification metadata. Setup также компилирует AEGIS-Maintenance.exe для локального graceful close/rollback.

Системные Linux требования для graphical run: GTK3/fontconfig и X11/XWayland (JavaFX21). Для update process pinning: libc2.36+, kernel5.3+. Это вызовы ОС через уже используемую JNA; новый сетевой компонент не добавляется.

## Полный регрессионный прогон и новый updater

```sh
./gradlew test :client-ui:pickerSmoke :client-ui:messengerSmoke :client-ui:clientUiRegressionSmoke -PtargetPlatform=linux
python3 -m unittest discover -s tools -p test_release_manifest.py -v
```

На Windows Gradle запускается через gradlew.bat; nativeDpapiCurrentUserRoundTrip автоматически выполняется только на Windows. На Linux его SKIP нельзя считать успехом Windows теста. UI smoke использует Monocle как test-only dependency, в client package не входит. sourceSets.smoke классы тоже не входят в JAR клиента.

package-clients.py дополнительно компилирует packaging/windows/updater.c в AEGIS-Updater.exe с исходной иконкой и asInvoker. Минимальный runtime включает java.desktop для bounded ImageIO. JNA Platform/Gson/TwelveMonkeys и их transitive JAR входят в обе platform stages; platform-specific JavaFX jars отличаются, common/core совпадают. Production signing private key для сборки не нужен.

packaging/archive-clients.py не включает stable/beta JSON/signature в source ZIP: final manifest содержит SHA самого ZIP и поэтому находится отдельно в release bundle. tools/prepare-release формирует final unsigned JSON после окончательной упаковки. Секретный owner key остаётся только у владельца.
