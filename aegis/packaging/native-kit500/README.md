# Комплект приёмки АЕГИС 5.0.0

Это отдельный набор проверок владельца, а не установленное приложение и не свидетельство пройденной приёмки. При упаковке все строки `OWNER-RESULTS-5.0.0.json` имеют NOT_RUN. Успех JUnit или UI smoke не переносится автоматически в нативные gates, а `productionReady` остаётся false.

## Целевые среды

Нужны Windows 11 x64, CachyOS KDE Wayland и CachyOS KDE X11 с отдельными результатами и два физических устройства в независимых сетях. Windows Server, Ubuntu headless, Monocle и два процесса одного компьютера не заменяют эти среды. Укажите редакцию/сборку ОС, desktop/session, физические устройства обезличенными метками, SHA-256 точных приложений.

Проверяйте SHA256SUMS release и kit перед запуском. TESTED-ARTIFACTS.json связывает текущий frozen source commit/tree, исходный ZIP, Windows ZIP и общие client/common JAR. В app/ приложения не копируются JUnit, сервер, worker или test JAR. Kit не загружает зависимости, не меняет Relay/feed и не запрашивает приватный ключ выпуска.

## Команды

Для локальной криптографии/хранилища/JavaFX и текущего интерфейса достаточно встроенной Java приложения:

```bat
Run-Windows.cmd C:\AEGIS-Test\AEGIS
Run-Appearance-Windows.cmd C:\AEGIS-Test\AEGIS
Run-Voice-Windows.cmd C:\AEGIS-Test\AEGIS
```

```sh
bash Run-CachyOS.sh /путь/к/AEGIS-5.0.0-CachyOS-x86_64.AppImage
bash Run-Appearance-CachyOS.sh /путь/к/AppDir
bash Run-Voice-CachyOS.sh /путь/к/AppDir
```

Команды на CachyOS принимают готовый AppDir или извлекают проверенный AppImage во временный каталог. Рабочий профиль владельца не открывается. UI-набор запускает Interface500Smoke (11 разделов, три блока, шесть категорий), ArchiveMenu500Smoke и актуальный VzorGlas250Smoke. Историческое имя последнего сохраняет совместимость, но не является выполнением приёмки 2.5. Наборы Interface200Smoke, SettingsResponsive200Smoke и Interface250RefinementSmoke со старыми категориями в kit не входят.

Встроенный NativeAcceptanceMain также запускает сохранённые компонентные проверки файлового выбора, писем, тем и единственного окна. Имена старых компонентных smoke отражают их происхождение. Эти операции используют синтетические данные, не production аккаунт.

`Run-Voice` по умолчанию только перечисляет устройства и проверяет проверенные Opus/Speex на синтетическом аудио. Микрофон и воспроизведение не включаются. Для явно разрешённого измерения уровня микрофона до 15 секунд добавьте второй аргумент `--test-microphone`. Звук не записывается, не воспроизводится и не передаётся. Для настоящего Гласа нужны отдельно принятый и аутентифицированный звонок двух физических устройств.

Серверные/worker/cross-module JUnit и реальная UI→service→SQLite проверка требуют отдельного полного **JDK 21**: клиентский Linux JRE может не содержать jdk.httpserver. Передайте проверенный JDK явно:

```bat
Run-Community-Windows.cmd C:\AEGIS-Test\AEGIS C:\Java\jdk-21
Run-Community-UI-Windows.cmd C:\AEGIS-Test\AEGIS C:\Java\jdk-21
```

```sh
bash Run-Community-CachyOS.sh /путь/к/AppDir /путь/к/jdk-21
bash Run-Community-UI-CachyOS.sh /путь/к/AppDir /путь/к/jdk-21
```

`staging/` содержит community-server, news-worker и проверенные test-зависимости, скомпилированные из того же frozen ZIP. JUnit проверяют настоящую SQLite/ACL, TOTP, два администратора, новостные/файловые ограничения, центральную проверку источников, HTTP подписи и взаимодействие клиента через явно обозначенный loopback SOCKS fixture. Этот fixture не является настоящим Tor. Community500FlowSmoke использует реальные UI и service objects, но передаёт RPC внутри процесса. Эти тесты не разворачивают production инфраструктуру.

## Результаты и конфиденциальность

Заполняйте OWNER-RESULTS-5.0.0.json по приложенной JSON Schema. Разрешены только PASS, FAIL, BLOCKED, NOT_RUN. Для PASS укажите время и относительный путь к реальному доказательству с SHA-256. Приложите скриншот, log или packet-capture summary только соответствующей операции. Не переносите PASS локального codec/parser теста в поля физического звонка, сетевой изоляции или signed updater E2E.

Отчёты могут содержать личные названия устройств, абсолютные пути, имена контактов и содержимое созданных тестовых документов. Используйте отдельные тестовые аккаунты и проверяйте/обезличивайте отчёты перед передачей. Не включайте рабочие vault, токены, TOTP seeds, личные ключи, полный crash dump, микрофонные записи или архив владельца. Скрипты ничего не отправляют автоматически.

Точные старые parser sources и provenance находятся в fixtures/manifest-compatibility. Тестовые подписи создаются временными test keys и не заменяют owner signature. Положительный updater E2E выполняется на отдельном подписанном владельцем тестовом manifest и предыдущем реальном клиенте; production Stable feed не меняется. Подробная матрица и порядок: NATIVE-ACCEPTANCE-5.0.0.md.
