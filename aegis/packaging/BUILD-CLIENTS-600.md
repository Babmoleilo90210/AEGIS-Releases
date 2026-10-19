# Сборка клиентского комплекта АЕГИС 6.0.0

`package-clients600.py` создаёт настоящие Windows Setup, Windows Portable ZIP и CachyOS AppImage из одного чистого зафиксированного commit. Скрипт не подписывает и не публикует релиз. Нативная приёмка остаётся отдельным обязательным этапом.

Перед упаковкой нужны успешный полный clean/nonincremental Gradle-прогон и неизменность исходников, зафиксированная в `GRADLE-VERIFICATION.json`: `gradleExitCode=0`, `sourceUnchanged=true`, `sourceDirtyAtStart=false`, тот же `sourceCommit`. Сборка с текущими незакоммиченными изменениями не подходит для релизной упаковки. Project JAR сверяются с доказательством сборки; все остальные JAR — с SHA-256 из `gradle/verification-metadata.xml`. Серверные JAR запрещены в клиентском classpath. Windows и Linux stageApp должны быть подготовлены из того же commit с JavaFX соответствующей платформы.

Нативная основа — точные опубликованные файлы владельца 5.0.0. Опубликованные BUILD/SOURCE-PROVENANCE указывают source commit `37779c113553bf5e1a42642e7ca7a010db9bdd4e`; локальный импорт того же проверенного дерева для разработки 6.0.0 — `38a3e6469a40e6edcb1b0448f906a488c73feb5d`. Эти идентификаторы записываются отдельно:

- Windows ZIP: `17b2ffa567ffe4fd9aef149ccaf39a3dc56ad0312db931dda3ae727cf7a31523`.
- Linux AppImage: `d27209621b936ff9445d5263c9c3bbf9366b00f9fc200704d00d9682d5bbc270`.

Windows ZIP заново безопасно извлекается в свежий каталог и проверяется целиком в том же процессе упаковки. Кэш извлечённых файлов Windows не используется. Linux payload проверяется сравнением всех файлов с извлечением точного AppImage. Обе JVM Temurin 21.0.12.1 проверяются по полному ранее утверждённому vendor registry; Opus/Speex — по существующим нативным пинам. Лицензии сохраняются. Tor наследуется только из точной проверенной основы, без подмены браузерной проверки OpenPGP. Результаты приёмки 5.0.0 в комплект 6.0.0 не переносятся.

`packaging/native-kit/packaging-toolchain600.json` закрепляет полный digest payload официальных Ubuntu-пакетов NSIS, MinGW x64/x86 и squashfs-tools. Цепочка проверки: доверенный системный Ubuntu archive keyring → проверенный gpgv InRelease → SHA-256 Packages.xz → SHA-256/размер `.deb` → только извлечение data payload. Maintainer scripts не выполняются, системная установка не нужна. Компилятор Linux и его версия/хеш записываются отдельно: сборка не заявляется герметичной.

Пример команды после фиксации исходников и успешных проверок (пути задаёт владелец сборочного окружения):

```sh
python packaging/package-clients600.py \
  --expected-commit FULL_COMMIT \
  --build-proof /verified/GRADLE-VERIFICATION.json \
  --windows-base-zip /verified/AEGIS-5.0.0-Windows-x64.zip \
  --linux-base-image /verified/AEGIS-5.0.0-CachyOS-x86_64.AppImage \
  --linux-base /verified/linux500/squashfs-root \
  --windows-app /verified/stage/win \
  --linux-app /verified/stage/linux \
  --native-tools /verified/ubuntu-toolchain/root \
  --linux-cc /usr/bin/cc \
  --out /new/empty-output
```

## Жизненный цикл и обновление

`RuntimeLease600` использует отдельный пустой файл `installation.lock`, не содержащий account ID, токенов или ключей. Путь общий для всех установок текущего пользователя и находится вне каталога приватного профиля: `LOCALAPPDATA/AEGIS-Runtime600-Guard` на Windows, `XDG_DATA_HOME/aegis-runtime600-guard` (либо `~/.local/share/...`) на Linux. Все компоненты удерживают shared byte-range lease до полного завершения использования runtime. Installer/updater требуют exclusive lease. Ошибка или неизвестное состояние блокируют замену файлов; чужие процессы не завершаются.

Windows launcher получает shared LockFileEx до запуска JVM и ждёт только собственный process HANDLE. Linux wrapper получает совместимый с Java `fcntl(F_RDLCK)`, создаёт дочернюю JVM, удерживает lease в родительском процессе и дожидается именно этого child. `flock` не применяется. В Windows launcher нет общего kill-on-job-close: независимые Взор и личная библиотека сохраняются после выхода Core. Пока они открыты, обновление сообщает причину блокировки.

NSIS x86 Unicode использует отдельно собранный x86 guard DLL, даже при x64 полезной нагрузке. DLL загружается из временного каталога; explicit LoadLibrary удерживает её и exclusive handle на всём участке резервного копирования/замены. После установки lease освобождается перед запуском нового Core. При аварии Windows освобождает kernel handles. Удаление также требует exclusive guard. Пользовательские данные не удаляются.

`MaintenanceMain600 backup` не ищет процессы по именам и не отправляет сигналы. Он дополнительно проверяет прежний `aegis.lock` и `core600/core.lock`, создаёт существующий защищённый snapshot и проверяет его inventory. Additive snapshot6 mapping сохраняет зашифрованный Core device vault и выбранные настройки; transient IPC/cache и lock-файлы не считаются переносимыми данными.

`entrypoints600.json` перечисляет настоящие Java entrypoints и их условия авторизации. Только Core получает desktop shortcut. Mail/Glas запускаются брокером через аутентифицированный anonymous pipe; Взор использует отдельный одноразовый nonce без account capability. `components600.json` закрепляет JVM и каждый JAR установленного комплекта. Сам по себе локальный JSON не заменяет подпись владельца над релизным пакетом.

## Границы подтверждения

В текущем Linux-контейнере фактически выполнены отдельные JVM-тесты shared/exclusive lease, Linux native/Java interop, отказ запуска при exclusive lock и symlink rejection. Выполнена кросс-компиляция Windows launcher/DLL и компиляция NSIS с отдельным явно обозначенным compiler fixture. Это не доказывает нативную установку, LockFileEx/Java interop или rollback на Windows 11. Для них, а также CachyOS KDE Wayland/X11, сохраняется NOT_RUN до реального прогона на соответствующей платформе.

Основные API проверены по первичным документам: [Microsoft LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex), [NSIS System plug-in](https://nsis.sourceforge.io/Docs/System/System.html), [Linux/POSIX fcntl](https://man7.org/linux/man-pages/man3/fcntl.3p.html). Ограничение POSIX о сбросе process record locks при закрытии любого descriptor того же файла учитывается единым refcount/channel внутри JVM; повторные локальные проверки не открывают второй descriptor.
