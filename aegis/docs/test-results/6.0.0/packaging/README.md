# Инструменты упаковки и жизненный цикл 6.0.0

Инструменты NSIS, MinGW и squashfs восстановлены только из официального снимка Ubuntu, через проверку подписанного InRelease, SHA-256 Packages.xz и точных размеров/хешей 14 пакетов. Пакеты только распакованы; package scripts не выполнялись. Полное дерево проверяется по `packaging/native-kit/packaging-toolchain600.json`. Хостовый Linux C compiler записывается отдельно: полная герметичность сборки не заявляется.

Фактически скомпилированы x64 Windows launcher/maintenance, x86 NSIS guard DLL и Linux launcher. Проверены PE-импорты, NX/ASLR и NSIS-синтаксис. `NSIS-COMPILER-FIXTURE.exe` — только компиляторный fixture, не готовый установщик АЕГИС. В Linux проверена настоящая совместимость kernel fcntl native launcher с Java FileLock: shared/exclusive, блокировка до запуска JVM, отказ при ссылке. RuntimeLease JUnit использует настоящие отдельные JVM и межпроцессные kernel locks.

Нативный launcher сохраняет shared lock до завершения своей JVM. Обновление/NSIS получает exclusive lock на тот же пустой файл вне пользовательского профиля. Независимые Взор и личный Obsidian не убиваются; если они читают общие JAR, замена блокируется. Native helper не перебирает процессы по имени и не сигналит PID, взятые из файлов. Java updater получает дополнительную старую profile-lock и выполняет backup/replace/rollback с отдельной проверкой ACK.

Проверены опубликованные исходные payload5 Windows/Linux и точный runtime-классpath32 JAR из lock/verification metadata. Packager повторно извлекает Windows payload из фиксированного по SHA-256 архива в собственный временный каталог: сторонний файл, обнаруженный в старом mutable-кэше, не принят и не копируется. Ни status, ни нативная приёмка версии5 не наследуются.

`package-clients600.py` требует чистый зафиксированный исходный commit и неизменившийся успешный полный build receipt с тем же commit. Development-результат с dirty source не проходит этот входной gate. Реальных финальных Setup/Portable/AppImage6 этим отчётом ещё не заявлено. Windows11 запуск/установка/UAC/rollback, CachyOS AppImage/Wayland/X11 и нативная работа независимых приложений **NOT_RUN**; `productionReady=false`.
