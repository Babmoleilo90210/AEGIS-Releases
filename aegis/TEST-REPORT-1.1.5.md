# Тестирование кандидата АЕГИС 1.1.5

`productionReady=false`. Это рабочий release candidate для приёмки, а не опубликованный Stable. Конкретные результаты JUnit/UI/packaged checks находятся в evidence; не переносите результаты 1.1.1 на новые бинарники.

Доступные проверки: реальный javac 21; JUnit прежних модулей плюс тесты bounded appearance, миграции, изображений, импорта, контраста и trusted update events; JavaFX Monocle с настоящими Scene, CSS, формами, редактором и снимками; структурный контроль EXE, иконок, JAR, runtime, Tor и AppImage; неизменность защищённых компонентов по SHA исходников.

Headless проверки не подтверждают физический DPI, KDE Wayland/X11, интеграцию окна с ОС и удобство на реальном экране. Windows Server 2025 в CI не равен Windows 11. Ubuntu Tor test не равен CachyOS.

В native acceptance kit перечислены UI-01…UI-30, SYS-01…SYS-10, регрессия почты и полный updater E2E. Эти native gates — NOT_RUN до фактических испытаний владельцем. Manifest verification, download/resume, fixture helper и пакетные проверки отдельно помечаются: это разные уровни доказательств, не полный переход пользователя.

Открытые ограничения: memory-only черновик исходной 1.1.1 при остановке процесса; нет production-подписи 1.1.5; не выполнены обязательные испытания Windows 11, CachyOS Wayland/X11 и подписанный full updater/rollback. Нельзя выставлять productionReady=true до их закрытия.

Измерение переключения оформления в одинаковой headless среде фиксируется в Appearance115Smoke.log. Снимки — реально отрисованный JavaFX интерфейс, не генерация дизайна. Потребление памяти и отзывчивость предыдущей версии должны сравниваться отдельно; отсутствующее измерение нельзя считать PASS.
