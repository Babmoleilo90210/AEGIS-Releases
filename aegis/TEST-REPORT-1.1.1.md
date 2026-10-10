# План и границы приёмки 1.1.1 Demo

Этот файл включён в бинарные пакеты до выполнения CI и не объявляет будущие проверки пройденными. Фактические результаты и SHA конкретной сборки находятся в финальном AEGIS-1.1.1-DEMO-TEST-REPORT-RU.md и TEST-EVIDENCE.zip.

Проверяются JUnit всех модулей, 16 release/security tests, шесть тем при восьми масштабах, выбор новой темы через реальную Appearance page, сохранение в новом JVM, единое окно/черновик, структурные ZIP/EXE/AppImage checks, старый published 1.1.0 verifier/state machine и real Tor HTTPS/signature/download/resume.

Native Windows Server CI не считается Windows 11; Ubuntu/Monocle не считаются CachyOS KDE Wayland/X11. Без новой подписи владельца и опубликованного Beta-feed нативный signed install/restart/rollback 1.1.0 → 1.1.1 — NOT_RUN. productionReady=false.
