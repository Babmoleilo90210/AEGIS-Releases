# Восстановленная проверка сборочной области, 19 октября 2026

После потери временной среды восстановлены исходники из сохранённого снимка и отдельные поздние исправления. Это новый фактический прогон текущих файлов, а не перенос старых PASS.

- Официальные JDK 21.0.12.1+1 и Gradle 9.8.0 заново скачаны, sidecar SHA совпали с закреплёнными значениями и фактическими архивами. 52 Maven JAR сверены с официальными SHA из dependency verification metadata (отдельные JUnit/Monocle pins сохранены в receipt).
- Точный опубликованный Linux AppImage 5.0.0 проверен по SHA и извлечён встроенным runtime. Старый core JAR имеет SHA `6d263ef70f5b159aa4458125ffc75bf55c71346baf52b01db3b7db00e155ebe2`.
- Диагностический Gradle `compileTestJava` всех 11 модулей и `client-ui:compileSmokeJava`: BUILD SUCCESSFUL. Это dirty/source-changed диагностический запуск с генерацией locks, не release proof. Впоследствии все 11 `:module:dependencies --write-locks` разрешены отдельно, включая runtime/smoke.
- Fresh focused JUnit: 75 начато, 74 PASS, 1 ABORT/SKIP из-за недоступного AF_UNIX host fixture, 0 FAIL; `sourceUnchanged=true`. Состав: независимый Взор, пути приватных данных, RuntimeLease, OS-lock backend/parsers, arrival dedup/preferences, Core-only rollback600 preflight/hash/ancestry и точный опубликованный5 JAR для реальной миграции/отката.
- Core UI: 117 реальных PNG и `sourceUnchanged=true`, отдельные JVM для 800×600, 1024×768, 1920×1080, 100/125/150/200%, светлой/тёмной темы. Настоящий signed Identity/Community HTTP/SQL, recovery UI, реальный отдельный consent child с аутентифицированным IPC heartbeat/shutdown, Core lock до входа и после входа, освобождение kernel lock, очистка detached PasswordField и защита от позднего signed ответа. Tor readiness, OS observation и локальный SOCKS явно заменены только в smoke fixture.
- Пакетировщик: 8 Python security-contract tests PASS. Полный пакет не был собран этим прогоном.

`RESULT.json` и XML содержат воспроизводимые результаты JUnit; `CORE-UI-RESULT.json` — SHA входных исходников, фактических временных JAR, команды и результаты геометрии. Эти временные GUI JAR не являются релизными артефактами. Хеши исходников в receipt связывают проверки с файлами; итоговый чистый commit будет проверен отдельно полным `clean test assemble`.

Windows11/CachyOS KDE Wayland/X11, реальный Tor, Linux browser namespace, Windows UAC/Sandbox/install/rollback и физические аудиоустройства этими результатами не проверены. Native acceptance остаётся NOT_RUN; productionReady=false. Пользовательская прежняя приёмка предыдущих версий не переносится на новый исходный commit автоматически.
