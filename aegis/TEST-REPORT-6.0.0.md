# Испытания АЕГИС6.0.0

Компонентные проверки и общий выпуск разделены. Результаты старого checkpoint не переносятся автоматически на новые исходники. Итоговый полный прогон, commit/tree, XML и хеши бинарников фиксируются в FINAL-VERIFICATION/BUILD-PROVENANCE рядом с готовым комплектом. Этот исходный документ не содержит хеш собственного будущего commit.

## Текущие воспроизводимые результаты восстановления19.10

- Identity и клиентские административные потоки:87/87PASS,sourceStable=true. Реальные Ed25519/HTTP/SQLite/CLI, восстановление, replay/expiry, отзыв и независимые подтверждения. JavaFX smoke реально изменяет серверное состояние после двух подтверждений и не создаёт запрос после закрытия панели. Два настоящих PNG.
- News Worker:33/33PASS,sourceStable=true, включая9 реальных service CLI/HTTP/SQL проверок. Namespace service/user разделён даже при одинаковом public key, replay сохраняется после restart, allowlist/role/revoke/rate проверяются на сервере.
- Debian tooling:26 тестов,22PASS/4NOT_RUN. Нативные systemd/AppArmor/chroot/setuid проверки не выдуманы; текущая Ubuntu с PID1supervisord не принимается как Debian13.
- Build-focused:75 JUnit,74PASS/1AF_UNIXSKIP/0FAIL. Взор и канонические пути, runtime lease, OS-lock parsers/adapters, уведомления, Windows rollback filesystem/helper contracts и фактическая совместимость снимка с точным опубликованным5 JAR. Это не реальная установка Windows.
- Core GUI:117 настоящих PNG,800×600/1024×768/1920×1080,четыре масштаба,light/dark. Настоящий отдельный consent child по MAC/pipe закрывается при lock; пароль очищается; запоздалый signed response не возвращает экран. HTTP/SOCKS/OS fixture и Monocle не являются нативной приёмкой.
- Android:200 host checks,7 Mail и12 Glas actual local integration,101 upstream sodium и16 Opus upstream tests,четыре unsigned+четыре TEST APK. Проверены SDK/apksig и отказ реального изменённого APK. Реальные нативные библиотеки собраны ARM64 с16КиБ alignment, но Android ART/Binder/устройство/Doze/физический звук не выполнены. Окончательные APK должны быть повторно собраны на общем exact commit.
- Gate validator:20 тестов. Это тесты самого валидатора, не приложение и не нативная приёмка. Ручная подмена true, пропуск обязательного gate, старые source/artifact hashes, altered receipt, headless-as-native и один компьютер вместо двух физических отклоняются.

Промежуточный общий compileTestJava/compileSmokeJava прошёл, но выполнялся при dirty/changed источнике и обновлении locks. Его receipt намеренно не является clean frozen release proof. Ранние FAIL старого clock fixture и неверного test root архива сохранены; исправление fixture не ослабляет production-проверку.

## Исторические значимые интеграционные проверки

Сохранённые XML/журналы включают реальный потоковый HTTP/Identity/SQLite/Tink/libsodium цикл вложения500МиБ под heap96МиБ с resume/restart/decrypt/SHA и protectedFF1, сохранение старого профиля, LibraryACL и очистку projection при зависшем authorize RPC. Они остаются компонентными доказательствами своего source snapshot; финальный общий test повторяет актуальный набор.

Настоящие Tor/Lyrebird lifecycle ранее прошли; публичный bootstrap среды18Oct былBLOCKED(Direct0%,Snowflake10%). HTTPS/onion/голос/updater через публичный Tor этим не засчитаны. Публичная RSS-попытка былаBLOCKEDDNS; полноценная автономная публикация с реальной разрешённой моделью не принята.

## Обязательная дальнейшая приёмка

Windows11x64, CachyOSKDEWayland иX11, Debian13/systemd/AppArmor, физическийAndroid13+ARM64, два физических устройства и независимые сети. Нужны realTor/HTTPS/onion/DNS/WebRTC/VPN leaks,60мин голоса, устройства ввода/вывода, Android background/Doze/permissions/FLAG_SECURE, полный updater download/install/restart/rollback, аварийное восстановление VPS и финальная приёмка владельца.

Неустранённые Android feature blockers перечислены в android/docs/RELEASE-GATES-ANDROID-6.0.0.json; целевые тесты — NATIVE-ACCEPTANCE-6.0.0.md. Готовность вычисляется tools/evaluate-release-gates600.py из обязательных результатов, exact source и artifact receipts. Недоступность проверки не превращается вPASS по прошедшему времени.
