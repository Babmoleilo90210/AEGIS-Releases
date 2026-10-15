# АЕГИС 2.0.0 — установка и проверка Windows 11 x64

Сборка для приёмки; `productionReady=false`. Native Windows11, официальный Tor Browser и полный подписанный updater E2E ещё NOT_RUN. Это не разрешение на Stable.

1. Сравните SHA-256 `AEGIS-Setup-2.0.0-x64.exe` или `AEGIS-2.0.0-Windows-x64.zip` с SHA256SUMS из доверенного канала (`Get-FileHash <файл> -Algorithm SHA256`).
2. Setup устанавливает в личный `%LOCALAPPDATA%\Programs\AEGIS`; portable ZIP распакуйте полностью и запустите AEGIS.exe. Не переносите один EXE без runtime/app/tor/native/resources. Java и почтовый Tor включены.
3. Для испытаний используйте отдельный профиль и синтетические аккаунты. Перед реальным переходом с 1.5.0 закройте прежнее приложение и сохраните резервную копию по MIGRATION-1.5.0-TO-2.0.0.md.
4. Safe Web требует официальный Tor Browser portable EXE и соответствующую .asc; выберите их в разделе Safe Web. Подпись проверяется до запуска установщика. Обычный Firefox не используется.
5. Изоляция Safe Web требует Windows11 **24H2+ Pro/Enterprise/Education**, установленный Windows Sandbox с официальным CLI и виртуализацию. Home/старый CLI не поддержаны этим backend. Компоненты ОС не включаются автоматически; менее защищённого fallback нет. Сам мессенджер остаётся отдельным приложением JavaFX.
6. Запустите native-acceptance по NATIVE-ACCEPTANCE-2.0.0.md. Нативный тестовый комплект не меняет production classpath. Успех headless/manifest-проверки не заменяет приёмку и установку/перезапуск/rollback.

Профиль: `%LOCALAPPDATA%\AEGIS`; Safe Web: отдельный `%LOCALAPPDATA%\AEGIS-SafeWeb`. Пароли и ключи архива браузеру не передаются. Не отключайте Defender/Firewall. Неподписанный Authenticode Setup может вызывать SmartScreen; Ed25519 подпись updater — отдельный механизм. Owner private release key нужен только владельцу офлайн и не передаётся приложению/CI.

Исторические инструкции базы 1.5.0 сохранены ниже; их результаты не являются результатами 2.0.0.

---

# АЕГИС 1.5.0 — Windows 11 x64

Это кандидат для проверки владельцем, не опубликованный Stable. Windows Server CI не заменяет Windows11 acceptance.

1. Скачайте полный AEGIS-1.5.0-Windows-x64.zip и SHA256SUMS из предоставленного кандидата. Проверка PowerShell: `Get-FileHash .\AEGIS-1.5.0-Windows-x64.zip -Algorithm SHA256`; сравните с SHA256SUMS, полученным по доверенному каналу.
2. Распакуйте всё в личный каталог. Запустите AEGIS.exe. Нельзя переносить один EXE без runtime/tor/app/native/resources.
3. Или запустите AEGIS-Setup-1.5.0-x64.exe: установка в %LOCALAPPDATA%\Programs\AEGIS без Administrator, ярлыки через штатный launcher.
4. Tor запускается автоматически. Введите адрес v3 .onion, затем войдите/зарегистрируйтесь. Профиль хранится в %LOCALAPPDATA%\AEGIS; системный Tor/Tor Browser и глобальная Java не нужны.
5. Откройте «Архив» и задайте независимый пароль; recovery key необязателен. Для переноса используйте зашифрованную копию.

SOCKS19050/19052 и Control19051 слушают только127.0.0.1. Не открывайте их в Firewall, не отключайте Defender. Неподписанный Authenticode EXE может вызвать SmartScreen; Ed25519 update signing защищает пакет updater, это другой механизм и не коммерческая подпись EXE.

Перед переходом с1.2 закрывайте старый АЕГИС, следуйте MIGRATION-1.2.0-TO-1.5.0.md. Native kit запускается отдельно на тестовом профиле; проверьте DPI100/125/150/200%, reboot, archive ACL, копию/восстановление и подписанный updater/rollback. OWNER-OFFLINE-SIGNING-1.5.0.md объясняет процесс публикации после приёмки.
