# АЕГИС 1.5.0 — Windows 11 x64

Это кандидат для проверки владельцем, не опубликованный Stable. Windows Server CI не заменяет Windows11 acceptance.

1. Скачайте полный AEGIS-1.5.0-Windows-x64.zip и SHA256SUMS из предоставленного кандидата. Проверка PowerShell: `Get-FileHash .\AEGIS-1.5.0-Windows-x64.zip -Algorithm SHA256`; сравните с SHA256SUMS, полученным по доверенному каналу.
2. Распакуйте всё в личный каталог. Запустите AEGIS.exe. Нельзя переносить один EXE без runtime/tor/app/native/resources.
3. Или запустите AEGIS-Setup-1.5.0-x64.exe: установка в %LOCALAPPDATA%\Programs\AEGIS без Administrator, ярлыки через штатный launcher.
4. Tor запускается автоматически. Введите адрес v3 .onion, затем войдите/зарегистрируйтесь. Профиль хранится в %LOCALAPPDATA%\AEGIS; системный Tor/Tor Browser и глобальная Java не нужны.
5. Откройте «Архив» и задайте независимый пароль; recovery key необязателен. Для переноса используйте зашифрованную копию.

SOCKS19050/19052 и Control19051 слушают только127.0.0.1. Не открывайте их в Firewall, не отключайте Defender. Неподписанный Authenticode EXE может вызвать SmartScreen; Ed25519 update signing защищает пакет updater, это другой механизм и не коммерческая подпись EXE.

Перед переходом с1.2 закрывайте старый АЕГИС, следуйте MIGRATION-1.2.0-TO-1.5.0.md. Native kit запускается отдельно на тестовом профиле; проверьте DPI100/125/150/200%, reboot, archive ACL, копию/восстановление и подписанный updater/rollback. OWNER-OFFLINE-SIGNING-1.5.0.md объясняет процесс публикации после приёмки.
