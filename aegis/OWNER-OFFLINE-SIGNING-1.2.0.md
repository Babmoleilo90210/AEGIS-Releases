# АЕГИС 1.2.0 — приёмка, офлайн-подпись и публикация владельцем

`productionReady=false`: это release candidate для нативной приёмки, не завершённый Stable. Client-only Friends, signed receipts и device-bound disappearing реализованы; production Relay менять не требуется. Обязательны Windows 11/CachyOS и owner-signed updater/restart/rollback. Учтите conservative expiry after OS reboot (LIFECYCLE-1.2.0.md). Private key остаётся у владельца, не передаётся в Work/CI/GitHub/VPS. Подпись не создана, production feed не менялся. Не переносите прежнюю подпись на новый manifest.

## Порядок

1. Распакуйте комплект; проверьте `SHA256SUMS`, отдельно `SIGNING-INPUT-SHA256`. Сверьте хеши бинарников с отчётом.
2. На копиях тестовых профилей проведите Windows 11, CachyOS KDE Wayland и X11 приёмку. Native kit и CSV находятся в комплекте. Проверьте миграцию, mail/file/offline/TTL, все UI/SYS сценарии, restart и rollback. Протокол/production Relay/onion не изменяются.
3. Закройте ограничение постоянных encrypted drafts либо отдельно согласуйте его; незавершённый черновик пока блокирует установку. Сборка не закрывает этот gate.
4. Для полного updater испытания предыдущего опубликованного клиента потребуется отдельно разрешённый подписанный Beta feed того же репозитория и доступные по HTTPS assets. Не заменяйте Stable для испытаний. Уже опубликованный 1.1.5 не принимает произвольный локальный test URL. Fixture-тесты этого ограничения не снимают.
5. Подписывайте конкретные неизменённые байты manifest офлайн. После изменения бинарника, source ZIP или SHA256SUMS нужен пересозданный manifest и новая подпись.
6. Проверьте подпись public key перед передачей только публичных release-файлов на онлайн-машину. Private key остаётся офлайн.
7. Публикуйте Stable только после всех mandatory gates. Actions candidate artifact/development branch не являются GitHub Release.

## Точная команда на CachyOS

Перейдите в каталог содержимого распакованного комплекта (в нём лежат SHA256SUMS и updates). Замените только путь к своему уже существующему PEM Ed25519 private key:

```bash
sha256sum -c SHA256SUMS
sha256sum -c SIGNING-INPUT-SHA256
openssl pkeyutl -sign -rawin -inkey /media/offline/aegis-ed25519-private.pem -in updates/stable.json -out updates/stable.json.sig
openssl pkeyutl -verify -pubin -rawin -inkey updates/release-public.pem -in updates/stable.json -sigfile updates/stable.json.sig
```

OpenSSL должен вывести `Signature Verified Successfully`. Detached Ed25519 signature — 64 байта. Не генерируйте новый ключ: используйте ключ, соответствующий pinned public key приложения. Не редактируйте stable.json после подписи и не меняйте его переводы строк. Эти команды **ничего не публикуют** и не подключаются к GitHub.

Для первого теста предыдущего бинарника нужен отдельно разрешённый Beta feed с точной owner-signed подписью и публично доступными assets. Произвольного endpoint override в опубликованном клиенте нет. Beta manifest должен быть отдельно сформирован из exact final assets с channel=beta и отдельно подписан; этот комплект не утверждает готовность такого теста. Не копируйте Stable подпись на Beta.

## Публикация после приёмки

В Babmoleilo90210/AEGIS-Releases создаётся Release с tag v1.2.0 и описанием из CHANGELOG-1.2.0.md. Загрузите все файлы, перечисленные в manifest: Setup EXE, Windows ZIP, CachyOS AppImage, client-source ZIP, SHA256SUMS и CHANGELOG. Полный source ZIP, отчёт, native kit и документы можно приложить дополнительно. Затем только по вашему разрешению обновляются main/updates/stable.json и stable.json.sig exact signed bytes. Не загружайте private key, Tor secret keys или пользовательский профиль.

Будущие ссылки после публикации (сейчас они могут возвращать 404):

- Windows Setup: https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-Setup-1.2.0-x64.exe
- Windows portable: https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-1.2.0-Windows-x64.zip
- CachyOS: https://github.com/Babmoleilo90210/AEGIS-Releases/releases/download/v1.2.0/AEGIS-1.2.0-CachyOS-x86_64.AppImage

Windows: открыть Setup под обычной учётной записью либо распаковать весь ZIP и открыть AEGIS.exe. Не извлекать один EXE из пакета — нужны runtime/tor/app. Java и Tor Browser отдельно не нужны. Данные сохраняются в LocalAppData.

CachyOS: скачать AppImage, `chmod +x AEGIS-1.2.0-CachyOS-x86_64.AppImage`, открыть его. Runtime и Tor внутри. Используйте README-CACHYOS.md для ограничений FUSE/Wayland. Не открывайте входящие порты и не запускайте клиент root.
