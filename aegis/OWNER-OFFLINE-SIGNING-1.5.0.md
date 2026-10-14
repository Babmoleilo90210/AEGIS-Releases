# Офлайн-подпись АЕГИС 1.5.0 владельцем

Private key остаётся на вашем офлайн устройстве. Его не нужно присылать, вставлять в чат/Work/GitHub/CI/VPS. Кандидат сейчас productionReady=false до обязательной нативной приёмки и updater E2E. Подпись сама по себе не делает непроверенную сборку готовой.

1. Проведите NATIVE-ACCEPTANCE-1.5.0.md на копиях профилей Windows11, KDE Wayland и X11. Зафиксируйте NOT_RUN/FAIL честно. Доступные CI доказательства лежат в evidence, они не заменяют native.
2. Убедитесь, что все итоговые файлы соответствуют SHA256SUMS; не меняйте бинарники после подписи. `updates/stable.json` и `updates/beta.json` — **неопубликованные** входы кандидата. Для каждого manifest нужен отдельный detached signature ровно64байта.
3. На CachyOS с OpenSSL3, в каталоге offline-signing:

```bash
sha256sum -c SHA256SUMS
sha256sum -c SIGNING-INPUT-SHA256
openssl pkeyutl -sign -rawin \
  -inkey /путь/к/вашему/offline-ed25519-private.pem \
  -in updates/stable.json -out updates/stable.json.sig
openssl pkeyutl -verify -rawin -pubin \
  -inkey updates/release-public.pem \
  -in updates/stable.json -sigfile updates/stable.json.sig
wc -c updates/stable.json.sig
```

Ожидается Signature Verified Successfully и64байта. Если public key не совпадает — остановитесь; pinned key клиента менять нельзя. Для Beta замените stable.json/stable.json.sig на beta.json/beta.json.sig. Это другая подпись, Stable signature не подходит Beta bytes.

4. Для безопасного updater E2E сначала используйте разрешённый владельцем отдельный Beta feed и GitHub Pre-release/Draft: точный tag v1.5.0 допустим как pre-release; Stable main/updates/stable.json не меняйте. Установленный1.2 выбирает Beta в настройках обновлений; manifest остаётся schema1 и с тем же pinned public key. Без публикации тестового feed и owner signature реальный полный E2E невозможен. Команда подписи **ничего не загружает в GitHub**.
5. После успешного теста установки/restart/profile preservation и отдельного rollback, собственного разрешения на Stable: загрузите точные assets в Releasev1.5.0, changelog и контрольные суммы; затем exact stable manifest+signature. Не пересохраняйте JSON редактором (подпись привязана к байтам). Хеши клиента защищены именно подписанным manifest; SHA256SUMS по недоверенному каналу сам по себе не аутентификация.

Рекомендуется `gh release create v1.5.0 --draft --title 'АЕГИС 1.5.0' --notes-file CHANGELOG-1.5.0.md <проверенные-артефакты>` только после вашего явного решения. Work не публикует Release и не создаёт production подпись. Не передавайте private PEM аргументом shell history как содержимое; команда использует только локальный путь.
