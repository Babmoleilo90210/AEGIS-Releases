# Офлайн-подпись АЕГИС 1.5.0 владельцем

Private key остаётся на вашем офлайн устройстве. Не передавайте его в чат, Work, GitHub, CI или VPS. Сейчас `productionReady=false`: подготовлены кандидат и доказательства доступных проверок. Подпись не заменяет нативную приёмку и полный updater E2E.

## Проверка пакета

Распакуйте полный `AEGIS-1.5.0-release-candidate.zip`. Перейдите в каталог `AEGIS-1.5.0-RC`. Там должны находиться бинарники, исходники, `SHA256SUMS` и папка `updates`. Маленький `AEGIS-1.5.0-offline-signing.zip` содержит только входы подписи и инструкцию; для проверки всех файлов нужен полный пакет.

На CachyOS:

```bash
sha256sum -c SHA256SUMS
sha256sum -c SIGNING-INPUT-SHA256
```

Все строки должны быть OK. Проверка SHA сама по себе не аутентификация источника: первоначальный пакет нужно получить по доверенному каналу. `updates/stable.json` и `updates/beta.json` различаются байтами и требуют отдельных подписей. Не меняйте JSON или бинарники после подписи. Не используйте старую подпись от другой сборки.

## Подпись на офлайн CachyOS

Для первого испытания используйте **Beta**. Команда с OpenSSL 3 читает только локальный файл вашего существующего Ed25519 ключа. Замените путь, не вставляя содержимое ключа в команду:

```bash
test ! -e updates/beta.json.sig
openssl pkeyutl -sign -rawin \
  -inkey /путь/к/вашему/offline-ed25519-private.pem \
  -in updates/beta.json -out updates/beta.json.sig
openssl pkeyutl -verify -rawin -pubin \
  -inkey updates/release-public.pem \
  -in updates/beta.json -sigfile updates/beta.json.sig
wc -c updates/beta.json.sig
```

Ожидается `Signature Verified Successfully` и ровно 64 байта. Если pinned public key не соответствует вашему ключу — остановитесь; менять ключ клиента для обхода проверки нельзя. Приватный PEM не копируется в пакет. На сетевой компьютер переносится только готовая подпись и manifest, не private key. **Команда подписи ничего не загружает в GitHub.**

## Реальный тест updater без изменения Stable

1. Выполните локальные проверки Windows 11, CachyOS KDE Wayland и X11 на копиях профилей. Native kit не меняет production профиль.
2. Только после собственного отдельного разрешения на тестовую публикацию создайте **публичный Pre-release** GitHub с tag `v1.5.0` в `Babmoleilo90210/AEGIS-Releases`. Прикрепите неизменные Setup EXE, portable ZIP, AppImage, client-source ZIP, source ZIP, `SHA256SUMS`, `CHANGELOG-1.5.0.md` и комплект приёмки. Draft подходит для подготовки, но **из Draft updater не сможет анонимно скачать assets через Tor**.
3. После отдельного разрешения на тестовый feed поместите точные `beta.json` и `beta.json.sig` в `main/updates/` репозитория. Установленный 1.2.0 использует фиксированный Beta URL в этом пути; произвольный staging URL без изменения его бинарника не поддерживается. **Не меняйте `stable.json` и `stable.json.sig`.** Beta затронет пользователей, добровольно выбравших этот канал.
4. На установленной 1.2.0 выберите Beta в настройках обновлений. Нужны копии профиля и два тестовых аккаунта. Проверьте Tor, системное письмо, загрузку/progress/resume, Ed25519/SHA/размер, consent, полный backup, установку, restart, новую версию, письма/identity/темы/TTL и создание пустого архива. Сохраните результат отдельно для трёх нативных платформ.
5. На отдельном disposable профиле проверьте rollback при неудачном startup. Не модифицируйте production binary и не повреждайте единственный профиль. Порядок сценариев — в `NATIVE-ACCEPTANCE-1.5.0.md`. Проверка manifest и успешное скачивание не считаются полной установкой.

Work не публиковал Pre-release, Release или feed. Без подписи владельца и разрешённой публикации Beta полный updater E2E кандидата пока недоступен.

## Stable после приёмки

Когда все обязательные проверки завершены и владелец отдельно разрешил Stable, подпишите `stable.json`:

```bash
test ! -e updates/stable.json.sig
openssl pkeyutl -sign -rawin \
  -inkey /путь/к/вашему/offline-ed25519-private.pem \
  -in updates/stable.json -out updates/stable.json.sig
openssl pkeyutl -verify -rawin -pubin \
  -inkey updates/release-public.pem \
  -in updates/stable.json -sigfile updates/stable.json.sig
wc -c updates/stable.json.sig
```

Подпись Beta не подходит Stable. Перенесите только public manifest/signature, снимите статус Pre-release после собственного решения и обновите Stable feed **точными проверенными байтами**. Хеши из подписанного manifest должны соответствовать уже загруженным assets. Если изменилась хотя бы одна сборка, нужны новые SHA и manifest с новой подписью. Не пересохраняйте подписанный JSON редактором.
