# Офлайн-подпись АЕГИС 6.0.0

Комплект подготовки не использует приватные ключи владельца, не создаёт производственные подписи и не меняет Stable feed. `productionReady=false` сохраняется даже после проверки публичных подписей APK. Подпись и контрольные суммы не заменяют нативную приёмку, испытания Tor, миграцию и решение владельца о публикации.

Существующий Ed25519 release key и закреплённый публичный ключ updater не изменены. Android использует отдельный APK signing key: ключи выпуска, учётной записи, Identity, Relay и Android не взаимозаменяемы. Приватные ключи остаются на доверенном компьютере владельца.

## Зафиксированные исходники и артефакты

Все команды выполняются из каталога `aegis` доверенного Git checkout. До отключения сети получите исходники и историю, проверьте нужный полный commit и перенесите проверенную копию на офлайн-компьютер. Экспорт ZIP не содержит `.git` и сам по себе не заменяет checkout для генератора. Рабочее дерево должно быть чистым, `HEAD` должен точно совпадать с переданным 40-символьным commit. Каталоги артефактов и результатов располагаются вне checkout.

```sh
python3 tools/prepare-sources600.py --project . \
  --source-commit FULL_40_CHARACTER_COMMIT --output /offline/artifacts
```

Экспортируются реальные Git blobs полного репозитория и клиентского поддерева. Для каждого ZIP проверяются точный набор файлов, режимы, размер, содержимое и `SOURCE-COMMIT-6.0.0.json`. Генератор не перезаписывает предыдущие ZIP.

Обязательны десять ролей: `debian13-server`, `windows-installer`, `windows-portable`, `cachyos-appimage`, `source`, `client-source`, `android-core`, `android-mail`, `android-glas`, `android-strazh`. Все четыре платформенные поставки отражаются в отдельном inventory. Для каждой роли указывается фактический файл и JSON provenance. Пример элемента спецификации:

```json
{
  "schemaVersion": 1,
  "version": "6.0.0",
  "sourceCommit": "FULL_40_CHARACTER_COMMIT",
  "artifacts": [
    {
      "role": "windows-portable",
      "fileName": "AEGIS-6.0.0-Windows-x64.zip",
      "provenanceFile": "BUILD-PROVENANCE-6.0.0.json"
    }
  ]
}
```

Пример сокращён: реально необходимы все десять элементов. Отсутствующий файл, неверное имя, повтор роли или заглушка вместо provenance приводят к отказу. Provenance каждого файла содержит `sourceCommit`, при наличии `sourceTree` — тот же tree, и `binaryArtifactSha256` с точным именем и SHA-256 этого файла. Поле `implementationCommit`, если присутствует, также должно совпадать. Provenance и артефакты включаются в плоский `SHA256SUMS`; `SHA256SUMS` не включает себя и создаваемые manifest. В перечне также нужен `CHANGELOG-6.0.0.md`.

## Android: сначала подпись APK

В среде разработки выдаются явно обозначенные `AEGIS-{Core,Mail,Glas,Strazh}-6.0.0-unsigned.apk` и при необходимости отдельные `-TEST.apk`. Тестовый сертификат не является сертификатом владельца. Подробные команды создания собственного ключа и подписи находятся в `android/docs/OWNER-OFFLINE-SIGNING-ANDROID-6.0.0.md`.

На офлайн-компьютере подпишите все четыре APK одним собственным сертификатом. Итоговые имена для режима публичной проверки: `AEGIS-Core-6.0.0.apk`, `AEGIS-Mail-6.0.0.apk`, `AEGIS-Glas-6.0.0.apk`, `AEGIS-Strazh-6.0.0.apk`. Если в инструкции Android использовано имя `-owner-candidate.apk`, переименуйте готовый проверенный файл в соответствующее итоговое имя до формирования provenance и SHA256SUMS. Переименование не меняет содержимое APK. Сторонние Tor Browser и Obsidian не переподписываются.

После подписи заново сформируйте точные хеши APK, provenance, SHA256SUMS и спецификацию имён. Затем вызовите:

```sh
python3 tools/generate-ecosystem-manifest600.py --project . \
  --source-commit FULL_40_CHARACTER_COMMIT \
  --artifacts /offline/artifacts --spec /offline/spec600.json \
  --output /offline/signing-final \
  --apksigner /trusted/android-sdk/build-tools/35.0.0/apksigner \
  --expected-apk-certificate EXPECTED_LOWERCASE_64_HEX_CERTIFICATE_SHA256
```

Официальный SDK `apksigner` и ожидаемый отпечаток сертификата предоставляются владельцем по доверенному пути. На Windows можно передать официальный `lib/apksigner.jar` и задать `JAVA_HOME`; shell wrappers `.bat/.cmd` не исполняются. Утилита выполняет только `verify`, проверяет одного подписанта, точный сертификат и успешную v2/v3 подпись, ограничивает вывод/время, повторно проверяет неизменность APK. Она не читает keystore и не подписывает APK. Ошибка любого из четырёх файлов отменяет формирование всего inventory.

Для подготовки неподписанного пакета опустите оба параметра `--apksigner`/`--expected-apk-certificate`; тогда принимаются только имена `-unsigned.apk`. Неполная пара параметров запрещена. В этом режиме inventory прямо указывает необходимость подписи владельцем.

## Два отдельных manifest

Генератор создаёт только новый каталог и два файла:

- `AEGIS-6.0.0-stable.UNSIGNED.json` — прежняя строгая схема updater с четырьмя артефактами: Windows installer, portable ZIP, CachyOS AppImage, client-source ZIP.
- `AEGIS-6.0.0-ecosystem.UNSIGNED.json` — отдельный подписываемый inventory Debian, Windows, CachyOS, четырёх APK и исходников. Он не добавляет отсутствующий runtime updater Android/сервера.

`tag` строго равен `v6.0.0`, URL содержат `/releases/download/v6.0.0/`. Проверки старых Java-парсеров не ослаблены. Файл `SIGNING-INPUT-SHA256` фиксирует точные байты обоих документов.

## Ed25519 — только на компьютере владельца

После финальной приёмки и проверки SHA256SUMS подпишите обычный manifest существующим helper:

```sh
sha256sum -c /offline/artifacts/SHA256SUMS
python3 tools/sign-release-manifest \
  /offline/signing-final/AEGIS-6.0.0-stable.UNSIGNED.json \
  /secure/offline/release-private.pem \
  --output /offline/signing-final/AEGIS-6.0.0-stable.UNSIGNED.json.sig
python3 tools/verify-release-manifest \
  /offline/signing-final/AEGIS-6.0.0-stable.UNSIGNED.json \
  /offline/signing-final/AEGIS-6.0.0-stable.UNSIGNED.json.sig \
  --assets /offline/artifacts
```

Отдельный inventory не принимается legacy parser как обновление. Для его точных байтов используйте OpenSSL Ed25519 и затем публичную проверку тем же закреплённым ключом:

```sh
openssl pkeyutl -sign -rawin -inkey /secure/offline/release-private.pem \
  -in /offline/signing-final/AEGIS-6.0.0-ecosystem.UNSIGNED.json \
  -out /offline/signing-final/AEGIS-6.0.0-ecosystem.UNSIGNED.json.sig
python3 tools/verify-ecosystem-manifest600.py \
  /offline/signing-final/AEGIS-6.0.0-ecosystem.UNSIGNED.json \
  /offline/signing-final/AEGIS-6.0.0-ecosystem.UNSIGNED.json.sig \
  --assets /offline/artifacts
```

Оба пути к ключам являются примерами локальных путей владельца. Эти операции с ключом владельца в среде разработки не выполнялись. Пароль защищённого ключа вводится локально OpenSSL; его не передают аргументом команды. Не перезаписывайте существующую подпись иной версией документа. После изменения любого APK, бинарника, provenance или SHA256SUMS пересоздаются оба manifest и обе подписи.

Публикация GitHub Release, присвоение Stable и замена `updates/stable.json`/`.sig` остаются отдельными действиями владельца после прохождения обязательных gates. Ни один инструмент этого комплекта не публикует релиз и не переводит `productionReady` в `true`.
