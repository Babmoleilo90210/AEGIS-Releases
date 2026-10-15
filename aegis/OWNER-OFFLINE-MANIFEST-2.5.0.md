# АЕГИС 2.5.0: manifest для офлайн-подписи

`tools/generate-release-manifest.py` создаёт только **UNSIGNED JSON** из окончательных локальных файлов. Он не подписывает данные, не меняет update feed и ничего не публикует. Готовность к Stable определяется приёмкой отдельно.

В одном каталоге должны находиться:

- `AEGIS-Setup-2.5.0-x64.exe`
- `AEGIS-2.5.0-Windows-x64.zip`
- `AEGIS-2.5.0-CachyOS-x86_64.AppImage`
- `AEGIS-2.5.0-client-source.zip`
- `CHANGELOG-2.5.0.md`
- `SHA256SUMS`

`SHA256SUMS` заранее создаётся для окончательных артефактов и changelog. Используется ASCII-формат `64_строчных_hex_символа`, два пробела, простое имя файла. Все перечисленные файлы должны присутствовать и совпадать по SHA-256. Сам `SHA256SUMS` в свой список не включается. Дополнительные документы и полный source ZIP могут находиться в списке; manifest updater сохраняет четыре совместимых типа артефактов.

```bash
python3 tools/generate-release-manifest.py \
  --artifacts /path/to/final-artifacts \
  --version 2.5.0 \
  --channel beta \
  --minimum-supported 1.5.0 \
  --output /path/to/offline/AEGIS-2.5.0-beta.UNSIGNED.json
```

Генератор измеряет размер и SHA-256 настоящих файлов, проверяет существующий `SHA256SUMS`, схему и ссылки. Output создаётся эксклюзивно, повторная запись и имена `stable.json`/`beta.json` отклоняются. При необходимости воспроизводимой метки времени добавьте `--published-at 2026-10-15T09:00:00Z`, указав фактическую дату подготовки. Release notes берутся из changelog; лимит — 12 000 символов.

При `version=2.5.0` оба канала используют `tag=v2.5.0` и ссылки `/releases/download/v2.5.0/…`. `channel=beta` не добавляет суффикс к tag. Для `version=2.5.0-beta.1` сначала собираются файлы той же prerelease-версии; затем generator использует `tag=v2.5.0-beta.1` и соответствующие имена файлов. Сочетание `version=2.0.0`, `tag=v2.0.0-beta.1` отклоняется до подписи.

На компьютере владельца без сети после просмотра exact JSON и завершения обязательной приёмки:

```bash
python3 tools/sign-release-manifest \
  /path/to/offline/AEGIS-2.5.0-beta.UNSIGNED.json \
  /offline-only/owner-ed25519-private.pem \
  --output /path/to/offline/AEGIS-2.5.0-beta.UNSIGNED.json.sig

python3 tools/verify-release-manifest \
  /path/to/offline/AEGIS-2.5.0-beta.UNSIGNED.json \
  /path/to/offline/AEGIS-2.5.0-beta.UNSIGNED.json.sig \
  --assets /path/to/final-artifacts \
  --minimum-version 2.0.0
```

Приватный ключ остаётся у владельца. Pinned public key не меняется. На сетевую машину переносятся только публичные manifest/signature/артефакты. После изменения любого артефакта нужны новые SHA256SUMS, manifest и подпись над новыми точными байтами. Каналы подписываются отдельно. Обновление production Stable feed и публикация требуют отдельного решения владельца.

Тест `SignedManifestCompatibility250Test` использует только временный Ed25519 key в памяти и package-private test injection. Он запускает настоящий unsigned generator, проверяет metadata текущим и неизменёнными историческими parser sources, сохраняет signature-first, pinned key, hash и anti-rollback проверки. Источники и SHA-256 frozen fixtures записаны в `client-core/src/test/resources/org/securemail/client/update/frozen/PROVENANCE.json`. В Git-теге 1.5.0 отсутствуют JsonData/SemVersion: только эти две зависимости взяты из зафиксированной базы 2.0.0, что явно отмечено в provenance; это не полная пересборка исторического клиента 1.5.0. Проверка parser compatibility не заменяет установку, перезапуск и rollback updater E2E.
