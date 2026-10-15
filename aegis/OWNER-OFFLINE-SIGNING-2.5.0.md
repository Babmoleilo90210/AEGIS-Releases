# Офлайн-подпись АЕГИС 2.5.0 владельцем

**Сейчас productionReady=false. Не подписывать для Stable-публикации до закрытия RELEASE-GATES-2.5.0.json.** Подготовленные manifest имеют суффикс `.UNSIGNED.json`; `.sig` владельца не создана. Ключ владельца в Work, GitHub, CI и Relay не требуется и не должен туда передаваться. Pinned public key сохранён.

## Проверка перед подписью

1. На доверенной машине проверьте SHA256SUMS, BUILD-PROVENANCE-2.5.0.json, исходный commit/tree и совпадение Java JAR в Windows/Linux.
2. Выполните обязательную нативную приёмку, настоящий Tor Browser, IP/DNS/WebRTC capture, два физических устройства в разных сетях, 60-минутный Глас и updater E2E/rollback на отдельном тестовом канале.
3. Приложите настоящие доказательства и повторно вычислите готовность. Любой FAIL/BLOCKED/NOT_RUN обязательного gate сохраняет false. Компиляция не заменяет эти проверки.
4. Если артефакты или release notes изменились — пересоздайте SHA256SUMS и unsigned manifest. Не редактируйте подписанные bytes.

Генерация на машине с итоговыми артефактами:

```sh
python3 tools/generate-release-manifest.py --artifacts /path/to/artifacts --version 2.5.0 --channel stable --output /path/to/signing/stable-2.5.0.UNSIGNED.json --title 'АЕГИС 2.5.0 — «Взор и Глас»'
```

Файл создаётся исключительно новым; production feed не перезаписывается. `version=2.5.0`, `tag=v2.5.0`, URL всех артефактов содержат `/releases/download/v2.5.0/`. Суффикс beta в tag при version без beta отвергается, как и несовпадающий URL. Future GitHub URL в unsigned metadata не означает публикацию.

Точный порядок подписи и проверки указан в OWNER-OFFLINE-MANIFEST-2.5.0.md и реализован в `tools/release_manifest.py`. Используйте штатный offline sign helper только на доверенной машине владельца; он дополнительно проверяет соответствие ключа закреплённому публичному ключу. Не отправляйте private key или пароль в чат.

Тестовая подпись native-kit создаётся одноразовым тестовым ключом и проверяется только отдельным test helper. Она не подходит production-клиенту, не меняет pinned key и не является подписью владельца. Полный updater E2E с release-pinned подписью остаётся отдельным обязательным испытанием.

После всех проверок владелец отдельно разрешает публикацию GitHub Release и изменение signed Stable feed. В этой работе ни публикация, ни изменение feed не выполняются.
