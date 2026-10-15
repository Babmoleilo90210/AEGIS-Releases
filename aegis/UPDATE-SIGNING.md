# Offline подпись АЕГИС 1.0.0

Production private key никогда не запрашивается, не копируется и не входит в source, bundle, GUI или сервер. Единственный root of trust клиента — встроенный public Ed25519 key. updates/release-public.pem — публичная копия для ручной verification.

Текущий production audit содержит false из-за native acceptance и frozen AUTH ограничений. Команды ниже предназначены владельцу **после закрытия этих условий** и проверки final exact files. JSON пока только локальная заготовка; live stable/beta и Release не публиковать.

В распакованном AEGIS-1.0.0-release сначала:

```sh
sha256sum -c SHA256SUMS
sha256sum -c SIGNING-INPUT-SHA256
python3 -c 'import json; a=json.load(open("FINAL-RELEASE-AUDIT-1.0.0.json")); assert a["productionReady"], "STOP: production acceptance is not complete"'
```

Последняя команда намеренно останавливает процесс на текущем false. После честной приёмки binary files/JSON не изменяются, иначе повторяются package checks/SHA/manifest. Audit не является тайным bypass/key и не влияет на runtime trust.

Точная подпись на CachyOS (только владельцем, offline):

```sh
python3 tools/sign-release-manifest updates/stable.json   "$HOME/.local/share/aegis-release-signing/release-private.pem"   --output updates/stable.json.sig
```

Внутри tool стандартный OpenSSL pkeyutl Ed25519, без собственного алгоритма. Он проверяет schema и соответствие pinned public key до окончательной записи, не перезаписывает имеющуюся signature и не копирует key. Эквивалент непосредственной OpenSSL команды:

```sh
openssl pkeyutl -sign -rawin   -inkey "$HOME/.local/share/aegis-release-signing/release-private.pem"   -in updates/stable.json -out updates/stable.json.sig
```

Подпись — **64 raw bytes**, не base64 и не hex. Проверка публичным файлом:

```sh
openssl pkeyutl -verify -pubin -rawin   -inkey updates/release-public.pem   -in updates/stable.json -sigfile updates/stable.json.sig
python3 tools/verify-release-manifest updates/stable.json updates/stable.json.sig   --assets . --minimum-version 1.0.0
```

Для переноса достаточно JSON, signature, public.pem и release assets; private key остаётся offline. После получения подписи повторно сверяются signing input hash и все asset hashes. Только затем отдельно согласуется публикация GitHub Release v1.0.0 и двух **согласованных** live update файлов. Signing tool, draft helper и updater никогда не публикуют live channel автоматически.
