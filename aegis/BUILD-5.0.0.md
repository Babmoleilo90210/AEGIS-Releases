# Сборка АЕГИС 5.0.0

База: tag v2.5.0, commit `699a3260fa456a40d4d16d3b711c957b088f9ab3`. Требуется JDK 21; Gradle 9.8.0 и зависимости проверяются закреплёнными SHA-256 и dependency verification. Нативные библиотеки берутся из явно проверенных входов, а не из случайного PATH.

## Штатная сборка

```sh
./gradlew --continue test :client-ui:jar :community-server:jar :news-worker:jar :client-ui:compileSmokeJava :relay-server:verifyIsolation
```

Для тестов требуются разрешённые и проверенные libsodium/Opus/SpeexDSP в `.native-test/native/`. Задача prepareNative — инструмент сборки, не скрытый runtime downloader. Модульный Java-клиент не включает серверные классы, SQLite/JUnit или news-worker в клиентский classpath. Серверному пакету нужен полный Java 21 с `jdk.httpserver`; клиентский сокращённый runtime для него не используется.

`tools/build-local.py` — дополнительный офлайн-компилятор для явно переданных JDK/JAR/native входов. Он сохраняет отдельные XML по пакетам и продолжает независимые тестовые модули после неуспешного набора. Он не заменяет нативную приёмку и не загружает зависимости. Итоговые релизные JAR берутся из воспроизводимых Gradle archive tasks с фиксированным порядком и timestamps.

## Упаковка

`tools/stage-candidate500.py` заменяет только собственные JAR и закреплённые зависимости в проверенных платформенных базах 2.5.0. `packaging/package-clients500.py` требует чистый точный source commit, полную проверку базовых ZIP/AppImage, Java/native provenance и проверенный MinGW/NSIS/SquashFS инструментарий. Windows launcher/maintenance EXE собираются заново с версией 5.0.0.0; Linux сохраняет проверенный Type 2 bootstrap. Commons-logging 1.4.0 заменяет старую 1.3.5 без дублей.

`tools/package-community500.py` подготавливает отдельный серверный комплект. `tools/package-native500.py` собирает текущие проверки и формы результатов владельца. `tools/assemble-release500.py` создаёт source ZIP из Git, копирует обязательные документы, связывает provenance, проверяет SHA и подготавливает unsigned manifest. Они не подписывают и не публикуют выпуск.

Точные команды, версии инструментария, результаты и SHA входов/выходов находятся рядом с артефактами в BUILD-PROVENANCE-5.0.0.json. Финальный source commit указывается там, чтобы избежать самоссылки Git commit на собственное содержимое. Все проверки, выполненные после упаковки, сохраняются отдельно от исторических результатов 2.5.0.

## Проверенные входы Tor Expert Bundle

Клиентский встроенный Tor полностью заменяется официальным Expert Bundle **15.0.25** (Tor **0.4.9.14**, OpenSSL **3.5.9**). Все runtime/data/license файлы берутся из новых архивов; из АЕГИС отдельно переносится только закреплённая конфигурация Snowflake. Исторические инструменты упаковки 2.5.0 не меняют свои исходные pins.

У `package-clients500.py` обязательны четыре дополнительных аргумента:

```sh
--tor-linux-archive /path/to/tor-expert-bundle-linux-x86_64-15.0.25.tar.gz \
--tor-linux-signature /path/to/tor-expert-bundle-linux-x86_64-15.0.25.tar.gz.asc \
--tor-windows-archive /path/to/tor-expert-bundle-windows-x86_64-15.0.25.tar.gz \
--tor-windows-signature /path/to/tor-expert-bundle-windows-x86_64-15.0.25.tar.gz.asc
```

| Вход | SHA-256 | Байты |
|---|---|---:|
| `tor-expert-bundle-linux-x86_64-15.0.25.tar.gz` | `19cf18726eecb362e0f21d27afa9ea9efe5da928bfdfbb1ceb5fe54519e87f4a` | 32448097 |
| `tor-expert-bundle-linux-x86_64-15.0.25.tar.gz.asc` | `1ae7917f8abd120f2fedca1ef5173296bcc322d800f38f8abebbe18d9da8eb26` | 833 |
| `tor-expert-bundle-windows-x86_64-15.0.25.tar.gz` | `c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252` | 22507599 |
| `tor-expert-bundle-windows-x86_64-15.0.25.tar.gz.asc` | `4ecb546445aaffff1f5a95b7544af968aff276361968b4cb03c612c010bf30ca` | 833 |

Первичный источник: [Tor Project, официальный каталог 15.0.25](https://dist.torproject.org/torbrowser/15.0.25/). Фактические URL официального зеркала и первичного источника записаны в `packaging/native-kit500/tor-runtime-provenance-5.0.0.json` и `docs/test-results/5.0.0-dependencies/native/tor-patch/DOWNLOADS.json`. Оба архива и detached-подписи независимо проверены GnuPG и действующим production `TorBrowserSignature`; primary fingerprint остаётся **EF6E286DDA85EA2A4BA7DE684E2C6E8793298290**, signing subkey — **022DA248432D2A0E0F54E65E316C1FACD62D07D9**. Подписанный официальный список SHA-256 совпадает. Не следует заменять эти входы одноимёнными непроверенными файлами.

Offline packaging повторно проверяет точные SHA/размеры архивов/подписей и каждый member по исходному реестру. Изменяемый sidecar установленного runtime не является корнем доверия. Выходы `TOR-RUNTIME-5.0.0.json` и `BUILD-INPUTS.json.patchedTor` записывают фактически упакованные файлы. `verify_client_release500.py` независимо проверяет полный каталог `tor/` на обоих клиентах. Старые библиотеки и лишние исполняемые файлы отклоняются.

Результат локального `DisableNetwork 1` probe подтверждает конфигурацию, загрузку нового OpenSSL и жизненный цикл процесса через методы `EmbeddedTor`; это не публичный bootstrap или сетевая приёмка. У «Взора» bwrap/slirp обеспечивают границы namespaces/файлов, но **slirp не является kernel firewall, принудительно пропускающим только Tor**. Tor-only веб-трафик опирается на штатную архитектуру Tor Browser. Защита от прямого egress полностью захваченного browser broker не подтверждена; этот gate нельзя отмечать PASS по одному факту запуска Tor. Нативные DNS/WebRTC/HTTPS/onion и захват трафика остаются отдельными обязательными проверками.
