# Android Tor: проверка происхождения, лицензий и индексированных уязвимостей

Проверено 18 октября 2026 г. Это read-only review зависимостей: SDK artifacts/production/Android sources не изменялись. Нативная сборка из исходников, реальные Android Tor/voice испытания и полная проверка APK здесь не проводились. ProductionReady данным review не присваивается.

## Происхождение

Tor Android 0.4.9.14 AAR и его sources.jar имеют действительные OpenPGP signatures Guardian Nathan primary `BBE20FD6DA48A3DD4CC7DF41A801183E69B37AA9`. jtorctl 0.4.5.7 JAR и sources.jar имеют действительные signatures Hans primary `EE6620C7136B0D2C456C0A4DE9E28DEA00AA5556`, signing subkey `972239DBE68699F526C06A053E177817BA1B9BFA`. Primary fingerprints сверены с официальной HTTPS страницей https://guardianproject.info/signing-keys/ до доверия загруженным ключам; subkey проверен как связанный с этим primary. GPG TRUST_UNDEFINED означает отсутствие локальной web-of-trust сертификации и не заменяет/не отменяет явную проверку published fingerprint. Доверие не основано только на short key ID или выдаче keyserver. Private keys не используются.

Точные SHA/размеры в ARTIFACT-PINS.json. jtorctl JAR получен MavenCentral и совпадает с upstream .jar.sha256; Google LocalBroadcastManager 1.1.0 получен с официального Google Maven HTTPS. Для Google AAR в этой проверке нет заявленной отдельной vendor OpenPGP-подписи. HTTPS/репозиторные хеши не являются подписью владельца АЕГИС.

Найден exact upstream tag 0.4.9.14→commit `0340ba1609cb73e663e202a316d083803e399db4`. TorService.java в подписанном sources.jar байтово совпал с файлом этого commit (SHA`9a80508dc2e0c9a6f18d9edee88541446f268d6f47bc8b187f79545ea5ebdb62`). Gitlinks и официальные теги native библиотек сопоставлены в NATIVE-PIN-MATCHES.json. Полная воспроизводимость native binaries из этих исходников не проверена.

## Исправление важной ошибки upstream README

README заявляет OpenSSL 3.5.7. Однако ВСЕ четыре AAR libtor.so содержат строку `OpenSSL 3.5.9 29 Sep 2026` (в действительном выводе с пробелами), а pinned OpenSSL gitlink `45e844fa2a14ec92d146bd8f5778ac130b6625fb` совпадает с официальным openssl-3.5.9 tag commit. Поэтому окончательный inventory использует3.5.9. Начальный OSV-REQUEST.json по старому README сохранён для истории; окончательные актуальные запросы — OSV-EXACT-*.json.

Фактические native strings: Tor 0.4.9.14, libevent 2.1.13-stable, OpenSSL 3.5.9, zlib 1.3.2, zstd 1.5.7. Tor gitlink `4a522a3ca491c6c04d4a44cb006b92101c42efc1` совпадает с встроенным source-id suffix. Строки сами по себе не являются криптографическим доказательством reproducible build; они сопоставлены с подписанным AAR и опубликованными source pins. AAR не содержит GeoIP database assets. Нативные библиотеки статически объединены; Android system libc/libm/libdl/liblog не перепаковываются этим AAR.

## Лицензии и notices

ANDROID-TOR-NOTICES.txt подготовлен для включения упаковщиком APK без изменения текста; его SHA и исходные лицензии перечислены в NOTICE-INVENTORY.json. Java wrapper/jtorctl — BSD-3-Clause; Tor aggregate LICENSE сохранён целиком с его third-party terms; libevent — BSD-3-Clause с включёнными дополнительными BSD/ISC/MIT notices; OpenSSL 3.5.9 и LocalBroadcastManager — Apache-2.0; zlib — Zlib; zstd — выбран BSD-3-Clause вариант из dual BSD/GPLv2.

Исторический TorAndroid LICENSE ссылается на Orbot, Privoxy и iptables. Это не основание объявлять Privoxy/iptables компонентами этого APK или добавлять к АЕГИС их GPL terms. Сохранён именно BSD wrapper section, а actual native Tor license получен из точного gitlink. OpenSSL tag не содержит NOTICE/NOTICE.md; сохранён его LICENSE.txt, copyright attribution взят из исходников данного commit. Наличие полного source package/остальных SDK dependency notices и окончательного APK inventory должен проверить упаковщик.

POM также объявляет Kotlin stdlib 2.2.10, поэтому он включён в SCA metadata review. Android агент сообщил отсутствие kotlin references в AAR Java classes; здесь НЕ заявляется, что Kotlin действительно включён в APK. Финальная dependency closure/APK inventory определяет, нужны ли дополнительные Kotlin notices. Test-scope зависимости jtorctl POM не считаются runtime только из-за наличия в POM.

## OSV и пределы вывода

Фактически выполнен HTTPS POST https://api.osv.dev/v1/querybatch, HTTP 200. Окончательный batch: четыре Maven coordinate/version (TorAndroid, jtorctl, LocalBroadcastManager, Kotlinstdlib), пять OSS-Fuzz native version queries и пять exact native git commit queries. Получено 14 пустых results, next_page_token нет. Формулировка результата: **NO_INDEXED_HITS_FOR_SUBMITTED_IDENTIFIERS**.

Пустой ответ не доказывает, что пакет распознан индексом, не гарантирует полноту экосистемы/fork coverage, не проверяет build flags и НЕ означает «CVE отсутствуют». Это не замена upstream advisories, native fuzzing, SAST или device acceptance. Official OpenSSL 3.5 release notes подтверждают, что3.5.9 — security patch release; review не заявляет абсолютную безопасность. Raw requests/responses/даты/SHA сохранены, результат ограничен моментом запроса.

## Дальнейшие обязательные проверки

Упаковщик включает notices в фактический APK и проверяет их presence/hash; сверяет окончательные dex/native компоненты и исключённый Kotlin; выполняет физические Android 33–36 Tor/voice/lifecycle/leak/16KiB acceptance и native SBOM/rebuild review. Это объективные последующие gates, а не PASS этого dependency review. Существующие private account keys/архивы/production feed не использовались.
