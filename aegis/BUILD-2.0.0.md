# Сборка development candidate 2.0.0

Используйте Java 21 и tools/build-local.py с явно указанными SHA-256 проверенными зависимостями. В ходе этой работы использовался Temurin 21.0.12.1+1; SHA-256 архива ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94. Клиентская база, JavaFX, native Tor/libsodium — из опубликованных Windows/AppImage 1.5.0 с проверенными релизными hash; PDF/JUnit зависимости закреплены в прежнем build-archive.py.

Полный source ZIP 1.5.0 SHA-256 7907e1a5970f5a167cec60f8d171c56d69bf013fc4d593b1236eef3265c3e9a8. Тег f9ac41ab9a7aca659e23df88f020a84618af77a1 содержит только часть исходников; отдельным коммитом восстановлены отсутствующие опубликованные файлы. Это не переход на исходники 1.2.0.

Упаковка использует packaging/package-clients.py, MinGW x64, NSIS, squashfs-tools и неизменённый runtime AppImage. Сначала создайте client-ui/build/stage/linux и win с полным набором платформенных зависимостей и новыми client-core/client-ui 2.0.0 JAR, common-protocol 0.2.0. Не смешивайте Windows/Linux JavaFX natives. Затем выполните verify_client_release.py. Нативная приёмка отдельно; cross-compilation не означает запуск Windows 11.

Для offline staging уже скомпилированных JAR используйте `tools/stage-candidate.py --linux-base <распакованный AppImage 1.5.0> --windows-base <распакованный Windows AEGIS 1.5.0> --deps <каталог safeweb-deps>`. По умолчанию он читает `build/local-java21/{client-core,client-ui,common-protocol}.jar` и создаёт `client-ui/build/stage/{linux,win}`. Проверка требует BCpg/BCutil/BCprov 1.86, Commons Compress 1.28.0, XZ 1.12, Commons IO 2.20.0, Lang3 3.18.0 и Codec 1.19.0; их SHA-256 совпадают с `gradle/verification-metadata.xml` и `packaging/client_runtime.py`. Одна BCprov копия может поступать из проверенной базы 1.5.0. Тестовые JUnit/Monocle и серверные JAR в клиент не добавляются.

Staging, `package-clients.py` и `verify_client_release.py` отдельно проверяют эти runtime зависимости и включение официального публичного Tor Browser verification key в core JAR. Наличие ключа не означает проверку свежести отзывов сертификата или запуск браузера. `RUNTIME-STAGE-2.0.0.json` фиксирует хеши скопированных JAR; этот документ не заменяет итоговую фиксацию source commit и native acceptance. Проверка staging: `cd tools && python -m unittest -v test_stage_candidate`.

Tor Browser не включён в дистрибутив; его лицензии и обновления не выдаются за проверенные. Установка отдельного официального подписанного пакета описана в SAFE-WEB-2.0.0.md, обычный запуск заблокирован release gate.
