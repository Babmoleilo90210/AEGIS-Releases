# Дополнение: AndroidX Annotation 1.1.0

Точная Maven-координата: `androidx.annotation:annotation:1.1.0`.

Это реальный официальный Google JAR, добавленный Android-сборщиком для компиляции неизменённого, отдельно OpenPGP-проверенного TorService source. Заглушки Nullable не используются. По данным сборщика компонент включается в DEX; этот аудит не проводил самостоятельный анализ финального DEX.

- SHA-256 JAR: `d38d63edb30f1467818d50aaf05f8a692dea8b31392a049bfa991b159ad5b692`.
- SHA-1 JAR: `e3a6fb2f40e3a3842e6b7472628ba4ce416ea4c8`, совпадает с фактически полученным официальным `.jar.sha1`.
- Источник: `https://dl.google.com/dl/android/maven2/androidx/annotation/annotation/1.1.0/`.
- POM, `.sha1` JAR и sources JAR получены по HTTPS с официального хоста, без перенаправления. Квитанции и SHA-256 сохранены в `FETCH-RECEIPTS.json`. SDK JAR прочитан без изменения.
- SHA-256 sources JAR: `92bcd2773b5624fd88b7ee21d5685145d7cafed59316c4ce83de33a7b2dd8c02`; SHA-1 совпадает с официальным `.sha1`. Сам sources JAR в доказательства не копируется; сохранён точный `Nullable.java` как ссылка на исходную лицензионную шапку.
- POM объявляет Apache-2.0; точная шапка Nullable: Copyright (C) 2013 The Android Open Source Project. Подготовлен отдельный полный `ANDROIDX-ANNOTATION-NOTICE.txt` для включения в APK. Общий ранее подготовленный Tor notice не менялся.

Фактически выполнен HTTPS POST `https://api.osv.dev/v1/querybatch` с этой одной Maven-координатой и версией. Ответ HTTP 200: `{"results":[{}]}`. Сырой запрос, ответ и хеши сохранены. Статус: **NO_INDEXED_HITS_FOR_SUBMITTED_IDENTIFIER**. Это отсутствие совпадений в данном индексе, а не доказательство отсутствия CVE, ошибок памяти или полноты покрытия.

SHA-1 проверяется только как опубликованная контрольная сумма того же официального HTTPS-источника. Она не является независимой цифровой подписью. Android-сборка дополнительно закрепляет SHA-256 JAR.

Нативная Android/ART/Binder/JNI/FGS-приёмка и независимое воспроизведение исходников в byte-identical официальный JAR в этом дополнении **NOT_RUN**.
