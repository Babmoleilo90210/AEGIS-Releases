# Офлайн-подпись четырёх APK владельцем

Текущий пакет неполный: `productionReady=false`, `versionName=6.0.0-test`. Подпись не заменяет прохождение release gates и не делает пакет Stable. Не публикуйте его как готовый релиз.

Используйте отдельный Android APK signing key. Никогда не загружайте его или пароль в Work, GitHub, CI или VPS. Старый Ed25519 manifest key не используется для APK. Все четыре собственных APK должны иметь один Android signing certificate. Сторонние APK Tor Browser/Obsidian не переподписываются.

1. На доверенном офлайн-компьютере проверьте SHA256SUMS unsigned APK и соответствие зафиксированному commit/build provenance. SDK build-tools должны быть официальными и проверенными.
2. Если Android key ещё не создан, создайте его локально. Команда запрашивает секреты интерактивно; не сохраняйте пароль в аргументах, истории или скрипте:

```bash
keytool -genkeypair -keystore AEGIS-ANDROID-OWNER.p12 -storetype PKCS12 \
  -alias aegis-android-owner -keyalg RSA -keysize 4096 -validity 10000
```

3. Подпишите каждое из четырёх уже выровненных unsigned APK. Повторите команду для `Core`, `Mail`, `Glas`, `Strazh`:

```bash
apksigner sign --ks /offline/AEGIS-ANDROID-OWNER.p12 \
  --ks-key-alias aegis-android-owner --v1-signing-enabled false \
  --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
  --out AEGIS-Core-6.0.0-owner-candidate.apk AEGIS-Core-6.0.0-unsigned.apk
apksigner verify --min-sdk-version 33 --verbose --print-certs -Werr \
  AEGIS-Core-6.0.0-owner-candidate.apk
zipalign -c -P 16 4 AEGIS-Core-6.0.0-owner-candidate.apk
```

4. Проверьте совпадение SHA-256 сертификата всех четырёх APK и сохраните отчёты. После подписи пересчитайте SHA-256 итоговых APK и сформируйте новый manifest точных размеров/версий/хешей. Первую установку Core и отпечаток сертификата проверяйте независимым доверенным способом. Core далее проверяет сертификаты остальных собственных APK.
5. Выполните обязательную нативную приёмку. Для установки тестового и production-сертификатов используйте разные тестовые окружения: Android не разрешит обычное обновление одним сертификатом поверх другого. Не удаляйте единственные пользовательские данные ради обхода этого ограничения.

Смена сертификата требует отдельной проверенной Android signing lineage/ротации, резервной копии и испытаний на Android 13+. Автоматическая ротация, аварийное восстановление Android signing key и updater E2E сейчас не испытаны, поэтому их gates остаются NOT_RUN. После изменения любого APK подпись/хеши/manifest формируются заново. Stable feed и публикация не выполнялись.
