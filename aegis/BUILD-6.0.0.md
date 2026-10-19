# Воспроизводимая подготовка АЕГИС 6.0.0

Используются существующие Gradle Java/JavaFX-модули. Нужны проверенные JDK21, Gradle9.8.0, закреплённые Maven/native входы; Android — официальный SDK36/build-tools36.1/NDKr29, minSdk33, ARM64. Версии/хеши фактически использованных инструментов записываются в provenance.

## Источник

Репозиторий восстановлен из настоящего опубликованного5 commit и проверенной резервной копии6. Точное происхождение — RECOVERY-PROVENANCE-6.0.0.json. Старые локальные commit objects не выдумывались. Для работы владельца с неопубликованной веткой предоставляется Git bundle, не содержащий `.git/config` или build credentials.

```sh
git clone --branch development/aegis-6.0.0 AEGIS-6.0.0-source.bundle aegis6-source
cd aegis6-source
git checkout --detach FULL_SOURCE_COMMIT
cd aegis
```

## Полный прогон

Перед сборкой требуется чистый HEAD. Настройте JAVA_HOME, проверенные зависимости и нативные тестовые библиотеки. Предварительная сборка с изменяющимися источниками/lockfiles является только диагностической.

```sh
./gradlew --no-daemon --no-build-cache --no-configuration-cache --rerun-tasks   -I packaging/verification600.gradle   -Plegacy500Bundle=/verified/published5/app   clean test assemble :client-ui:stageApp
```

Не добавляйте `--write-locks`, `--tests`, `-x` или `--dry-run` в финальный прогон. Init отключает incremental JavaCompile и требует реальный опубликованный5 JAR для compatibility/rollback теста. Проверяются хеши исходников до/после, commit/tree/dirty, JAR CRC/SHA и XML. Перечень test source files не является числом пройденных тестов.

Windows stage делается отдельно с `-PtargetPlatform=win :client-ui:stageApp`; он не подменяет полный test receipt. `packaging/package-clients600.py` требует exact clean fullbuild proof, официальные проверенные5 runtime bases и native tool registry. PE/ELF файлы собираются реально, но cross-compilation не является целевой нативной приёмкой.

Серверный пакет создаёт `deployment/debian600/deploy.py` из восьми текущих JAR с их CRC/SHA и закреплённых runtime dependencies. Android собирается `android/build.py --expected-commit FULL_SOURCE_COMMIT` с проверенными SDK/native входами; четыре unsigned и четыре TEST APK имеют отдельный provenance. Production APK signing key не используется.

`tools/prepare-sources600.py` экспортирует реальные Git blobs и режимы. `tools/generate-ecosystem-manifest600.py` связывает десять обязательных ролей с exact hashes/provenance и создаёт только UNSIGNED документы. Старый manifest сохраняет strict version/tag/URL и прежнюю схему. Ecosystem inventory не означает, что появился runtime updater Android/серверов.

После сборки все результаты хранятся вне checkout. Изменение любого бинарника требует новых SHA/provenance/manifest. Подпись, нативная приёмка и публикация остаются отдельными действиями владельца.
