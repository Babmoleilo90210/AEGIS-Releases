# Отчёт о финальных испытаниях 5.0.0

`report-release500.py` не запускает тесты, не подписывает файлы, не меняет production и не выставляет готовность Stable. Он читает фактические XML штатного Gradle и формирует проверяемую матрицу с консервативными ограничениями.

## До фиксации исходников

```sh
python3 tools/report-release500.py inventory --repo . --output docs/test-results/5.0.0
```

Этот режим записывает `sourceCommit=null`, не связывает существующие XML с будущим commit и не создаёт окончательные release gates. Исторические `RESULTS.json` общего evidence-каталога перечисляются отдельно с SHA, не суммируются повторно и не считаются выполнением нативных сценариев.

## После фиксации исходников

Все исходники, тесты, map и committed evidence должны быть зафиксированы. Каталог candidate и receipt располагаются **вне** Git. Следующие команды — шаблон для оператора; вместо примера укажите точную реальную Gradle-команду своего проверенного build environment:

```sh
python3 tools/report-release500.py capture --repo . \
  --receipt /candidate/TESTED-SOURCE-RECEIPT-5.0.0.json \
  --command './gradlew test --rerun-tasks --offline'

./gradlew test --rerun-tasks --offline

python3 tools/report-release500.py generate --repo . \
  --receipt /candidate/TESTED-SOURCE-RECEIPT-5.0.0.json \
  --source-commit FROZEN_40_HEX_COMMIT \
  --output /candidate
```

Не передавайте секреты в `--command`: строка воспроизведения попадёт в публичный отчёт. Приватный release-signing key инструменту не нужен.

Capture требует чистый Git tree и записывает SHA-256 каждого tracked файла, дополнительно сверяя реальное содержимое с Git blob даже при `assume-unchanged`. Generate требует тот же commit/tree/файлы до и после тестирования. Каждый XML шести модулей с JUnit тестами должен получить новую временную метку и содержимое после capture. Старые, неполные, противоречивые XML или изменения исходников/receipt/результатов приводят к отказу. `client-ui` без JUnit явно обозначается отдельно; отсутствующие тесты не превращаются в PASS.

## Выходные файлы

- `TEST-REPORT-5.0.0.md`.
- `RELEASE-GATES-5.0.0.json`.
- `FINAL-VERIFICATION-5.0.0.json`.
- `JUNIT-INVENTORY-5.0.0.json` с per-module counters, точными test cases и SHA исходных XML.
- `requirements-matrix.json`: 224 сценария (20 migration, 20 access, 30 AI, 30 library, 24 organization, 60 native, 15 physical, 25 updater).
- Точная копия `TESTED-SOURCE-RECEIPT-5.0.0.json`.
- `AEGIS-5.0.0-final-test-evidence.zip` со всеми перечисленными отчётами, очищенными XML и отдельным `SHA256SUMS`.

Копии XML сохраняют test names/outcomes/counters, удаляют stdout/stderr/properties/hostname и тексты ошибок. Original XML SHA находится в inventory; SHA очищенного XML находится в ZIP `SHA256SUMS`. Отчёты и ZIP связаны с `sourceCommit`, `sourceTree`, SHA точного receipt и digest карты исходников.

Сопоставления из `release500-matrix.json` требуют точного module/class/testcase. Неоднозначные параметризованные display names не используются для PASS. Частичные тесты показываются отдельно и не закрывают требование. PASS всегда ограничен явно названной локальной областью. Windows 11, CachyOS Wayland/X11, реальный Tor, два физических устройства, полноценный updater/rollback и приёмка владельцем этим инструментом не выполняются. Старое подтверждение проверки 2.5.0 не переносится на 5.0.0. `productionReady` остаётся `false`; параметра для ручного обхода нет.
