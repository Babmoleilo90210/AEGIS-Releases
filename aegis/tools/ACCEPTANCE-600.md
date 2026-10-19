# Выпускные свидетельства АЕГИС 6.0.0

`evaluate-release-gates600.py` проверяет согласованность свидетельств для единого фиксированного исходного commit/tree и точных байтов артефактов. Он **не выполняет** Windows/Android/Tor испытания, не удостоверяет чужой журнал, не подписывает артефакты и не разрешает публикацию. Полный набор обязательных gates задан в коде; удалить неудачный gate из JSON нельзя. `PASS` допустим только после реально выполненной соответствующей проверки.

Корневой `RELEASE-GATES-6.0.0.json` в исходниках содержит восстановительный статус. После фиксации окончательных исходников сформировать его выпускной экземпляр **вне Git checkout**, чтобы отчёт не менял tested source. Записать точные `sourceCommit` и `sourceTree` (`git rev-parse HEAD` и `git rev-parse HEAD^{tree}`), проверить отсутствие незакоммиченных изменений. Исторический snapshot HEAD с незакоммиченными файлами не подходит.

В `artifacts` перечислить десять обязательных ролей с относительными путями и SHA-256 фактически существующих файлов: сервер Debian, Windows installer/portable, CachyOS AppImage, полные и клиентские исходники, четыре APK. Пути разрешаются только внутри явно заданного `--evidence-root`; traversal, symlink, отсутствующие, пустые или изменённые файлы отклоняются. Release inventory и manifest проверяются отдельно штатными `generate-ecosystem-manifest600.py` / `verify-ecosystem-manifest600.py`.

У каждого gate есть `id`, `status`, непустое `reason` и `evidence` — список объектов `{"path":"…","sha256":"…"}`. Для BLOCKED/NOT_RUN/SKIPPED хранить запись среды/блокера, а не фиктивный PASS-лог. Для PASS дополнительно указать `receipt` — путь к одному из хешированных JSON-свидетельств. Его схема:

```json
{
  "schemaVersion": 1,
  "version": "6.0.0",
  "sourceCommit": "ТОЧНЫЙ_40_HEX_COMMIT",
  "sourceTree": "ТОЧНЫЙ_40_HEX_TREE",
  "gateIds": ["NATIVE-WINDOWS11"],
  "status": "PASS",
  "artifactSha256": {"AEGIS-Setup-6.0.0-x64.exe": "ТОЧНЫЙ_SHA256"},
  "execution": {
    "kind": "native",
    "platform": "windows11-x64",
    "startedAt": "ВРЕМЯ_НАЧАЛА_С_ЧАСОВЫМ_ПОЯСОМ",
    "endedAt": "ВРЕМЯ_ОКОНЧАНИЯ_С_ЧАСОВЫМ_ПОЯСОМ",
    "description": "Фактически выполненные шаги и среда"
  },
  "results": [{"path": "evidence/native-windows11.log", "sha256": "ТОЧНЫЙ_SHA256_ЖУРНАЛА"}]
}
```

Это описание формата с явными незаполненными обозначениями, **не готовое свидетельство**. Его нельзя копировать как результат испытания. Разрешённый `execution.kind` зависит от gate: build, automated, integration, native, public-network, physical-network, security-review, owner-acceptance. Headless-тест не удовлетворяет native gate. Для физического межсетевого прогона дополнительно записать два разных `physicalDevices` и два разных `independentNetworks` (условные метки без IP/секретов); два процесса на одном устройстве не подходят. Security receipt требует `openCritical:0` и `openHigh:0` после фактического полного review. Финальное owner-acceptance имеет `execution.acceptedBy:"owner"` и относится к точным проверенным файлам; оно не требует передачи приватного ключа в Work.

Запуск:

```bash
python3 tools/evaluate-release-gates600.py /absolute/candidate/RELEASE-GATES-6.0.0.json \
  --evidence-root /absolute/candidate \
  --expected-source-commit "$COMMIT600" --expected-source-tree "$TREE600"
```

Сначала задать `COMMIT600`/`TREE600` реальными значениями зафиксированного проекта. Проверка возвращает 0 только при всех PASS и полном inventory; 2 — согласованную неготовность; 1 — ошибку схемы, источника, хеша или необоснованное записанное `productionReady`. Она не меняет входные файлы. `productionReady=true` — результат полного набора свидетельств, а не переключатель по длительности работы. `publicationAuthorized` всегда false: публикация требует отдельного распоряжения владельца.

Старый CLI `evaluate-release-gates.py` автоматически направляет документы версии 6.0.0 в строгую проверку. Его прежний программный `evaluate(document)` отказывает 6.0.0, чтобы нельзя было обойти source/evidence binding старой упрощённой функцией. Правила старых версий сохраняются.
