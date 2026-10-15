# Финальные проверки общего UI 2.5.0

`productionReady=false`. Четыре самостоятельных JavaFX smoke прогона завершены чисто, без production source/class overrides. Runtime UI загружен из общего JAR `686eb69a381f0fabbc46aab8df53a195904293724ee2b72c6119ed317ba0f7fe`. Точные SHA всех shared JAR и исходников находятся в `source-inputs.json`; фактические CodeSource URL одиннадцати ключевых production-классов — в `production-code-origins.json`.

- `Interface250RefinementSmoke`: PASS_HEADLESS — галерея 16 пресетов, избранное/поиск/Apply, архив с русскими типами,11 встроенных форм, popup,100–200%, light/dark, очистка секретов, безопасные RU ошибки, stored System.
- `SettingsResponsive200Smoke`: PASS_HEADLESS — 5 групп на общей панели, content ниже, реальные 800×600 на 100/125/150/200% и 2 темах, offline signedavatar refresh/removal.
- `SingleWindowSmoke`: PASS_HEADLESS — навигация, вложенные страницы, пароль, filepicker cancel, сохранённый черновик, закрытие родителя, один Stage.
- `InWindowDialogs200Smoke`: PASS_HEADLESS — 24 переносимые строки, реальная прокрутка к кнопкам, геометрия и ancestor clipping, русские ОК/Отмена, восстановление черновика и nested cleanup на 800×600, 100–200%, в двух темах.

Первоначальный подтверждённый width-bug и диагностические снимки сохранены в `../attempt-width-bug/`. При 150% кнопки находились на y1158–1215 за пределами Scene высотой 600 px. Исправлено в общем `InWindowDialog`: `DialogPane.getContentBias()` возвращает HORIZONTAL, поэтому высота зависит от фактической ширины переносимых строк. В этом финальном прогоне 150% и 200% проходят прежние строгие assertions; условия не ослаблялись.

100 PNG — настоящие снимки JavaFX Monocle с синтетическими локальными данными. Эти данные не подтверждают Windows 11/CachyOS native acceptance, Tor/browser/audio/liveRelay; соответствующие результаты остаются NOT_RUN. Старая отдельная ошибка Monocle resize из Interface200Smoke сохранена как PARTIAL_BACKEND_ERROR в `2.5.0-ui-followup`, а не переименована в чистый PASS.
