# Проверка генератора отчётов 5.0.0

13 реальных Python unittest policy tests на временных Git/XML fixtures. Точные исходные SHA и фактический журнал рядом. Не является проверкой АЕГИС на native платформах, Tor, двух физических устройствах или updater E2E.

Воспроизведение: `python -m unittest discover -s tools -p test_report_release500.py -v`. Usage и модель receipt описаны в `tools/REPORT-RELEASE500.md`. Этот source cut не переносит текущие XML на будущий commit; финальные отчёты создаются только после capture/final Gradle/generate.
