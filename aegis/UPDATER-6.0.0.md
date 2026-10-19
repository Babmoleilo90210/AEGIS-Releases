# Updater и приёмка 6.0.0

Сохранены Ed25519, SHA-256, anti-rollback, точные размеры файлов, закреплённый ключ, строгие версии, GitHub tags/URL и Tor-only HTTPS production transport. Четыре привычных поля артефактов legacy manifest не расширены несовместимым набором. Все четыре платформенные поставки экосистемы описывает отдельный inventory; он не является реализацией runtime updater сервера/Android.

## Исправления

Проверка с автоматическим скачиванием теперь сохраняет уже проверенный manifest при обрыве загрузки. Ранее файл `.part` оставался на диске, но состояние `FAILED` теряло manifest и кнопка продолжения не могла возобновить загрузку. Непроверенные подписи и отклонённые policy manifest по-прежнему не попадают в доступное для установки состояние.

Detached helper копируется за пределы установленного комплекта. Подготовка через символическую ссылку или внутри старого bundle отклоняется. Helper не получает shared running lease. После завершения старого клиента он получает эксклюзивный `RuntimeLease600`, затем legacy `AppPaths.lock`, создаёт и проверяет snapshot, копирует и атомарно переключает бинарники. Оба lock освобождаются до запуска нового Core; Core обязан получить собственный shared runtime lease.

При отсутствии startup acknowledgement updater завершает только запущенный им процесс и его потомков. Затем повторно получает эксклюзивный runtime lease и legacy lock перед заменой бинарников и восстановлением профиля. Если независимый менеджер успел запуститься, откат блокируется, старый и новый комплекты сохраняются, записывается `recovery-blocked`. Внешний catch больше не удаляет текущую установку и не восстанавливает `.old` вне guard. Старые `.old`/`.new` другой незавершённой транзакции не перезаписываются и не удаляются.

Snapshot включает разрешённые постоянные Core6 файлы (`device.vault`, navigation, public service pins/config, Tor mode и небольшой `obsidian-control/linux-distribution.json`), зашифрованное состояние `glas600`, migration receipt/MAC и путь уже созданной зашифрованной migration backup из receipt. Само Mail хранилище копируется по текущему `config.storagePath`, без повторного включения всего дерева `mail600`. Не включаются browser/Library cache, проекции, cookies, runtime guard, IPC/socket/tmp, `.lock`, временные atomic файлы и рекурсивные папки резервных копий. Восстановление старого snapshot без Core6 ownership metadata не удаляет позднее созданные Core6 credentials.

Копирование ciphertext не переносит автоматически связанные с устройством ключи из DPAPI/Secret Service. Смена компьютера/профиля ОС и восстановление системного хранилища секретов требуют отдельной поддерживаемой процедуры. Невозможно объявить такую переносимость только по успешной проверке файлов snapshot.

## Воспроизводимые проверки

```sh
python3 tools/test-updater600-local.py --jdk /path/to/jdk-21 \
  --deps /path/to/maven-deps --deps /path/to/test-deps \
  --out /outside/checkout/updater-results
python3 -m unittest discover -s tools -p 'test*release_manifest*.py' -v
```

Java проверяет реальные JCA Ed25519 подписи тестового ключа в памяти, production signature-first/schema/hash/anti-rollback policy, настоящую локальную HTTP загрузку с обрывом и Range resume, изменение байтов, startup acknowledgement и файловый откат. Замороженные неизменённые парсеры 1.5.0, 2.0.0 и опубликованной 5.0.0 компилируются и проверяют manifest 6.0.0; SHA-256 исходников замороженных парсеров проверяется по provenance.

Runtime guard испытания запускают отдельные JVM: действующий компонент блокирует замену; эксклюзивная блокировка сохраняется во время backup; новый Core получает shared lease после переключения; точный новый процесс завершается до отката; независимый менеджер блокирует восстановление; pre6 legacy lock предотвращает установку; чужой `.new` сохраняется. Это настоящие файловые блокировки и copy/rename в тестовом каталоге, но не Windows/CachyOS native acceptance.

Python проверяет настоящий временный Git repo/tree и реальные измеренные fixture bytes, строгие роли/имена/commit/provenance, source ZIP blobs, отказ при изменении артефакта, отсутствие ключей, неизменность feed и атомарный новый output directory. Metadata fixtures не выдаются за installer/APK. Отдельный тест public APK verifier использует официальный SDK и настоящий тестовый APK, а также повреждает APK; parser fixtures отмечены отдельно.

Локальный HTTP transport существует только в тесте. Production не получает параметра произвольного HTTP endpoint или нового доверенного ключа. Тестовая подпись не принимается закреплённым production ключом.

## Границы результатов

Локальные тесты не доказывают нативную установку Windows 11, CachyOS KDE Wayland/X11, работу updater через реальный Tor, миграцию на физических устройствах, Android owner signing/update, Debian deployment, перезапуск packaged Core и аварийный rollback готового установщика. Эти проверки фиксируются отдельно как NOT_RUN/BLOCKED до фактического выполнения. Состояние `productionReady` по результатам только этих проверок остаётся `false`.

Фактический локальный прогон: 55/55 Java, 0 пропусков, исходники стабильны в ходе прогона; 40/40 Python release metadata; 11/11 public APK verifier, включая официальный SDK и повреждение настоящего TEST APK. Подробности и SHA-256 журналов — `docs/test-results/6.0.0/updater/SUMMARY.json`. Исправления других модулей после этого прогона требуют финального общего повторения.

После исходного прогона исправлено создание пустых отсутствующих migration targets при restore: оно ошибочно блокировало последующую миграцию Mail. Повторный прогон — 56/56 Java, 0 пропусков, sourceStable=true; доказательства в `docs/test-results/6.0.0/updater/restore-fix`.

Добавлены постоянные Core notification preferences в exact allowlist (`core600/notification-preferences.json`). Повторный прогон 56/56, 0 skip, sourceStable=true — `docs/test-results/6.0.0/updater/notification-prefs`.
