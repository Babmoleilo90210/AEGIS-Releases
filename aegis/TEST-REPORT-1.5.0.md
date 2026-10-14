# Испытания АЕГИС 1.5.0

**productionReady=false.** Это релизный кандидат для приёмки. Windows 11, CachyOS KDE Wayland/X11, два физических устройства и полный переход через updater с подписью владельца ещё не проверены.

Бинарники: commit `f9ac41ab9a7aca659e23df88f020a84618af77a1`, CI run `38532085562`. Последующие изменения касаются документации, доказательств, проверенных Gradle locks и тестового комплекта. Код приложения в итоговом исходном ZIP совпадает с кодом этой сборки. Хеши — в `SHA256SUMS`, параметры упаковки — в `ARTIFACT-VERIFICATION.json` и `BUILD-PROVENANCE.json`.

## Выполненные проверки

| Проверка | Результат | Доказательство и границы |
|---|---|---|
| Полный JUnit, Java 21 | **165 PASS, 1 SKIP, 0 FAIL** | 166 обнаруженных тестов: common 4, client-core 146, relay 3, integration 13. SKIP — Windows DPAPI в Linux. XML: `evidence/junit/`. |
| Release/security Python | **16 PASS** | `evidence/release-security-tests.log`: неправильные подписи, схема, размер, хеш, traversal и rollback. |
| JavaFX smoke | **6 PASS** | Настоящие сцены Monocle: единое окно, почта, архив, 22 оформления, навигация, логический масштаб, черновики и настройки. Это не нативная приёмка KDE/Windows 11. |
| Архив, Windows Server 2025 | **22 PASS, 0 FAIL** | Run `38534308414`, точные итоговые JAR/runtime. `evidence/platform/final-AEGIS-1.5.0-archive-windows-2025-evidence/`. |
| Архив, Ubuntu 24.04 | **22 PASS, 0 FAIL** | Тот же run и итоговые JAR/runtime. `evidence/platform/final-AEGIS-1.5.0-archive-ubuntu-24.04-evidence/`. |
| Windows package | **8 PASS** | Native crypto/DPAPI/JavaFX, Setup install, EXE без глобальной Java, loopback Tor, завершение собственного Tor, чужой Tor остаётся. `evidence/platform/final-AEGIS-1.5.0-Windows-Server-evidence/RESULTS.json`. Windows Server не заменяет Windows 11. |
| Direct Tor и Snowflake | **PASS на Windows Server и Ubuntu** | Настоящий bootstrap 100%, TLS с truststore пакета, production Ed25519, корректная обработка старого feed, GitHub download, progress, Range resume и SHA-256. Production feed только читался. |
| Совместимость старой почты | **4 комбинации PASS** | Клиенты 1.2.0/1.5.0 с Relay 0.2.0/0.3.0; staging SQLite 0.2 → 0.3 → 0.2. `evidence/compatibility-matrix.json`. Synthetic SOCKS, не native Tor; production Relay не менялся. |
| Реальные onion services, P2P | **PASS** | Run `38534308413`, frozen commit `f9ac41a`. Два client-core экземпляра, один Tor-процесс и один Linux-хост. При остановленном Relay проверены direct protected letter/FF1, вложение, signed ACK/read, dedup, offline Relay и реальное истечение 60 секунд. `evidence/platform/final-AEGIS-1.5.0-real-onion-staging-evidence/`. |
| Verifier 1.2.0, точные пакеты 1.5.0 | **PASS с тестовым ключом** | Проверены схема, размер, SHA и пакет. Production pinned key отвергает тестовую подпись. Это не установка кандидата, подписанного владельцем. |
| Структура артефактов | **PASS** | Windows AMD64 GUI/asInvoker/ASLR/NX, иконка 7 размеров, ZIP CRC, AppImage ELF/SquashFS, полный payload SHA, одинаковые application JAR на Windows/Linux, нет Relay JAR в клиенте, pinned public key сохранён. |

## Архивная группа

Тесты используют настоящую файловую систему и AEAD, а не mock encryption. Проверены создание и неверный пароль, recovery/rotation/disable, смена пароля без изменения объектов, соль/nonce, подмена wrapper и объектов, зашифрованные имена/теги/индекс, вложенность и циклы папок, rebuild индекса, restore/merge, подменённая копия, дубликаты, quota, отмена, явный экспорт и блокировка. Проверены подготовленная запись после прерывания, известный rollback и полный снимок профиля с управляемыми архивами.

PDF/image/UTF-8 тесты действительно декодируют документы. Регрессионная проверка ImageIO использует filesystem watcher при включённом стандартном cache: просмотр не оставляет plaintext cache. PDF helper не сканирует системные шрифты и не создаёт их дисковый cache; применяет лицензированный встроенный fallback PDFBox. Документный plaintext не записывается в staging.

`AUTO-NATIVE-MATRIX-1.5.0.json` и `NATIVE-RESULTS-1.5.0.csv` содержат отдельные статусы для 40 ARC, 30 UI и 10 P2P сценариев. Автоматический PASS не переносится в колонку нативной платформы. Ручные действия, которые smoke не проверял, остаются NOT_RUN.

## Ошибки во время испытаний

Первый Linux job окончательной сборки завершился `FAIL_OR_UNAVAILABLE` при обращении к свежесозданному onion Relay. Исходный результат и журнал сохранены в `final-AEGIS-1.5.0-Linux-Tor-evidence`. Отдельный повторный тест **тех же бинарников** после ограниченного ожидания публикации descriptor прошёл; runtime-код ради прохождения проверки не менялся.

Более ранний staging fixture требовал повторного входа после restart Relay: его сеансы существуют в памяти. Исправлен тестовый сценарий. Старые журналы находятся в исторических доказательствах и не выдаются за результаты финальных файлов.

Во время отдельных изменений размера Monocle выдавал предупреждение `Too small int buffer size`. Проверки сцены прошли; это не доказательство отсутствия проблемы на родном compositor. Нужна визуальная приёмка Windows 11, Wayland и X11.

## Измерения

Один CI sample, файл 32 MiB, итоговый commit: создание 509 мс, импорт 620 мс, текстовый импорт и поиск 17 мс, backup 542 мс, restore с полной проверкой 3197 мс. CPU 6010 мс, heap после GC 8 851 440 байт. `evidence/archive-performance.json`. Первоначальный backup занимал 39 147 мс из-за посимвольной записи FilterOutputStream; bulk write устранил причину. Один sample и разные workers не являются статистической гарантией.

Сопоставимая JavaFX нагрузка 1280×900, 30 переключений: baseline 1.2.0 — median 17 мс / P95 58 мс / heap 30,56 МБ; 1.5.0 — median 16 мс / P95 68 мс / heap 30,78 МБ. Медиана сопоставима, хвост чуть хуже. Нативная отзывчивость ещё требует проверки. В локальном sandbox CPU duration недоступен и обозначен `-1`, вместо выдуманного значения. Архив создаётся лениво; обычная почта не загружает его документы и индекс.

## NOT_RUN и ограничения

- Windows 11 x64, CachyOS KDE Wayland и X11; системный DPI, reboot, Explorer/Dolphin и другой пользователь ОС на этих платформах.
- Два физических устройства, разные сети и OS; передача между ними и длительная нестабильность Tor.
- Точная подпись владельца и полный updater 1.2.0 → 1.5.0: consent, установка, restart, сохранность профиля, письмо об успехе, отдельный rollback. Read-only production feed и ephemeral-key fixture не заменяют этот тест.
- Физическое отключение питания; prepared commit проверялся программно.

Автоматические копии работают только при запущенном приложении и разблокированном архиве. Смена пароля не отзывает уже извлечённый DEK. На новом устройстве без anchor нельзя доказать свежесть контейнера. Стирание Java/JavaFX/native памяти — best effort. PDF worker ограничен ресурсами, но не является OS sandbox; не встроенные шрифты могут заменяться. Preview имеет документированные пределы. Явный экспорт создаёт plaintext; авария может оставить приватный partial. Отмена merge сохраняет уже импортированные объекты. Исторические письма 0.1 переносятся через явный экспорт/импорт. Черновики остаются RAM-only; установка требует сначала завершить или очистить их.

В доказательствах нет production профилей, private keys или паролей пользователя. Копии production manifest/signature относятся только к read-only проверке прежней версии и не являются подписью 1.5.0. Stable не опубликован, production Relay/feed/ключи не изменены. Независимый security audit не проводился.
