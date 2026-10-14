# АЕГИС 1.5.0 — технический аудит и карта изменений
Дата: 14.10.2026. Продолжение 1.2.0, не новый проект. Независимый security audit не проводился.

## Доказанная база
Бинарный commit 1.2.0: 70f80c27c13321d3ad8f7c8d7fa630862c56c56d. Итоговый docs commit: 8dd290af025921c16c40798f71b7958878524faf. Восстановлен source ZIP SHA256 93c816760d3f688214a3a37e67483e9ec89233e5f671d28bb8f5b49f7f370324. Текущий main/updates/stable.json действительно имеет version=1.2.0 и эти же artifact hashes. Публикация владельцем не доказывает прохождение ранее NOT_RUN нативных тестов.
Полный bundle проверен по b2456bba147cc74654a5b1f8134b898110dd1e4d0471c4bd87497586e8bcf3c7.

## Изученный контекст
Открыта shared страница 6acf0927-a220-83ed-8642-c248b9e0b8b6; извлечены фактические React loader сообщения. Изучены решения владельца четырёх этапов 1.1.5, трёх этапов 1.2.0 и трёх этапов 1.5.0. Последние изображения навигации, длинного меню настроек, растянутой карточки сети и двух TTL контролов получены из связанных image_asset_pointer. Новое утверждённое Work ТЗ имеет приоритет над текстом планировочного чата «не запускай Work».

## Компоненты
| Компонент | Действительная реализация | Изменение |
|---|---|---|
| GUI | client-ui/.../MessengerApp.java, MailViewer.java, InWindowDialog/FileChooser | ArchiveView в едином окне, структурированные настройки, компактный header, archive action после reveal |
| Оформление | Appearance.java/Store, ThemeManager, AppearanceEngine, ScaledRoot | Сопоставить Friends→Contacts, добавить Archive, сохранить presets/layout/theme/scale |
| Vault | storage/LocalStore.java, AtomicFiles.java | Существующий формат не заменять; новый независимый архив рядом с профилем/внутри профильного дерева |
| Пароли | crypto/Secrets.java | BC Argon2id v19 m=64MiB,t=3,p=1; добавить отдельный archive context, существующие account/vault contexts неизменны |
| Криптография | BC1.86, Tink1.23.0, JCA, libsodium | AES-GCM wrapping случайного DEK; существующий Tink StreamingAead для больших файлов |
| Письмо/FF1 | PlainMessage.java, LetterEnvelope.java, MailViewer.java | Архивировать только явно показанный текст, без сохранения исходных секретов; оригинал не меняется |
| Lifecycle | LifecycleService, DeviceCapabilities, ExpiryGuard, BootClock | Таймер оригинала не останавливать; архивная копия после предупреждения |
| P2P | net/NetworkService.java, TorTransport.java, PeerServer.java, TorControl.java | Нынешний DELIVER идёт к подписанному peer onion, не к Relay. Но deliverControl всегда делает FIND на Relay сначала: P2P при выключенном Relay требует клиентского кэша свежего подписанного Route |
| Updater | SignedManifest, UpdateService, UpdateInstaller/UpdaterMain | Сохранить pinned Ed25519/TLS/SHA/antirollback; обновить version/packaging; никаких production feed writes |
| Backup | ProfileSnapshot, ClientUpgrade | Full ciphertext snapshot до version-open; archive independent backup/recovery; guards вне rollback snapshot |
| Build | Gradle, build-local/build-stability, package-clients/verify-client | Версия клиента1.5.0, unchanged protocol/common/Relay; source and exact final artifact hashes |

## Архитектура архива
Отдельный случайный 256-bit DEK и независимый пароль. Argon2id с новой context строкой, случайная соль16; AES-256-GCM wraps DEK с уникальным nonce12 и archive/version/type AAD. Optional recovery32 случайных байт — самостоятельная wrapper, показывается единожды, не логируется/не передаётся. Смена пароля обновляет только wrapper.
Данные файлов — стандартный существующий Tink AES-GCM-HKDF StreamingAead, не самостоятельно составленный chunk cipher. Каталог, виртуальные имена/папки/tags/hash и индекс — encrypted AEAD. Файлы на диске названы случайными UUID. Декодирование ограничено по размерам; произвольных URL или native serialization нет. Private POSIX700/600 либо NTFS owner ACL через AtomicFiles.
External encrypted revision anchor и prepare/commit journal обнаруживают обычный локальный rollback и не откатываются updater snapshot. На новом компьютере без прежнего доверенного anchor невозможно доказать свежесть скопированного контейнера — явно документировать, требовать проверяемый пароль/полную целостность. Не заявлять защиту против hostile OS или удаления всех anchors.
Архив не создаётся/не наполняется автоматически при миграции. Fulltext index только encrypted на диске; повреждённый index перестраивается из authenticated objects, не разрушая их.
PDFBox3.0.8 — новая Apache2 библиотека только локального PDF decode/render/text extraction, без SaaS. Изолированный bounded headless helper, memory input, без document temp files и active content execution. Dependencies/официальная документация проверены 14.10.2026.

## Проверенные ограничения
1.2.0 disappearing timer device-bound, консервативное раннее закрытие после OS reboot/потери guard; сохраняется, не выдаётся за исправление. FF1 deliberately no correctness oracle: показ candidate не доказывает правильность code. Persistent plaintext drafts отсутствуют, остаются RAM-only. Identity backup не равен profile backup.
Local archive plaintext память Java/JavaFX нельзя гарантированно стереть из всех GC/native/render copies. Explicit export/external opening создаёт обычный файл по предупреждению; encryption at rest не защищает открытый процесс от администратора/keylogger.
Previous Linux one Tor staging PASS не является P2P между физическими пользовательскими сетями. Windows11/KDE и full owner-signed updater E2E/rollback сейчас NOT_RUN. ProductionReady=false до mandatory gates.
