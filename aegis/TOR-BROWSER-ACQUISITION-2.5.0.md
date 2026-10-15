# Взор 2.5.0: подготовка официального Tor Browser

Реализована автоматическая загрузка стабильного Tor Browser x86_64 для Linux и Windows portable. Приложение получает актуальные per-platform JSON с `aus1.torproject.org`, затем архив и соответствующую `.asc` с `dist.torproject.org`. Все три запроса используют существующий HTTPS SOCKS-контекст Tor АЕГИС (`torUpdateSocksPort`). При отключённом Tor возвращается `WAITING_FOR_TOR`; прямого fallback нет. DNS назначения передаётся доменным именем внутри SOCKS5.

Источники и правила проверены по первичным материалам Tor Project:

- [Linux stable discovery JSON](https://aus1.torproject.org/torbrowser/update_3/release/download-linux-x86_64.json).
- [Windows x86_64 stable discovery JSON](https://aus1.torproject.org/torbrowser/update_3/release/download-windows-x86_64.json).
- [Проверка подписи Tor Browser](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/).
- [Штатная установка Tor Browser](https://support.torproject.org/tor-browser/getting-started/installing/).
- [Переносимая установка и возможность штатных обновлений](https://support.torproject.org/tor-browser/getting-started/making-tor-browser-portable/).
- [Генерация tbb_version.json: исходный build recipe Tor Project](https://lists.torproject.org/mailman3/hyperkitty/list/tbb-commits%40lists.torproject.org/thread/JVF25644IS5CWBPOJ4TCDN5IPWEBGSQW/?sort=date).
- [Официальная стандартизация имён платформ](https://archive.torproject.org/websites/lists.torproject.org/pipermail/tbb-commits/2023-August/018265.html).

JSON является указателем на кандидат, а не доказательством подлинности. Парсер ограничивает размер, UTF-8, поля, повторы ключей, стабильную числовую версию, build tag, архитектуру, точное имя архива и `.asc`. HTTPS проверяет hostname и TLS. До четырёх redirect допускаются только с сохранением официального host и точного пути. HTTP запрещает неоднозначное framing, декомпрессию HTTP, HTML вместо файла и превышение лимитов. Cookie, аккаунтные данные, пароли, ключи и содержимое писем не передаются.

Файлы записываются в отдельный приватный каталог под случайным именем. `.part` создаётся эксклюзивно, синхронизируется и атомарно переименовывается. Отмена закрывает только собственный активный сокет, затем удаляет собственные временные файлы. Подпись проверяется существующим OpenPGP verifier с фиксированным primary fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`.

Версия самого Tor Browser берётся из подписанного `Browser/tbb_version.json`. `Version` в `application.ini` относится к движку Firefox и не используется как версия Tor Browser. На Linux подписанный TAR проверяется без исполнения перед состоянием READY. На Windows внутренние данные проверяются после извлечения уже удостоверенным штатным portable EXE и до публикации bundle. Метаданные, подменённое имя файла и переименованный старый подписанный архив не могут удостоверить новую версию.

Офлайн-импорт и автоматическая загрузка используют один `TorBrowserInstaller`. Он сохраняет исходный проверенный bundle отдельно от сессий, проверяет реальную ELF/PE архитектуру Firefox и Tor. Вне sandbox сохраняются версия, платформа, SHA-256 исходного пакета и fingerprint разработчика. Монотонная отметка версии не позволяет обычным импортом вернуться к более старому браузеру. Проверенный текущий template также участвует в восстановлении отметки после сбоя. Новый selected-template публикуется атомарно после всех потенциально ошибочных записей; поздняя отмена уже завершённую установку не удаляет. Аккаунты, письма, архив АЕГИС и чужие браузерные профили не копируются.

Перед запуском authenticatedPreflight проверяет template и обычную сессию. Только новый удостоверенный импорт может восстановить изменённые файлы того же archive hash; repair использует staging, rollback и восстановление backup после сбоя, сохраняя собственные Browser Data и загрузки. Три штатных Mozilla mutex leaf в profile.default не переносятся после подтверждённой остановки; другие небезопасные ссылки останавливают перенос.

Импорт поддерживает отмену снимка входных файлов, распаковки и копирования. В Windows проверенный NSIS EXE создаётся `CREATE_SUSPENDED`, включается в отдельный не наследуемый Job Object с `KILL_ON_JOB_CLOSE` и запускается только после успешного включения. Используются штатные `/S /D=...`; shell не применяется. Отмена/timeout завершает только эту группу с проверкой её состояния. При завершении JVM закрытие Job завершает её процессы. Это управление временем жизни installer, а не sandbox браузера. Реальное выполнение этого пути на Windows в данной среде **NOT_RUN**.

Штатный updater Tor Browser не заменён: он работает в writable копии bundle сессии. Если обновление изменило executable-файлы, следующий запуск требует вновь удостоверенного официального пакета с соответствующей версией; локальное самоподписание изменённых файлов запрещено. Совместимость конкретного обновления с запуском на Windows 11/CachyOS требует нативной приёмки.

`TorBrowserDiscovery` выполняет только ограниченный поиск известных каталогов, включая Downloads/Desktop, `~/.local/share/tor-browser`, `$XDG_DATA_HOME/tor-browser` и стандартный каталог torbrowser-launcher. Можно проверить вручную выбранный каталог. Читаются ограниченные `application.ini`, `tbb_version.json` и ELF/PE headers; профиль, cookies, пароли и закладки не читаются, не копируются и не используются. Обнаружение не удостоверяет существующие executable-файлы и не включает их в доверенные template. Нужен официальный подписанный пакет.

## Фактически выполненные проверки

69/69 теста прошли в JDK 21.0.12.1+1 / JUnit Platform 1.13.4. XML и текстовые отчёты сохранены в `docs/test-results/2.5.0-tor-browser/`. Включены регрессии OpenPGP, bounded TAR/XZ, сессий и новые проверки HTTP, отмены, antirollback, версии и обнаружения. Fixture integration использует настоящий disposable RSA3072/OpenPGP, XZ/TAR и production HTTP parser. Два теста выполняют настоящие loopback SOCKS-сокеты: hostname/port handshake и отмену во время заблокированного handshake. Эти тесты не являются запуском Tor Browser или сетевой приёмкой Tor.

Официальный web retrieval 15 октября 2026 показывает stable 15.0.25, `tbb-15.0.25-build2` для обеих платформ. Его schema-fixtures сохранены с явным provenance. Нативные запросы JSON из среды разработки получили 195-байтную HTML-страницу SiteUnavailable; исходные ответы и SHA-256 сохранены в отчётах. Официальный архив в этой среде не получен, поэтому проверка его реальной подписи, запуск браузера, onion/HTTPS, сетевые утечки и Windows Job/NSIS **NOT_RUN**. `productionReady=false` до обязательной нативной и сетевой приёмки.

## API

`new TorBrowserDownloadService(config, torReady).downloadLatest(privateRoot, listener, cancellation)` возвращает `VerifiedPackage` с `archive()`, `signature()`, `release()`, `verification()`. Его нужно закрыть после `safeWeb.install(archive, signature, cancellation::cancelled)`. `Cancellation.cancel()` закрывает собственный сокет. Каталог загрузки должен находиться вне браузерных сессий. Автоматическая установка не запускает браузер сама.
