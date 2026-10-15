# Модель угроз Взора — АЕГИС 2.5.0

Статус: описание фактической реализации и её границ, а не сертификат безопасности. Автоматические проверки отдельных свойств выполнены; запуск официального Tor Browser и сетевые измерения на Windows 11/CachyOS остаются **NOT_RUN**. `productionReady=false`.

## Активы, противник и доверие

Защищаются identity private keys, ключи и пароли переписки, FF1/letter passwords, recovery keys, расшифрованные данные архива, account storage, независимость почтового соединения, целостность запускаемых browser executable и сохранность Browser Data при обновлении/отмене. Приватный release-signing key не требуется ни downloader, ни installer и не поступает в приложение для подготовки Взора.

Рассматриваются вредоносная web-страница/renderer, захват browser broker в пределах реально предоставленной ему ОС-изоляции, опасная загрузка, подмена пакета/metadata/URL, попытка выхода через filesystem links, подмена скачанного файла во время импорта, сбой процесса/JVM, повторный запуск, отмена и вмешательство в browser-owned writable bundle. Глобальный противник корреляции, захват host account/root/kernel/hypervisor, уязвимости Xephyr/slirp/bubblewrap/Windows Sandbox, физический доступ и восстановление SSD/snapshots не закрываются гарантией этого приложения.

Доверенная часть: проверенный исходный код и runtime АЕГИС, криптографическая реализация и pinned Tor public key, системное TLS trust store, системные sandbox-компоненты, host-private control/templates, сам официальный подписанный Tor Browser и его штатная модель Tor/SOCKS/DNS/fingerprinting. Наличие отдельного процесса само по себе не считается sandbox.

## Границы

| Переход | Фактический контроль | Остаточное ограничение |
| --- | --- | --- |
| Открытие из JavaFX → background worker | URL проверяется до действия; blocking network/hash/extract/start выполняются вне FX; одна очередь подготовки, cancel token | Реальная отзывчивость GUI на целевых ОС требует нативного smoke |
| АЕГИС → официальный download endpoint | Только vendor HTTPS через loopback Tor SOCKS; hostname передаётся SOCKS domain, TLS hostname/SNI; без cookies и прямого fallback | Tor availability и TLS/официальный endpoint остаются внешней зависимостью |
| JSON → пакет | Bounded strict JSON, точный stable platform/version/tag/URL/asc; каждый redirect сохраняет host/path; bounded HTTP framing | JSON не имеет отдельной OpenPGP-подписи и сам не удостоверяет бинарник или абсолютную свежесть |
| Пакет → installer | Private byte snapshot; pinned OpenPGP проверяется раньше TAR/XZ parser или Windows EXE execution | Embedded keyring может устареть; новый/отозванный subkey требует удостоверенного обновления keyring |
| Подписанные bytes → версия | `tbb_version.json` сверяется с именем/платформой/release; ELF/PE Firefox и Tor должны быть x86_64; protected monotonic floor | Первое получение устаревшего, но действительного подписанного пакета не исключается одной подписью |
| Установка → последующий запуск | Внешние trusted manifests; preflight; свежий удостоверенный source для repair; атомарная публикация/backup recovery | Browser Data остаётся изменяемым состоянием собственного браузера; его настройки не являются гарантией анонимности |
| Browser filesystem → host | Linux namespaces/ограниченные mounts либо Windows VM/единственный mapping; host-private templates/control не передаются | Ошибка host ОС/sandbox или захват привилегированного host процесса вне границы |
| Download → зашифрованный архив | Явный выбор и unlock; приватный bounded snapshot, directory handle/no-follow/reparse/hardlink и mutation checks | Содержимое остаётся недоверенным; шифрование не обезвреживает вредоносный файл |
| URL/guest hint → управление процессами | Только проверенные URL и фиксированный bootstrap; host-private VM ID; прекращаются свои процессы/VM | Гостевой status не удостоверяет Tor bootstrap или остановку VM; host CLI должен подтвердить владение/остановку |

## Аутентификация, целостность и repair

Fingerprint Tor Browser Developers закреплён: `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`. Пользовательский ключ, подпись АЕГИС, имя файла или произвольная таблица SHA-256 не могут его заменить. Подлинность удостоверяет точные bytes, поэтому подпись проверяется до сложного parsing/execution. Installer получает собственный snapshot; замена исходного файла после выбора не становится новой доверенной установкой.

Внешний release JSON позволяет выбрать пакет, но не повысить доверенную версию сам по себе. На Linux signed internal version читается без исполнения. На Windows проверенный portable installer сначала извлекает bundle; лишь затем читается подписанное внутреннее version metadata и проверяются executable headers. При mismatch, повреждении или неподдерживаемой архитектуре bundle не выбирается для запуска.

Host-private receipt хранит actual version, архитектуру, SHA-256 архива и developer fingerprint. Version floor монотонен для удостоверенных архивов; изменение metadata/имени подписанного старого архива не повышает его. Это локальная защита от обычного rollback, а не полноценный протокол глобального времени/свежести. Штатный MAR updater проверяет собственные обновления внутри Tor Browser; АЕГИС не получает доверенный MAR receipt. Изменённые executable-файлы требуют нового official archive attestation. Полный реальный цикл MAR → закрытие → повторное удостоверение → запуск ещё **NOT_RUN**.

`authenticatedPreflight()` не пересчитывает changed bytes в новые trusted hashes. Missing/corrupt template или изменённая обычная сессия возвращают запрос повторного удостоверения, а ошибки доступа и опасные корни сохраняются как ошибки. Repair разрешён только после нового authenticated import. Исправленная копия создаётся из свежего удостоверенного source; только собственные Browser Data и загрузки переносятся со старой сессии. Исходные пользовательские данные не удаляются при неудаче копирования. Замена использует staging/backup, rollback и восстановление известного backup под manager lock после сбоя. Только три точных служебных Mozilla mutex leaf в `profile.default` пропускаются; другие внешние/dangling links не становятся разрешёнными.

## Linux

Tor Browser и его собственный Tor находятся в одном rootless namespace, созданном fixed-path системным bubblewrap с drop capabilities, изолированными process/IPC/network namespaces, чистым окружением, отдельными `/proc`, `/dev`, `/tmp`, HOME и writable browser bundle. Системные библиотеки/шрифты/сертификаты доступны ограниченными read-only mounts. Приватные расположения АЕГИС и выбранного архива проверяются на пересечение с видимыми mounts.

Собственная сеть поднимается slirp4netns с `--disable-host-loopback`, ограниченными ready/exit channels и проверкой принадлежности netns PID своему bwrap. Это скрывает host loopback и не делает slirp Tor-only firewall. Для штатного Tor/PT нужен внешний доступ. Resolver `10.0.2.3` относится к netns; Tor/bridge bootstrap может использовать DNS. Нельзя объявлять его DNS-пакеты утечкой web DNS без привязки к инициатору и назначению.

Браузер получает только вложенный Xephyr display с отдельным Xauthority. Host X socket, D-Bus, пользовательский `/run/user`, host home, audio и clipboard не монтируются. KDE Wayland использует Xwayland как host для Xephyr; отсутствие нужных зависимостей/локального DISPLAY/user namespaces запрещает запуск. Xephyr и его host display доступ — часть доверенной границы, требующая нативных испытаний.

## Windows

Backend требует Windows 11 24H2+ x64 Pro/Enterprise/Education, включённую виртуализацию, Windows Sandbox и актуальный Microsoft CLI. **Home не поддерживается**; fallback на обычный процесс/AppContainer не добавлен. Проверка prerequisites ничего не включает в ОС и не доказывает работоспособность VM.

Одна writable mapping содержит только bundle своей сессии и её downloads. Identity, архив, control и trusted template не отображаются в гостя. В `.wsb` отключены clipboard, camera/audio input, printers и vGPU, включён Protected Client. Сеть включена для Tor; гостевая Windows может иметь собственные сетевые службы. Не следует выдавать весь трафик VM за трафик Firefox.

CLI выбирается через проверенный Microsoft App Execution Alias и защищённый WindowsApps package; произвольный executable/PATH не принимается. Случайный host-private VM ID и ownership receipt записываются до запуска; посторонняя VM не принимается под управление. Из гостя поступают только ограниченные process hints. Stop подтверждается host CLI, а не текстовым guest status или выходом launcher PID. При неоднозначном stop данные и ownership остаются для повторного закрытия. Crash recovery использует только свои host-private receipt.

Отдельно, до браузерного запуска, подписью удостоверенный vendor NSIS installer исполняется на host в собственном Job Object: suspended creation → assign kill-on-close job → resume. Cancel/timeout завершает его группу, не затрагивая чужие Tor Browser. Эта мера ограничивает время жизни installer и не является sandbox браузера. Windows API path, NSIS execution, VM, NTFS ACL/reparse и собственные Job Object должны быть проверены на настоящей Windows 11; в этой среде их статус **NOT_RUN**.

## Сеть, идентичность и загруженные данные

Обычный web-трафик использует штатную Tor Browser proxy/DNS/WebRTC модель. Не изменяются fingerprinting-настройки, не добавляются расширения, не используется messenger SOCKS как сетевой backend браузера. Загрузка пакета через почтовый Tor и дальнейшая работа собственного Tor браузера — разные этапы; UI не выдаёт состояние первого за состояние второго.

Namespace/VM не запрещает скомпрометированному browser broker произвольный внешний трафик kernel policy. Следовательно, отсутствие прямых browser-соединений, DNS/IP/WebRTC leaks и корректность onion нельзя доказывать одним фактом использования Tor. Нужна реальная запись трафика и процессов, различающая Firefox, Tor/PT и службы гостевой ОС. Глобальная корреляция и действия пользователя, раскрывающего личность на сайтах, остаются риском.

В обычном режиме собственные Browser Data сохраняются. Они не являются данными аккаунта АЕГИС, однако могут содержать разрешённые самим Tor Browser browser settings/закладки и сведения, введённые пользователем. Перенос сохраняет это изменяемое состояние, а не доказывает его безопасность. Временный режим удаляет свой bundle после подтверждённой остановки; forensic erase не заявляется.

Приложение не запускает загрузки автоматически и не открывает их внешними host приложениями. Tor Project отдельно предупреждает о сетевых запросах документов во внешних приложениях; явный импорт в архив не снимает этот риск. Browser stdout/stderr отбрасываются; URL, query, passwords, Tor cookies и содержимое переписки не добавляются в диагностические журналы. UI не показывает raw HTTP header/path exception как доверенный текст ошибки.

## Что проверено и что блокирует Stable

69 локальных unit/fixture integration тестов прошли. Они включают реальные disposable OpenPGP signatures, HTTP framing, bounded XZ/TAR, version mismatch/antirollback, смену файла, cancellation и cleanup, реальный loopback SOCKS domain handshake, прерывание заблокированного SOCKS socket, repair/rollback/crash recovery и перенос stale mutex с сохранением bookmarks/downloads. Fixtures не являются официальным Tor Browser; их успех не удостоверяет официальный архив.

| Необходимое доказательство | Состояние в этой среде |
| --- | --- |
| Полное получение official archive + `.asc` и production-pin verification | NOT_RUN: native endpoint вернул HTML SiteUnavailable |
| Реальный launch/close официального Tor Browser на Windows 11 | NOT_RUN |
| Реальный launch/close на CachyOS KDE Wayland и X11 | NOT_RUN |
| HTTPS/onion и независимость почты при запуске/закрытии Взора | NOT_RUN |
| Web DNS/WebRTC/IP/direct-connection capture с привязкой к процессам | NOT_RUN |
| Реальные filesystem/IPC/clipboard probes внутри native sandbox | NOT_RUN |
| Официальный MAR update → re-attestation → bookmarks/downloads migration | NOT_RUN |
| Native cancel/kill, VM ownership recovery и installer Job descendants | NOT_RUN |

Эти пункты сохраняют `productionReady=false`. Build, synthetic fixture, headless JavaFX screenshot или отсутствие трафика у незапущенного браузера не переводят их в PASS. Сырые native metadata responses и XML локальных тестов находятся в `docs/test-results/2.5.0-tor-browser/`.

## Первичные источники

- Tor verification: <https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/>.
- Tor Browser security levels: <https://support.torproject.org/tor-browser/features/security-levels/>.
- Tor Browser safety / external documents: <https://support.torproject.org/tor-browser/security/using-tb-safely/>.
- Tor Browser identities: <https://support.torproject.org/tor-browser/features/managing-identities/>.
- Signed internal version build recipe: <https://lists.torproject.org/mailman3/hyperkitty/list/tbb-commits%40lists.torproject.org/thread/JVF25644IS5CWBPOJ4TCDN5IPWEBGSQW/?sort=date>.
- bubblewrap boundary design: <https://github.com/containers/bubblewrap/blob/main/README.md>.
- slirp4netns options: <https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md>.
- Windows Sandbox edition support: <https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/>.
- Windows Sandbox configuration: <https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file>.
- Windows Sandbox CLI: <https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli>.
- Windows Job Objects: <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>.
- Mozilla profile locks: <https://searchfox.org/firefox-main/source/toolkit/profile/nsProfileLock.cpp>.
