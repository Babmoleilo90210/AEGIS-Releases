# Модель угроз Safe Web 2.0.0

## Активы и противники

Защищаемые активы АЕГИС: identity private keys, пароли аккаунтов и писем, FF1, recovery keys, зашифрованный архив и его расшифрованное содержимое, переписка и signing metadata. Приватный release-signing key владельца вообще не должен попадать в сборочную среду.

Рассматриваются вредоносный сайт/renderer, опасная загрузка, подмена пакета, URL/command injection, попытка доступа к host home, loopback, IPC и clipboard, сбой/повторный запуск и очистка чужих процессов. Полный захват host OS/учётной записи, уязвимость ядра/гипервизора/Xephyr, глобальный traffic correlation и физическое восстановление удалённых SSD-блоков не покрываются гарантией приложения.

## Границы доверия

| Граница | Механизм | Предел доказательства |
|---|---|---|
| Пакет → installer | Pinned Tor primary fingerprint, OpenPGP detached signature, закрытый snapshot до распаковки | Снимок keyring не знает будущих отзывов; подпись не доказывает свежесть версии |
| Installer → хранилище | Ограниченная распаковка, безопасные внутренние ссылки, атомарная публикация | Официальный реальный архив ещё должен пройти E2E |
| Browser bundle → trusted metadata | Шаблоны/receipts в немонтируемом control/templates | Host-процесс с теми же правами может изменить оба; он вне этой гарантии |
| Linux browser → host | Bubblewrap namespaces, cap-drop, private slirp и вложенный Xephyr | Доверяем ядру, системным компонентам и графическому серверу; не mount весь home |
| Windows browser → host | Windows Sandbox, один bundle mapping, отключённый clipboard/devices, собственный VM ID | Требуются поддерживаемые edition/build/CLI; гипервизор/redirected FS остаются доверенными |
| Browser → Tor | Неизменённая штатная архитектура Tor Browser с собственным Tor | Нет kernel firewall против полного browser-broker compromise |
| Download → archive | Явный выбор, bounded snapshot с безопасными handles вне sandbox, существующий EncryptedArchive | Импорт не делает содержимое файла безопасным для последующего просмотра |
| AEGIS lifecycle → browser | Собственные процессы/namespace или VM ID, manager lock, остановка до удаления | Нативное поведение и аварии должны быть подтверждены на целевых ОС |

Browser launcher не получает ключевые/архивные объекты, локальную БД или текст письма. Проверяемые приватные пути передаются только host-контроллеру для исключения их из системных mounts. Окружение очищается. URL передаётся одним argv либо фиксированным гостевым data-файлом; shell-код не строится из URL. Browser stdout/stderr отбрасываются. Сырые URL, Tor cookies, параметры писем и пароли не пишутся в диагностические журналы.

## Сетевой риск

Для нормального браузерного трафика сохраняются штатные SOCKS/DNS/WebRTC и anti-fingerprinting настройки Tor Browser. Собственный Tor/bridge transport должен выходить наружу, поэтому весь процессный набор не может быть просто лишён внешней сети. Namespace/slirp прячет host network namespace и loopback; он сам не различает Tor и захваченный broker. Windows Sandbox дополнительно содержит службы гостевой ОС. Сетевые измерения должны различать браузер, Tor/PT и ОС; отсутствие DNS/UDP у браузера нельзя доказывать пустым headless-тестом.

SW-01/02/03/04 остаются NOT_RUN до реального HTTPS/onion/DNS/WebRTC испытания и захвата трафика. Не обещать сохранение анонимности при захвате broker/host OS. Не использовать найденное ограничение как повод отключать штатный Firefox sandbox.

## Изменяемые данные и обновления

Из hash inventory исключены только штатные browser Data, отдельные загрузки и генерируемый корневой desktop launcher; canonical vendor launcher и исполняемые файлы остаются проверяемыми. Mutable roots не могут быть ссылками/особыми файлами. Downloads не являются trusted executable code. Официальное обновление не даёт права пересчитать доверенные хэши без нового подписанного источника. Перенос профиля в новый пакет касается только браузерных Data/загрузок.

Временный профиль удаляется только после успешного завершения собственной среды. Ошибка остановки должна сохранять владение и блокировать повторный запуск/удаление. Остатки после аварии удаляются под исключительной host-блокировкой; постоянный профиль не очищается. Secure erase не заявляется.

## Состояние приёмки

Криптография, policy/FS/lifecycle unit-тесты и headless JavaFX дают локальные доказательства отдельных правил. Фактический Tor Browser launch, Windows Sandbox CLI, namespace sandbox, MAR update и целевые Windows11/CachyOS сетевые проверки требуют нативных доказательств. Их статус не переводится в PASS по успешной сборке. Полная матрица SW-01…SW-20 хранится в FINAL-VERIFICATION-2.0.0.json; `productionReady=false` до завершения обязательных испытаний.

Основные источники: [Tor Browser](https://support.torproject.org/tor-browser/), [проверка подписи Tor](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/), [bubblewrap](https://github.com/containers/bubblewrap), [slirp4netns](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md), [Windows Sandbox configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file), [Windows Sandbox CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli).
