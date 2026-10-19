# Debian 13 Server — АЕГИС 6.0.0

Это отдельный серверный staging-комплект для проверки нового кода. Он не заменяет действующий Relay, не меняет его БД, onion-адрес, production Tor, GitHub, feed или release-signing key. Все имена новых units начинаются с `aegis600-staging-`. До нативной приёмки и разрешения владельца `productionReady=false`.

## Реальные границы служб

Комплект содержит действительные Java mains Identity, Attachment Service, Community, Library Controller, Glas Signaling, News Worker и Management Agent, отдельный opt-in Mail Relay6, а также отдельный локальный Monitoring collector. Библиотечный процесс использует общую Community SQLite и её модель ACL; он запускается под тем же `aegis600-community`, имеет отдельный сервисный ключ и производный ключ аудита, но не является изолированным от доверенной Community-базы сервисом. Профиль Library разрешает только файлы этой БД и собственный state, не исходный TOTP KEK. Инициализация Library выполняется доверенным оператором отдельно.

Отдельного исполняемого `Library Sync`/Syncthing ACL daemon этот комплект не выдумывает. Действительный Glas Signaling хранит только короткоживущие root/app-подписанные onion-привязки и contact-политики; он не принимает аудио, media offers или приватные ключи. Старый production Relay остаётся прежним. Отдельный Mail Relay6 использует реальный RelayMain600 с LOGIN6/REGISTER6 и обязательным Identity gate; его нативная приёмка и миграция существующих аккаунтов проходят отдельно. Наличие unit-файла не доказывает их прохождение. Management отклоняет несуществующие/неразрешённые сервисы, не выдаёт за них успешный статус.

Identity6 выдаёт проверяемые app capabilities с account/device/app/generation, PoP запроса, коротким lease и отзывом. Owner Bootstrap одноразовый и требует подписи постоянной identity; никакие приватные ключи пользователя на сервер не отправляются. Вложения имеют отдельный protocol `ATTACHMENTS_V1`; старые protocol1/Operation/Limits не изменяются. Поддержка клиентов5 — минимум12 месяцев после фактической даты выпуска6, а не со дня подготовки этого пакета. Дата окончания будет опубликована вместе с разрешённым релизом.

## Требования и проверка платформы

Цель: Debian 13 amd64, штатные OpenJDK21 и systemd257, AppArmor в enforce, Tor, Python3, sqlite3, restic. WireGuard необязателен и предназначен только для ограниченного административного доступа. Ориентир4 GB RAM — для ограниченного теста,8 GB предпочтительно; это не результат нагрузочной приёмки. Локальная крупная ИИ-модель на маломVPS не предполагается.

Запустите `python3 opt/aegis600/bin/preflight.py`. Он только читает состояние. Ubuntu, PID1supervisord, отсутствие enforce или непроверенные профили не становятся DebianPASS. Системные пакеты устанавливаются оператором штатнымAPT с проверкой Debian-репозиториев; комплект не выполняет `curl|sh`, не отключает подписи и не содержит произвольных root-команд из клиентского ввода. Проверьте обновления безопасности этих пакетов перед приёмкой.

## Сборка действительного дистрибутива

После сборки новых серверных JAR Java21 и фиксации исходников:

```sh
python3 deployment/debian600/staging.py \
  --jar-dir build/local-java21 \
  --deps /absolute/verified-runtime-dependencies \
  --root /absolute/new-server-staging \
  --source-commit FULL_COMMIT_SHA \
  --archive /absolute/AEGIS-6.0.0-Debian13-Server.tar.gz
```

Приводятся реальные пути конкретной проверенной среды сборки. Нужны точные `common-protocol.jar`, `identity-server.jar`, `attachment-service.jar`, `glas-signaling.jar`, `management-agent.jar`, `community-server.jar`, `news-worker.jar`, `relay-server.jar`, а также закреплённые Gson2.14.0, его runtime dependency error_prone_annotations2.48.0, SQLiteJDBC3.53.4.0 и SLF4J2.0.17; только mail-relay дополнительно содержит Password4j1.8.4. Клиентские JAR, Tink, JavaFX и расшифрование писем в серверный runtime не включаются. Пакет содержит свой inventory размеров/режимов/SHA256 и source commit. `--allow-development` допустим только для локальной проверки; такой пакет явно отмечен dirty и deploy отказывается его устанавливать.

## Развёртывание новой staging-среды

Сначала независимо проверьте утверждённую владельцем подпись release manifest закреплённым публичным ключом и SHA256 конкретного скачанного пакета. Самопроверка inventory неподписанного архива не заменяет доверие к источнику. Неподписанный кандидат разрешён только как явно обозначенный объект тестирования, не как автоматическое production-обновление. Приватный release key на VPS не нужен и запрещён.

В новой Debian 13 test-среде распакуйте комплект в отдельный каталог. Команда:

```sh
python3 opt/aegis600/bin/deploy.py /absolute/unpacked/AEGIS-6.0.0-Debian 13-Server
```

по умолчанию показывает план без изменений ОС. Режим применения требует одновременно root, `--apply --staging-confirmation NEW-ISOLATED-STAGING`, Debian 13, clean-source provenance и отсутствия всех целевых путей AEGIS 6. Он копирует только фиксированные `/opt/aegis600`, `/etc/aegis600`, свои units/profiles/sysusers/tmpfiles, создаёт отдельныеUID и загружает профили. Сервисы автоматически не запускаются. Ошибка любого шага останавливает процесс; это не транзакционное обновление существующего сервера. Существующие пути не перезаписываются. Для обновления уже установленного AEGIS 6 нужен отдельно проверенный migration/deploy механизм.

Проверить `systemd-analyze verify` всех units, загрузку `apparmor_parser -r`, actual `aa-status`/`/sys/kernel/security/apparmor/profiles` и аудит отказов. Профили и JDK-пути — кандидат, а не утверждение о прошедшей enforce-приёмке. Профиль не переводится автоматически в complain при отказе. Подтвердите доступ только к собственным state, отсутствие доступа News Worker к Relay/Identity и чужим ключам, эффективные cgroup лимиты и отсутствие незаявленных public-listen портов.

## Первоначальная настройка

Все сервисные ключи создаются на сервере под собственным пользователем, файлы0600/каталоги0700. Они не являются release-signing key или account identity private key. Перед каждым шагом проверьте свой путь,UID и наличие резервной копии существующей Community-базы.

Identity:

```sh
sudo -u aegis600-identity /opt/aegis600/identity/bin/identity init --home /var/lib/aegis600/identity/state
```

Публичный `service-public.txt` независимо сверяется по SHA256 и копируется оператором как root-owned `/etc/aegis600/identity-public.txt`. Это только открытый ключ; приватный `service.key` не копируется. После регистрации аккаунта владельца с доказательством владения root/device keys:

```sh
sudo -u aegis600-identity /opt/aegis600/bin/aegis-admin owner bootstrap \
  --home /var/lib/aegis600/identity/state --account-id ACCOUNT_ID --challenge /private/operator/owner-challenge.json
```

Точные `proofBytes` подписываются Почтой/доверенным локальным клиентом после повторной аутентификации. На сервер передаётся только публичный JSON-документ доказательства. Повторный bootstrap и подмена nickname не дают владельца. Подтверждение выполняется тем же вызовом с `--proof FILE` вместо `--challenge`. Ни подпись, ни команду нельзя заменять созданием пользователя с похожим именем.

Attachment:

```sh
sudo -u aegis600-attachments /opt/aegis600/attachments/bin/attachments init /var/lib/aegis600/attachments/state
```

Community6 создаётся через действительный Identity-gated `gateway600.CommunityMain600`, а не старый legacy `CommunityMain`:

```sh
sudo -u aegis600-community /opt/aegis600/community/bin/community --init \
  /var/lib/aegis600/community/state \
  --identity-public /etc/aegis600/identity-public.txt \
  --identity-fingerprint IDENTITY_SHA256 --identity-port 38250 --port 38252
```

Порт сохраняется в private config; `--serve` не принимает дополнительный `--port`. Начальные пользовательские роли и legacy admins не создаются; Owner подтверждается Identity. Production БД не используется как тестовый файл. Library Controller инициализируется собственным main (`--init DIR --community-home DIR --identity-public FILE --identity-fingerprint SHA256 --identity-port 38250 --port 38253`) под Community UID. Два доверенных контекста не становятся автоматически единой авторизацией без проверки действительных server bridges. Закрытые материалы не выдаются Syncthing целиком: noteACL проверяет Controller до содержимого; LibrarySync/sandbox delivery остаются отдельной приёмкой.

Management Agent и root broker получают разные state. Инициализируйте `/var/lib/aegis600/management/state` под `aegis600-management`, а фиксированный `/var/lib/aegis600/management-broker` — локально командой `sudo /opt/aegis600/management/bin/management broker-init`. Каталог создаёт tmpfiles; повторная инициализация непустого каталога запрещена. Broker создаёт только собственный audit key и не получает сервисный ключ публичного агента. Root broker читает только фиксированный `/etc/aegis600/management-broker.properties` и root-owned audit key. Public agent непривилегирован, `NoNewPrivileges=true`. Broker принимает соединения только от реального UID `aegis600-management` через Linux `SO_PEERCRED`, а не из JSON. Public agent проверяет root peer и root-owned Unix socket. Они имеют разные RuntimeDirectory: public `aegis600-management-agent`, broker `aegis600-management`.

Каждая операция broker повторно проверяет appPoP через закреплённый Identity, account/app/current generation/ADMIN/fresh step-up; restore требует двух различных действующих администраторов, подписавших точный неизменный request UUID/payload. БД не допускает повторного исполнения ID; HMAC audit записывает intent до systemctl и результат после. После сбоя `STARTED` не исполняется автоматически повторно. Аудит не защищает от восстановления целого старого снимка БД root-злоумышленником без внешнего checkpoint.

Broker выполняет только фиксированные staging units из enum. Не принимает имя unit, shell, путь, URL, argv или переменные окружения от пользователя. Production Relay, общий root shell, arbitrary package install и trust rotation отсутствуют в этом API. Backup/restore создают асинхронное systemd-задание; принятие команды не является подтверждением успешной резервной копии. Release единолично утверждает владелец; правило двух администраторов относится к критическим серверным операциям.

## Отдельный Mail Relay6

Это новый экземпляр, а не замена production Relay. Он имеет UID `aegis600-mail-relay`, каталог `/var/lib/aegis600/mail-relay/state`, собственные ключи и onion, origin `127.0.0.1:38256`. Relay JAR сохраняет исходную версию 0.3.0; комплект АЕГИС имеет версию 6.0.0. Файл `mail-relay.properties.example` не активируется автоматически. Оператор проверяет и создаёт root-owned `/etc/aegis600/mail-relay.properties`, доступный только этому UID для чтения. Пример закрывает регистрацию; её изменение выполняется отдельным разрешённым решением оператора. Старый протокол и предел 100 MiB сохраняются; большие вложения идут отдельным Attachment Service.

Сначала создайте новый state и ключ сервиса:

```sh
sudo -u aegis600-mail-relay /opt/aegis600/mail-relay/bin/mail-relay init \
  --home /var/lib/aegis600/mail-relay/state \
  --config /etc/aegis600/mail-relay.properties \
  --identity-public /etc/aegis600/identity-public.txt \
  --identity-fingerprint IDENTITY_SHA256 --identity-port 38250
```

Независимо сверьте публичный `service-public.txt` и его SHA-256. Доверенный оператор копирует только этот публичный файл в root-owned `/etc/aegis600/mail-relay-service-public.txt` с group `aegis600-identity`, режимом 0440. **До первого запуска** явно разрешите этот конкретный открытый ключ в Identity:

```sh
sudo -u aegis600-identity /opt/aegis600/bin/aegis-admin service relay allow \
  --home /var/lib/aegis600/identity/state \
  --public /etc/aegis600/mail-relay-service-public.txt \
  --fingerprint RELAY_SERVICE_SHA256
```

Не передавайте в Identity `service.key` или пользовательские private keys. Передача только публичного файла между UID выполняется доверенным оператором через отдельно сверенную копию: приватный каталог Relay 0700 не нужно открывать другим пользователям. Если allowlist не настроен, новый защищённый доступ отклоняется. После проверки запускается только `aegis600-staging-mail-relay.service`. Management enum `MAIL_RELAY` управляет этой фиксированной unit; произвольное имя и production Relay не принимаются.

## Glas Signaling и Monitoring

Собственный сервисный ключ Гласа создаётся командой `sudo -u aegis600-glas-signaling /opt/aegis600/glas-signaling/bin/glas-signaling init /var/lib/aegis600/glas-signaling/state`. Сервер запускается только на loopback за отдельным onion. Каждая операция привязана к app PoP точных байтов, GLAS/VOICE_CALL и текущей Identity-generation. Delegation подписывается постоянной identity только в Почте после явного типизированного согласия; приватный ключ на сервер не передаётся. Endpoint имеет подпись GLAS app, pin сервиса и срок не более 120 секунд.

Сервер принудительно проверяет два contact allowlists: caller outgoing и callee incoming. Неизвестные закрыты по умолчанию; организационные исключения без отдельного проверенного authority не добавляются. Lookup обеих сторон проверяет live capability. Клиент обязан свежо проверять counterpart перед каждым incoming/outgoing handshake и ограниченно обновлять lease во время разговора; одна публичная подпись не является разрешением продолжать отозванную сессию. Полное описание формата находится в `glas-signaling/CONTRACT-6.0.0.md` исходников. Реальный публичный Tor и audio native acceptance не заменяются HTTP fixtures.

Monitoring — непривилегированный Python-процесс с фиксированным перечнем новых units. Он получает только ActiveState/SubState, MemoryCurrent, TasksCurrent и CPUUsageNSec, сохраняет один атомарный приватный health.json раз в минуту и не читает БД, содержимое журналов, окружение, токены, аккаунты или звук. Нет внешнего listen/телеметрии. `monitoring.py --once` даёт read-only проверку; если PID 1 не systemd, явно возвращает NOT_RUN. Присутствие счётчиков не доказывает нагрузочную или нативную приёмку.

## Tor и WireGuard

`torrc.staging` запускается отдельной unit/UID/state и не подменяет существующий torrc. Origin ports 38250–38256 только loopback, отдельные onion services. Glas Signaling использует порт 38255 и собственный UID/state. Сверьте фактические `ss -ltnp`, onion identities и Tor-подключение каждого приложения. Наличие onion-конфига не доказывает отсутствия утечек.

News Worker имеет самостоятельную identity и разрешённые публичные HTTPS-источники; пользовательские ключи/переписка ему не выдаются. Он требует существующего coordinator и собственного keyfile. До настройки рабочей конфигурации main завершается с понятным отказом. Пример не является действительным адресом. Внешние API по умолчанию не настроены; ключи не помещаются в шаблоны/argv/архив. Допустимые локальные модели не требуют платного сервиса.

Пример WireGuard не содержит private key и не активируется автоматически. Создавайте ключи локально на доверенных устройствах; admin peer имеет отдельный `/32`, host firewall допускает только ограниченные административные порты. Не включать forwarding/NAT или full tunnel просто ради управления. WireGuard AllowedIPs не заменяет firewall. Один VPS остаётся общей точкой отказа и root-компрометации.

## Внешние зашифрованные резервные копии

Штатный restic отвечает за шифрование/аутентификацию; собственной криптографии резервных копий нет. Оператор готовит внешний репозиторий и сильный пароль вне чата/Git/публичных логов VPS. `backup.json`/repositoryfile/passwordfile — отдельные root0600, `offsiteConfirmed=true` только после фактической проверки. Локальный каталог того же VPS не принимается как offsite. Значения секретов не передаются в argv; stdout/stderr restic с путями не публикуются.

Backup job останавливает только новые пишущие службы АЕГИС 6, включая Management Agent, его broker и отдельный staging Tor. Root копирует ограниченные непрозрачные байты файлов, включая SQLite WAL и служебные ключи, без загрузки SQLite-парсера. Затем ранее активные службы запускаются в обратном порядке, до разбора любых БД. Временные monitoring-снимки не копируются. Существующий Relay не останавливается и не читается. Предел snapshot: 100000 объектов / 32 GiB, private 0700/0600; symlink, path traversal, нерегулярные файлы и рекурсивное копирование запрещены. Неудачный snapshot удаляется и при ошибке валидатора.

Каждая БД отдельно передаётся непривилегированному DynamicUser в ограниченный systemd unit: собственный RootDirectory, только эта БД и её WAL/journal, read-only вход и отдельный выход, без сети и доступа к служебным ключам, AppArmor, seccomp, NoNewPrivileges, пустой capability set, 192 MiB памяти, 15 секунд CPU и 20 секунд общего времени. Предел входа одной БД — 512 MiB. Валидатор проверяет фактический UID, NoNewPrivileges и запрет создания сетевых сокетов до разбора БД; при отсутствии изоляции операция прекращается. После изолированного SQLite backup/integrity_check root копирует результат как непрозрачный файл, затем проверяет SHA-256 inventory. Только после этого запускаются restic backup и `check --read-data`.

В Work выполнены 20 переносимых Python-проверок, включая реальный seccomp-запрет AF_INET/AF_INET6/AF_UNIX и отказ настоящего worker вне sandbox. Четыре проверки полного UID/chroot sandbox отмечены NOT_RUN: у среды нет CAP_SYS_CHROOT/CAP_SETUID/CAP_SETGID. Проверки systemd DynamicUser, AppArmor enforce и точной Debian 13 SQLite-библиотеки также NOT_RUN; функциональный тест на синтетической WAL-БД их не заменяет. Публичный JSON `PASS_COMMAND` означает выполненную команду, а не внешний restore drill или завершённую нативную приёмку.

Restore требует полный snapshot ID из 64 hex-символов и критическое одобрение. `restic restore --verify` пишет в новый приватный каталог root. Во время выполнения проверяются предел 32 GiB, 100000 объектов, минимум 256 MiB свободного места и срок 3600 секунд. При нарушении процесс и его дочерняя группа завершаются; затем root проверяет SHA-256 inventory и отдельный непривилегированный per-DB validator проверяет SQLite без изменения восстановленного inventory. Частичный результат не становится рабочим state. Работающая БД не перезаписывается, liveStateSwitched=false. Переключение, схемы, новые записи после snapshot, rollback и перезапуск проверяются отдельно. Старый state не удаляется. Полный внешний restore и аварийное восстановление VPS обязательны до Stable.

## Приёмка

Отдельно фиксировать: Debian 13 native/install/systemd/AppArmorEnforce; все onion-клиенты; 500MiB при heap 96 MiB; resumablequeue/TTL 30 days/quota/diskfull; Owner Bootstrap и recovery; реальные операции двух администраторов и отзыв; внешнийresticrestore; совместимостьклиентов 5; прежнийRelay; миграция/rollback. Локальные HTTP/SOCKS fixture-тесты не являются Tor или Debian native. Полный серверный дистрибутив со скриптами не даёт основания productionReady=true.
