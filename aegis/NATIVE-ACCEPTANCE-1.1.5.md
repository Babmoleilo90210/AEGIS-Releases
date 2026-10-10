# Native acceptance kit 1.1.5

Проводите испытания на копии тестового профиля, с отдельными тестовыми аккаунтами и staging Relay. Production Relay/onion не меняется. Не вводите production private key на онлайн-машине.

Матрица: Windows 11 x64 DPI 100/125/150/200%; CachyOS KDE Wayland и X11, доступное дробное масштабирование. Для каждого пункта указывайте PASS/FAIL/SKIP/NOT_RUN, ОС, версию, hash пакета, дату и причину. SKIP не закрывает обязательную проверку.

UI-01: все 16 новых и шесть прежних пресетов. UI-02: собственная тема. UI-03: preview/apply/cancel без ранней записи. UI-04: перезапуск. UI-05: системная тема. UI-06: расписание через полночь. UI-07: import/export. UI-08: повреждённый JSON. UI-09: safe recovery/reset/backup. UI-10: разные/отсутствующие шрифты. UI-11: большие шрифты и длинные никнеймы. UI-12: формы/размеры. UI-13: значки/текст/оба. UI-14: три зоны. UI-15: порядок и доступ к настройкам. UI-16: sliders/dividers/restart. UI-17: стандартный макет. UI-18/19/20: 2/3/compact. UI-21: cards. UI-22: expanded. UI-23: preview без plaintext защищённого письма. UI-24: черновик/получатели/тема/файлы/секреты в памяти при изменении темы. UI-25: page/drawer. UI-26: минимум окна. UI-27: реальный DPI. UI-28: alpha/opaque fallback. UI-29: ровно один Stage/OS window, включая файловые действия. UI-30: одна основная кнопка updater и отсутствие двойного close.

SYS-01: owner-signed newer manifest → available letter. SYS-02: invalid signature → no trusted letter. SYS-03: repeat → no duplicate. SYS-04/05: installed letter только после healthy startup + commit helper. SYS-06: ошибка в истории, только безопасный код. SYS-07: история offline. SYS-08: обычное Relay письмо с ником «АЕГИС» не получает system type. SYS-09: Stable/Beta history. SYS-10: system письма не уходят в Relay.

Регрессия: вход/выход, remember-login, offline vault, Direct Tor и Snowflake, Relay, online/offline доставка, TTL, ответы/цепочки, контакты/friends capabilities, блокировка и неизвестные отправители, protected letter/letter password/FF1, файлы, search/filter, vault/full backup и updater. Два настоящих клиента обменяются тестовым письмом и архивом; recipient offline, затем появление/ACK/TTL. Проверяйте фактические файлы/receipts и ciphertext на staging, не только интерфейс.

## Настоящий переход и подпись

Сначала проверьте финальные SHA256SUMS и unsigned manifest. Без подписи pinned production key клиент отклонит manifest — это правильное поведение. Создайте подпись только офлайн на CachyOS:

```bash
cd /path/to/AEGIS-1.1.5-candidate
sha256sum -c SHA256SUMS
sha256sum -c SIGNING-INPUT-SHA256
openssl pkeyutl -sign -rawin -inkey /media/offline/aegis-ed25519-private.pem -in updates/stable.json -out updates/stable.json.sig
openssl pkeyutl -verify -pubin -rawin -inkey updates/release-public.pem -in updates/stable.json -sigfile updates/stable.json.sig
```

Эта команда **не загружает ничего на GitHub**. Ключ не передаётся в Work/CI/репозиторий. Требуется существующий PEM Ed25519 ключ, соответствующий pinned public key; не генерируйте новый production key.

В исходной модели updater endpoints закреплены в бинарнике на main/updates/stable.json и beta.json. Изолированная ссылка другого репозитория или произвольный URL в настройках не поддерживается. Поэтому полного owner-signed E2E на неизменённом опубликованном клиенте нельзя выполнить с непубличным локальным manifest. Варианты: отдельно разрешённый временный Beta feed того же репозитория с собственным подписанным beta manifest, либо отдельная staging сборка с тестовым каналом, чьи результаты не подменяют проверку опубликованного клиента. Не меняйте Stable до завершения согласованной приёмки. Manifest Stable и Beta — разные байты и разные подписи.

После отдельного разрешения владельца: загрузите конечные assets в согласованный draft/test Release, опубликуйте согласованный подписанный тестовый feed. Предыдущий клиент должен получить manifest через свой Tor, Ed25519, показать письмо, скачать с progress/resume, проверить размер/SHA/package, ждать подтверждения, backup, install, restart, подтвердить версию/данные/installed letter. На отдельной копии профиля смоделируйте startup failure и проверьте бинарный и data rollback. Одна успешная загрузка не является полным E2E. Все 17 шагов ТЗ фиксируются отдельно.

Не публикуйте Stable 1.1.5, пока обязательные native gates и открытые ограничения не закрыты.
