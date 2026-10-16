# Содержимое сообщества АЕГИС 5.0.0

`ContentService(CommunityStore, AccessControl)` обслуживает JSON RPC `content.*`. Клиентская identity уже проверена внешним транспортом. Каждый обработчик выполняет чтение, текущую проверку полномочий и изменение в одной транзакции SQLite. Клиентские роли, nickname, флаги администратора и авторства не принимаются.

## Материал

Возвращаемый объект: `id, kind, type, owner, organization, cityId, distribution, title, body, state, revision, createdAt, updatedAt, publishedAt, eventDate, ai, sources, policy, files, history`.

- `kind`: NEWS, EVENT, LIBRARY. Общая библиотека не читает личный архив.
- `type`: NOTE, ARTICLE, DOCUMENT, PDF, IMAGE, VIDEO, NEWS, EVENT, PERSON, ORGANIZATION, TOPIC.
- `distribution`: GLOBAL, CITY, ORGANIZATION. География отдельно от допуска.
- `cityId`: нормализованный `ru/ru-mow/moscow`; город не определяется по IP. Город организационного материала берётся из серверной записи организации. Организация без города не может подделать региональную публикацию.
- `state`: DRAFT, SUBMITTED, APPROVED, PUBLISHED, CORRECTED, REJECTED, RETRACTED.
- `policy`: `{scope:'GLOBAL'|'ORG:<uuid>',minimumLevel:0,permissions:[],organizations:[],users:[],offlineAllowed:false}`. Списки организаций и пользователей объединяются OR; уровень и дополнительные разрешения применяются AND. Организационный scope требует актуального членства. Отсутствующий policy по умолчанию выбирает GLOBAL для общего материала, ORG:id для организации.
- `body` хранит исходный Markdown без потери начальных/конечных пробелов. Он выдаётся как инертные данные, не исполняется. Клиент обязан использовать безопасный renderer. HTML/JavaScript не исполняются сервером и не загружаются как документ.
- `history` открытого материала содержит только номера версий и время; старое содержимое выдаётся только по отдельному редакторскому запросу.

## Действия

Для префиксов `content.news`, `content.events`, `content.library` доступны:

- `.create`: `{title,body,organization?,cityId?,distribution?,type?,policy?,sources?}`. Для EVENT обязательны `startsAt` (epoch ms), дополнительно `location,online,capacity` (0 = без лимита).
- `.get`: `{id}`.
- `.list`: `{feed?:'ALL'|'GLOBAL'|'CITY'|'ORGANIZATIONS',cityId?,organization?,query?,type?,from?,to?,cursor?,limit?}`; ответ `{items,nextCursor}`. Лимит 1–100, по умолчанию 40. Фильтрация производится на сервере, закрытые материалы не входят в результаты и счётчики. Список и граф возвращают метаданные и summary до 280 Unicode code points; полный body, sources, files и history выдаются только get.
- `.update`: `{id,revision,title,body,policy?,sources?,startsAt?,location?,online?,capacity?}`. Старый revision вызывает CONFLICT; новая редакция становится черновиком. Изменение политики требует отдельного `<PREFIX>_ACCESS_MANAGE`.
- `.submit`: `{id,revision}`. Только черновик или отклонённая заявка.
- `.moderate`: `{id,revision,decision:'APPROVE'|'REJECT'}`. Только поданная заявка и MODERATE.
- `.publish`: `{id,revision}`. Требует PUBLISH; всеобщая новость дополнительно требует `NEWS_GLOBAL_PUBLISH` исключительно GLOBAL. Обычный автор не может обойти модерацию правом CREATE.
- `.retract`, `.delete`: `{id,revision}`. Удаление мягкое, сохраняет историю, требует отдельного DELETE. Отзыв требует PUBLISH.
- `.revisions`: `{id,cursor?,limit?}` — до пяти содержательных редакций за страницу, только EDIT; ответ `nextCursor` содержит номер следующей границы или 0.
- `.revert`: `{id,revision,targetRevision}` — новая редакция, не перезапись истории; политика доступа не откатывается.
- `.export`: `{id}` — отдельное EXPORT и актуальное право чтения; возвращает инертный Markdown.
- `.react`: `{id,reaction:'Нравится'|'Полезно'|'Поддерживаю'|'Интересно'|''}`.
- `.poll.create`: `{id,question,options:[...]}` — 2–12 вариантов в черновике, EDIT.
- `.poll.vote`: `{id,optionId}` — вариант должен принадлежать именно этому видимому опубликованному материалу. Один голос на пользователя, повторный выбор заменяет его.

Имена разрешений: NEWS_*, LIBRARY_*, EVENTS_*; CREATE, EDIT, MODERATE, PUBLISH, DELETE, EXPORT, ACCESS_MANAGE независимы. Уровень допуска не даёт права редактирования. Чтение публичного материала не требует пользовательской роли, дополнительные ограничения применяются политикой.

## Мероприятия

`content.events.list` дополнительно принимает `startsFrom?,startsTo?` — включительные границы даты начала мероприятия в epoch ms, отдельно от `from/to` даты изменения. Фильтр применяется до SQL-лимита кандидатов, права и cursor сохраняются; метаданные EVENT содержат `startsAt,online`, без полного документа.

`content.events.register/unregister {id}`; вместимость и повторная регистрация проверяются атомарно. `content.events.cancel {id,revision}` отзывает мероприятие и уведомляет записанных участников. Участник может прочитать статус отменённого мероприятия только пока его текущая политика допуска сохраняет доступ. Перенос через update/publish сохраняет участников и создаёт уведомление.

## Граф и связи

- `content.library.graph {cursor?,limit?,query?,type?,organization?,from?,to?}` -> `{nodes,edges,nextCursor}`. До 100 доступных узлов за страницу; фактический размер динамически ограничивается 7000 JSON values / 7 МиБ с запасом под подписанный envelope (декодеры 8192 / 8 МиБ). Каждое ребро выдаётся при достижении большего ID его разрешённых концов, включая связи с ранее загруженными страницами. Для обоих концов повторно проверяются ACL и те же фильтры. `nextCursor` непрозрачен: ID завершённого узла либо `E:<nodeUUID>:<lastVisibleEdgeUUID>` для продолжения его рёбер; узел в таком продолжении может повториться, ребро не повторяется. Клиент объединяет узлы по ID и сохраняет cursor без разбора. При нехватке budget ни узлы, ни рёбра не пропускаются молча. Нет общего количества закрытых узлов/рёбер.
- `content.library.link.propose {from,to,explanation}` -> PROPOSED; требует LIBRARY_LINK и чтения обеих вершин. Утверждённая связь не создаётся автоматически.
- `.link.list {id,state?,limit?}` -> `{items}`. Предложения видны только читателям обеих вершин.
- `.link.decide {id,decision:'APPROVE'|'REJECT'}` требует LIBRARY_EDIT в областях обеих вершин и актуального права чтения.

## Файлы

`content.files.upload {materialId,name,mime,base64}` — не более 4 МиБ на файл, 32 файла / 32 МиБ на материал. Требует EDIT. Случайные непрогнозируемые ID, SHA-256, данные в BLOB SQLite: распаковки, файловых путей и symlink-выхода нет. Имя не допускает пути. MIME сверяется с сигнатурой, PNG/JPEG/WebP имеют ограничение 32 млн пикселей и 16384 на сторону. Допустимы PNG, JPEG, WebP, PDF, MP4, UTF-8 plain/Markdown; HTML, SVG и исполняемые форматы отвергаются.

`content.files.download {id}` проверяет актуальную политику родительского материала и возвращает base64 с `disposition:'attachment'`. PDF/медиа сервером не исполняются и автоматически не запускаются. Проверка сигнатуры не является антивирусной проверкой; клиент не должен автоматически исполнять вложение.

## Уведомления

- `content.notifications.list {cursor?,limit?}` -> `{items,nextCursor}`; максимум 512 записей на пользователя, 100 за страницу. Перед выдачей названия заново проверяется доступ к материалу.
- `.read {id}` — только собственное уведомление и текущий доступ.
- `.settings {category?,enabled?}` — MODERATION, EVENT_CHANGED, EVENT_REGISTERED; возвращает настройки категорий.

## Автоматический редактор

`ingestAi(actor,draft)` — только Java-вызов доверенного центрального редактора, не RPC-действие. Требуются NEWS_CREATE и для автоматической публикации NEWS_PUBLISH/NEWS_GLOBAL_PUBLISH. Вход: title, body/summary, cityId, distribution, sources, sourceGroups, eventDate (ISO Instant), significance (LOW/NORMAL/HIGH/CRITICAL/IMPORTANT), verified, autoPublish, обязательный dedupe. AI-флаг назначается сервером. Неуверенный материал, менее двух независимых групп или HIGH/CRITICAL/IMPORTANT направляется на модерацию. `dedupe` уникален в БД и сохраняется при перезапуске.

Рабочий узел не может вызвать этот sink через API, сам назначить AI-происхождение, автора, состояние или глобальные полномочия. Центральная подсистема дополнительно проверяет происхождение и независимость источников; content sink не выдаёт модельную оценку за доказанный факт.

## Ограничения проверки

JUnit использует настоящую SQLite и production AccessControl на одном хосте. Это не нативная приёмка Windows/CachyOS, не сетевой Tor E2E и не проверка двух физических устройств. Поисковый проход ограничен 5001 кандидатом, граф — страницей 100 узлов; при росте необходима серверная индексация ACL без выдачи скрытых метаданных. Нативные и production-сценарии отдельно остаются неподтверждёнными.
