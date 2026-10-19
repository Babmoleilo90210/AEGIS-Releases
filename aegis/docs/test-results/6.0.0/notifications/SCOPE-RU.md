# Центр уведомлений Core 6.0.0

Реализован CoreNotificationsView600: server-filtered shared-system events, русские категории, read acknowledgement, сохранение предпочтений, ненавязчивые ссылки на приложения Письма/Глас и проверенные обновления. Личный текст писем и голосовые данные не импортируются. Shared CommunityUi принадлежит Core и не закрывается локальным view. Смена lock/close lifecycle запрещает поздним ответам восстановить содержимое.

Локальная JavaFX Monocle проверка PASS_HEADLESS использовала реальные IdentityHttpServer и CommunityHttpGateway600, Ed25519 app proofs/response signatures, настоящую SQLite и production CommunityClient600/TorTransport через явный loopback SOCKS fixture. Сервер заранее фильтрует закрытый title; клиент не получает закрытое имя, чтобы затем спрятать его. Проверены 50×10 страниц и предел500, сохранённое seen=1, category enabled=0, прекращение генерации выключенной категории, actual signed list reply задержан и не отрисован после lock. Получены2 настоящих PNG, визуально просмотрены.

Это не настоящая Tor-сеть и не нативная Windows/CachyOS приёмка. Основной backend загружен из source-compiled классов диагностического Gradle и focused Library output; RUN.json фиксирует использованные class SHA/команды, новый UI source SHA проверен до/после. Итоговый общий source-coherent Gradle/root smoke необходим перед релизом. Production не менялся.
