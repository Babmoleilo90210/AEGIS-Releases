# Серверные библиотеки АЕГИС 6.0.0

Пакет сохраняет исходные JAR и содержащиеся в них уведомления. Дополнительные тексты лицензий получены из официальных тегов проектов; файлы и контрольные суммы перечислены в inventory/SBOM. Это перечень шести внешних runtime JAR сервера, а не всей ОС, JDK, клиентских или build/test зависимостей.

| Компонент | Версия | Условия распространения |
|---|---|---|
| Google Gson | 2.14.0 | Apache License 2.0; Copyright 2008 Google LLC (также указан в опубликованном POM) |
| Xerial SQLite JDBC | 3.53.4.0 | Apache License 2.0 и сохранённый BSD 2-Clause notice David Crawshaw, 2006 |
| SLF4J API | 2.0.17 | MIT; Copyright 2004–2022 QOS.ch Sarl |
| Error Prone annotations | 2.48.0 | Apache License 2.0; Copyright 2015 The Error Prone Authors; runtime dependency Gson |
| Password4j | 1.8.4 | Apache License 2.0; только отдельный mail-relay600 |
| SLF4J NOP | 2.0.17 | MIT; Copyright 2004–2022 QOS.ch Sarl |

Официальные источники текстов:

- https://github.com/google/gson/blob/gson-parent-2.14.0/LICENSE
- https://github.com/xerial/sqlite-jdbc/blob/3.53.4.0/LICENSE
- https://github.com/xerial/sqlite-jdbc/blob/3.53.4.0/LICENSE.zentus
- https://github.com/qos-ch/slf4j/blob/v_2.0.17/LICENSE.txt
- https://github.com/Password4j/password4j/blob/1.8.4/LICENSE
- https://github.com/google/error-prone/blob/v2.48.0/COPYING

SQLite core имеет собственное посвящение в public domain: https://www.sqlite.org/copyright.html. Сам SQLite JDBC JAR сохраняется целиком, включая native libraries и авторские уведомления. Проверка реально загруженного Linux JNI дала SQLite 3.53.4; это не отдельный независимый аудит всех встроенных native binary variants.

Debian OpenJDK, Tor, Python, restic, systemd, AppArmor и необязательный WireGuard устанавливаются оператором из штатных подписанных репозиториев Debian и не включаются бинарниками в этот tar. Их точные установленные версии, лицензии и security updates проверяются отдельно в целевой Debian 13 среде. Приватные ключи пользователя и release-signing key в комплект не входят.
