# Проверки АЕГИС 1.1.0

Кандидат; productionReady=false. Архивные 54 теста 1.0.0 и 16 release/security tests изучены, но не выдаются за проверку нового клиента. Изменённые исходники собираются на Java 21.

Текущие JUnit XML: 97 тестов; 96 PASS, 1 Windows DPAPI SKIP в Linux. Отдельные 16 Python release/security tests PASS. JavaFX Monocle проверяет всю геометрию Scene на 80/100/125/150/200%, сохранение масштаба, черновиков и файлов, центральный профиль и неизменяемый nickname, масштаб диалогов и один window chrome. Последующие этапы дополнят этот отчёт точными хешами упаковок и compatibility matrix.

Нативная приёмка Windows 11, KDE Wayland/X11, live Tor Direct/Snowflake, внешний Relay и reboot, установщик/restart/rollback — NOT RUN. Монокль, loopback SOCKS harness и Linux CI не считаются этими проверками. Проверки staging используют синтетические аккаунты и временную SQLite; production VPS не затронут.
