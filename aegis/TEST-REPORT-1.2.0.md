# АЕГИС 1.2.0 — тестирование клиентского кандидата

productionReady=false. Итоги CI/JUnit/JavaFX и структурных проверок добавляются только после выполнения. Native Windows 11, CachyOS KDE Wayland/X11, owner-signed install/restart/rollback пока NOT_RUN. Friends/receipts/after-read expiry остаются архитектурно заблокированы; их NOT_RUN нельзя заменить unit PASS.

Сохранены старые регрессионные тесты E2EE/TTL/ACK/files/offline/storage/updates. Дополнительные проверки: single Tor attempt, честные состояния fallback/relay probe, block > friends, локальный отзыв, helper без UI/FX, реальная JavaFX регистрация пяти шрифтов с проверенными Cyrillic glyphs, in-window avatar zoom/Escape, bounded responsive geometry. Подробные доказательства находятся в evidence.
