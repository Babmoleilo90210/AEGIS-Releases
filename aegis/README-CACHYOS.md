# АЕГИС 2.0.0 — установка и проверка CachyOS KDE

Сборка для приёмки; `productionReady=false`. Native KDE Wayland/X11, официальный Tor Browser и полный updater E2E ещё NOT_RUN. Headless Linux не заменяет эти платформы.

```bash
sha256sum AEGIS-2.0.0-CachyOS-x86_64.AppImage
chmod +x AEGIS-2.0.0-CachyOS-x86_64.AppImage
./AEGIS-2.0.0-CachyOS-x86_64.AppImage
```

Сравните SHA-256 с доверенным SHA256SUMS до запуска. Java21, libsodium и почтовый Tor входят в AppImage. При отсутствии FUSE возможен штатный `APPIMAGE_EXTRACT_AND_RUN=1 ./AEGIS-2.0.0-CachyOS-x86_64.AppImage`. Не запускайте приложение от root.

Для Safe Web установите системные bubblewrap, slirp4netns и Xephyr, обеспечьте локальный X11/Xwayland и разрешённые user namespaces. Затем получите официальный Linux x86_64 Tor Browser `.tar.xz` и его `.asc`, выберите оба в Safe Web. АЕГИС проверяет OpenPGP до распаковки. Браузер работает во вложенном отдельном дисплее и отдельной сети, без host home/clipboard/AEGIS data. Отсутствие зависимостей останавливает запуск без неограниченного fallback. Работу sandbox/браузера необходимо проверить на реальном KDE; ограничения описаны в SAFE-WEB-2.0.0.md.

Профиль приложения: XDG_DATA_HOME/aegis-app либо ~/.local/share/aegis-app; конфиг — XDG_CONFIG_HOME/aegis/client.properties либо ~/.config/aegis/client.properties. Safe Web хранится отдельно в соседнем aegis-safeweb, не в архиве. Существующие темы/макеты и identity keys сохраняются миграцией с предварительным snapshot. См. MIGRATION-1.5.0-TO-2.0.0.md.

Испытания native-acceptance выполняйте отдельно в KDE Wayland и X11, с реальным DPI и Safe Web, сетевым захватом, миграцией и updater rollback. До этого не считать пакет Stable.

Историческая документация базы 1.5.0 сохранена ниже; её результаты не переносятся на 2.0.0.

---

# АЕГИС 1.5.0 — CachyOS KDE x86_64

Это release candidate. Ubuntu headless/Monocle/CI не заменяют KDE Wayland/X11 acceptance.

Сохраните полный AppImage в пользовательский каталог и проверьте SHA256SUMS:

```bash
sha256sum AEGIS-1.5.0-CachyOS-x86_64.AppImage
chmod +x AEGIS-1.5.0-CachyOS-x86_64.AppImage
./AEGIS-1.5.0-CachyOS-x86_64.AppImage
```

Java21/Tor/libsodium включены; приложение не требует root, системного Tor или Tor Browser. Если FUSE отсутствует, официальный AppImage режим `APPIMAGE_EXTRACT_AND_RUN=1 ./AEGIS-1.5.0-CachyOS-x86_64.AppImage` извлекает только программный payload. Пользовательские plaintext документы не входят в AppImage.

Tor подключается автоматически, затем вставьте .onion и войдите. Собственный torrc явно передаётся через defaults-torrc/-f, системный /etc/tor/torrc не используется. Сетевые listeners только localhost; никаких портов роутера открывать не требуется.

Профиль: XDG_DATA_HOME/aegis-app либо ~/.local/share/aegis-app. Конфиг: XDG_CONFIG_HOME/aegis/client.properties либо ~/.config/aegis/client.properties. Сохранение семидневного входа зависит от доступного Secret Service, иначе работает ручной пароль/offline. Архив имеет отдельный пароль; работает без Tor. Linux каталог700 и файлы600; Explorer/Dolphin не показывают содержимое без расшифрования. Экспорт — явное создание обычного файла.

Проверьте native kit отдельно в KDE Wayland и X11, включая дробный масштаб, темы/шрифты, минимальное окно, restore, Tor/Snowflake и updater. Не запускайте старый binary поверх изменённого профиля для отката — используйте согласованный backup/rollback.
