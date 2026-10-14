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

Профиль: XDG_DATA_HOME/aegis либо ~/.local/share/aegis. Сохранение семидневного входа зависит от доступного Secret Service, иначе работает ручной пароль/offline. Архив имеет отдельный пароль; работает без Tor. Linux каталог700 и файлы600; Explorer/Dolphin не показывают содержимое без расшифрования. Экспорт — явное создание обычного файла.

Проверьте native kit отдельно в KDE Wayland и X11, включая дробный масштаб, темы/шрифты, минимальное окно, restore, Tor/Snowflake и updater. Не запускайте старый binary поверх изменённого профиля для отката — используйте согласованный backup/rollback.
