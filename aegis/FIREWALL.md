# Ограничение сети и проверка localhost

АЕГИС сам не меняет firewall клиента. TorTransport разрешает только числовой loopback SOCKS и onion destination; при недоступности своего Tor сеть приложения блокируется. Это ограничение кода, а не независимый kernel kill switch.

В 0.2.0 Tor — дочерний процесс клиента. **Не применяйте старый UID/cgroup-запрет Internet ко всему приложению:** он заблокирует также Tor и Snowflake. Старый рецепт с отдельным системным Tor не соответствует portable-сборке 0.2.0. Отдельный проверенный cgroup launcher для CachyOS в эту поставку не включён.

Проверка слушающих портов CachyOS (read-only):

```sh
ss -ltnp | rg '19050|19051|19120'
```

Допустим только 127.0.0.1. Java не должен слушать публичный интерфейс. Встроенный Tor должен иметь исходящий доступ к Tor-сети; при Snowflake — также broker/CDN, STUN и WebRTC peers.

На Windows независимое правило можно вручную привязать именно к `runtime\bin\javaw.exe`, сохраняя разрешение для `tor\tor.exe` и Lyrebird. Не блокируйте Java и Tor одним правилом по каталогу. Программа никаких таких правил не создаёт; после правила отдельно проверьте localhost и реальную блокировку Internet. Изменение пути portable-пакета потребует обновления правила. Не отключайте Firewall, Defender или SmartScreen.

Сервер: installer задаёт UFW deny incoming, allow outgoing, разрешает определённый SSH-порт и не открывает 19110. Независимый systemd-фильтр relay: `IPAddressDeny=any`, `IPAddressAllow=localhost`; системный Tor находится в другом unit. Проверка:

```sh
sudo systemctl show aegis-relay -p IPAddressDeny -p IPAddressAllow
sudo ufw status verbose
sudo ss -ltnp | grep ':19110'
```

Эти команды диагностики ничего не меняют. У системы должны работать cgroup/BPF-ограничения systemd: предупреждение об их отсутствии означает, что на этот дополнительный слой полагаться нельзя. Loopback bind в самом Java relay остаётся обязательным независимо от firewall.
