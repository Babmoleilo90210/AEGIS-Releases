#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
fail(){ printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || fail 'Запустите sudo ./install-server.sh'
. /etc/os-release
[[ "$ID" == debian && "$VERSION_ID" == 13 && "$(uname -m)" == x86_64 ]] || fail 'Требуется Debian 13 x86_64'
[[ -f relay/lib/relay-server-0.3.0.jar && -x relay/runtime/bin/java ]] || fail 'Распакуйте полный серверный ZIP'
if [[ -e /opt/aegis/relay && ${1:-} != --upgrade && -e /etc/aegis/relay.properties ]]; then
  printf '%s\n' 'Найдена установка. Для обновления используйте upgrade-server.sh.'
  /usr/local/bin/aegis-server doctor
  exit $?
fi
printf '%s\n' 'Устанавливаются только Tor, UFW, Python и SQLite. Java 21 входит в пакет.' 'Загрузчик, разделы диска и DNS не изменяются.'
apt-get update
apt-get install -y --no-install-recommends tor ufw python3 sqlite3 ca-certificates
getent group aegis-relay >/dev/null || groupadd --system aegis-relay
id aegis-relay >/dev/null 2>&1 || useradd --system --gid aegis-relay --home-dir /var/lib/aegis-relay --shell /usr/sbin/nologin aegis-relay
install -d -o root -g root -m 755 /opt/aegis
install -d -o root -g aegis-relay -m 750 /etc/aegis
install -d -o aegis-relay -g aegis-relay -m 700 /var/lib/aegis-relay
systemctl stop aegis-relay.service 2>/dev/null || true
stage=$(mktemp -d /opt/aegis/relay.new.XXXXXXXX)
cp -a relay/. "$stage/"
chown -R root:root "$stage"
chmod 755 "$stage"
if [[ -e /opt/aegis/relay ]]; then mv /opt/aegis/relay "/opt/aegis/relay.previous.$(date -u +%Y%m%dT%H%M%S)"; fi
mv "$stage" /opt/aegis/relay
if [[ ! -e /etc/aegis/relay.properties ]]; then install -o root -g aegis-relay -m 640 relay.properties /etc/aegis/relay.properties; fi
chown root:aegis-relay /etc/aegis /etc/aegis/relay.properties
chmod 750 /etc/aegis
chmod 640 /etc/aegis/relay.properties
runuser -u aegis-relay -- /opt/aegis/relay/bin/relay-server version /etc/aegis/relay.properties || fail 'Сервис не может прочитать конфигурацию. Проверьте права /etc/aegis.'
install -m 755 aegis-server.py /usr/local/bin/aegis-server
install -d -m 755 /opt/aegis/tor
install -m 755 tor/lyrebird /opt/aegis/tor/lyrebird
install -m 644 tor/snowflake-bridges.txt /opt/aegis/tor/snowflake-bridges.txt
install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor/aegis-relay
/usr/local/bin/aegis-server configure-tor
if [[ -d /etc/apparmor.d/local && -f /etc/apparmor.d/system_tor ]]; then
  touch /etc/apparmor.d/local/system_tor
  if ! grep -qF '/opt/aegis/tor/lyrebird' /etc/apparmor.d/local/system_tor; then
    printf '\n# AEGIS bundled Snowflake transport\n/opt/aegis/tor/lyrebird ixr,\n/opt/aegis/tor/** r,\n' >> /etc/apparmor.d/local/system_tor
  fi
  if command -v apparmor_parser >/dev/null; then apparmor_parser -r /etc/apparmor.d/system_tor; fi
fi
runuser -u debian-tor -- /usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --verify-config || fail 'Конфигурация Tor не прошла проверку'
install -m 644 aegis-relay.service /etc/systemd/system/aegis-relay.service
install -m 644 aegis-tor-bootstrap.service /etc/systemd/system/aegis-tor-bootstrap.service
systemctl daemon-reload
ssh_port=${AEGIS_SSH_PORT:-}
if [[ -z "$ssh_port" && -n ${SSH_CONNECTION:-} ]]; then read -r _ _ _ ssh_port <<< "$SSH_CONNECTION"; fi
if [[ -z "$ssh_port" ]]; then ssh_port=$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port"{print $2;exit}'); fi
[[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1 && "$ssh_port" -le 65535 ]] || fail 'Не удалось определить SSH порт. Повторите с AEGIS_SSH_PORT=<порт>; firewall пока не изменён.'
ufw allow "$ssh_port/tcp" comment 'SSH access preserved by AEGIS installer'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
systemctl enable --now tor@default.service aegis-relay.service
systemctl restart tor@default.service
systemctl enable aegis-tor-bootstrap.service
/usr/local/bin/aegis-server bootstrap
/usr/local/bin/aegis-server doctor
/usr/local/bin/aegis-server onion
