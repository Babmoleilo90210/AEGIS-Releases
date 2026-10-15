#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 1 ]] || { echo 'sudo ./rollback-server.sh /var/backups/aegis/upgrade-...'; exit 1; }
backup=$(realpath -- "$1")
[[ "$backup" == /var/backups/aegis/upgrade-* && -f "$backup/relay.db" && -d "$backup/relay" ]] || { echo 'Неверная резервная копия'; exit 1; }
systemctl stop aegis-relay.service
mv /opt/aegis/relay "/opt/aegis/relay.failed.$(date -u +%Y%m%dT%H%M%S)"
cp -a "$backup/relay" /opt/aegis/relay
cp -a "$backup/config/." /etc/aegis/
database=$(cat "$backup/database-path")
install -o aegis-relay -g aegis-relay -m 600 "$backup/relay.db" "$database"
chown root:aegis-relay /etc/aegis /etc/aegis/relay.properties
chmod 750 /etc/aegis
chmod 640 /etc/aegis/relay.properties
systemctl start aegis-relay.service
/usr/local/bin/aegis-server doctor
