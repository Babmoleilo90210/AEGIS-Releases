#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
[[ $EUID == 0 ]] || { echo 'Запустите sudo ./upgrade-server.sh' >&2; exit 1; }
[[ -d /opt/aegis/relay && -f /etc/aegis/relay.properties ]] || { echo 'Сначала установите сервер'; exit 1; }
install -d -m 700 /var/backups/aegis
backup=$(mktemp -d /var/backups/aegis/upgrade-XXXXXXXX)
systemctl stop aegis-relay.service
trap 'echo "Обновление не завершено. Резервная копия: $backup. Откат: sudo ./rollback-server.sh $backup" >&2' ERR
python3 - "$backup" <<'PY'
import pathlib,sqlite3,sys,shutil
backup=pathlib.Path(sys.argv[1]);p=pathlib.Path('/etc/aegis/relay.properties');settings=dict(l.split('=',1) for l in p.read_text().splitlines() if '=' in l and not l.lstrip().startswith('#'))
source=sqlite3.connect(settings['databasePath']);target=sqlite3.connect(backup/'relay.db');source.backup(target);target.close();source.close();(backup/'database-path').write_text(settings['databasePath'])
shutil.copytree('/etc/aegis',backup/'config');shutil.copytree('/opt/aegis/relay',backup/'relay');shutil.copytree('/etc/tor',backup/'tor-config');shutil.copytree('/var/lib/tor',backup/'tor-state',symlinks=True)
PY
# Explicit 0.2 migration requested by the project owner; existing 0.2 policy is preserved.
python3 - <<'PYUP'
from pathlib import Path
p=Path('/etc/aegis/relay.properties');text=p.read_text()
if not any(line.strip().startswith('registrationMode=') for line in text.splitlines()):
 p.write_text(text.rstrip()+'\n# AEGIS 0.2 registration policy migration\nregistrationMode=open\nmaxUsers=32\n')
PYUP
./install-server.sh --upgrade
printf 'Обновление завершено. Резервная копия: %s\n' "$backup"
