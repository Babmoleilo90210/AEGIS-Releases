#!/usr/bin/env bash
set -euo pipefail
umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v tor >/dev/null
install -d -m 700 "$HOME/.config/systemd/user" "$HOME/.local/share/aegis-tor"
: > "$HOME/.local/share/aegis-tor/defaults-torrc"
: > "$HOME/.local/share/aegis-tor/torrc"
install -m 600 "$script_dir/aegis-tor.service" "$HOME/.config/systemd/user/aegis-tor.service"
systemctl --user daemon-reload
systemctl --user enable --now aegis-tor.service
printf '%s\n' 'Dedicated Tor started. No firewall settings were changed.'
