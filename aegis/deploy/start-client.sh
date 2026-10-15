#!/usr/bin/env bash
# Launcher for the extracted Linux bundle. No installer, downloads or firewall changes.
set -euo pipefail
umask 077
ulimit -c 0
if [[ -z "${JAVA_HOME:-}" && -x /usr/lib/jvm/java-21-openjdk/bin/java ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
fi
aegis_dir=$(dirname -- "$(readlink -f -- "$0")")
exec "$aegis_dir/client/bin/client-ui" "$@"
