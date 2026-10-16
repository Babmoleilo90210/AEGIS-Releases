#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
aegis_native_prepare "${1:-}"
for aegis_test_mode in interface archive vzor-glas; do
  aegis_native_java org.securemail.ui.AppearanceNativeLauncher500 "$aegis_test_app" "$aegis_test_mode"
done
printf '%s\n' 'Синтетические снимки: build/ui500-screenshots, build/archive-menu500.' \
  'Эти UI fixture не запускают официальный Tor Browser и не открывают микрофон; browser/network/voice acceptance отдельно.'
