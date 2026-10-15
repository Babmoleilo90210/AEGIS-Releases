#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
aegis_native_prepare "${1:-}"
for aegis_test_mode in refinement responsive vzor-glas; do
  aegis_native_java org.securemail.ui.AppearanceNativeLauncher "$aegis_test_app" "$aegis_test_mode"
done
printf '%s\n' 'Синтетические снимки: build/ui250-refinement-screenshots, build/vzor-glas250-screenshots.' \
  'Эти UI fixture не запускают официальный Tor Browser и не открывают микрофон; browser/network/voice acceptance отдельно.'
