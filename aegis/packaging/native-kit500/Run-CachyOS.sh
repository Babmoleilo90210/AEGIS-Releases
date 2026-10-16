#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
aegis_native_prepare "${1:-}"
printf '%s\n' 'Локальная проверка АЕГИС 5.0.0: будут открываться синтетические тестовые окна.'
aegis_native_java org.securemail.client.security.NativeAcceptanceMain "$aegis_test_app" "$aegis_test_kit" --gui
printf '%s\n' 'Отчёт AEGIS-native-Linux-*.json сохранён в native-acceptance. Полная нативная приёмка выполняется отдельно.'
