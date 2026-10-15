#!/usr/bin/env bash
set -euo pipefail
if (( $# > 2 )) || [[ ${2:-} != '' && ${2:-} != '--test-microphone' ]]; then
  printf '%s\n' 'Usage: Run-Voice-CachyOS.sh AppImage|AppDir [--test-microphone]'; exit 2
fi
aegis_test_microphone=${2:-}
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
aegis_native_prepare "${1:-}"
if [[ "$aegis_test_microphone" == '--test-microphone' ]]; then
  printf '%s\n' 'Явно запрошена локальная проверка уровня микрофона до 15 секунд. Записи, воспроизведения и передачи нет.'
  aegis_native_java org.securemail.client.security.VoiceNativeAcceptanceMain "$aegis_test_app" --test-microphone
else
  aegis_native_java org.securemail.client.security.VoiceNativeAcceptanceMain "$aegis_test_app"
fi
printf '%s\n' 'JSON содержит локальные результаты и имена устройств. Двухмашинная/60-минутная голосовая приёмка остаётся NOT_RUN.'
