#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
[[ $# == 2 && -x "$2/bin/java" ]] || { printf '%s\n' 'Usage: Run-Community-UI-CachyOS.sh APP_DIRECTORY_OR_APPIMAGE JDK21_DIRECTORY'; exit 2; }
aegis_test_jdk=$(cd -- "$2" && pwd)
aegis_native_prepare "$1"
"$aegis_test_jdk/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -Daegis.home="$aegis_test_app" -cp "$aegis_test_app/app/*:$aegis_test_kit/staging/*:$aegis_test_kit/aegis-ui-tests.jar" org.securemail.ui.AppearanceNativeLauncher500 "$aegis_test_app" community-flow
