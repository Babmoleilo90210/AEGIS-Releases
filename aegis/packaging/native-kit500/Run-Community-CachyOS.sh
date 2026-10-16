#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/Common-CachyOS.sh"
[[ $# == 2 && -x "$2/bin/java" ]] || { printf '%s\n' 'Usage: Run-Community-CachyOS.sh APP_DIRECTORY_OR_APPIMAGE JDK21_DIRECTORY'; exit 2; }
aegis_test_jdk=$(cd -- "$2" && pwd)
aegis_native_prepare "$1"
printf '%s\n' 'Локальные JUnit: настоящая SQLite, ACL и подписанный HTTP через loopback fixtures. Это не Tor/native E2E.'
"$aegis_test_jdk/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -Daegis.native.root="$aegis_test_app" -cp "$aegis_test_app/app/*:$aegis_test_kit/staging/*:$aegis_test_kit/aegis-community-tests.jar" org.junit.platform.console.ConsoleLauncher execute --select-package org.securemail.community --select-package org.securemail.worker --select-package org.securemail.client.community --select-class org.securemail.integration.CommunityIntegration500Test --reports-dir "$aegis_test_kit/results-local-community" --disable-banner
