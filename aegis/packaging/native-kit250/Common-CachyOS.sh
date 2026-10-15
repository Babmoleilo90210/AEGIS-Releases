#!/usr/bin/env bash
# Sourced only by this kit's wrappers. No downloads, signing, microphone or production profile access.
aegis_native_prepare() {
  umask 077
  aegis_test_kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  aegis_test_image=${1:-"$aegis_test_kit/../AEGIS-2.5.0-CachyOS-x86_64.AppImage"}
  aegis_test_temp=$(mktemp -d -t aegis250-native-kit-XXXXXXXX)
  trap 'rm -rf -- "$aegis_test_temp"' EXIT
  if [[ -d "$aegis_test_image/runtime" ]]; then
    aegis_test_app=$(cd -- "$aegis_test_image" && pwd)
  else
    [[ -f "$aegis_test_image" && -x "$aegis_test_image" ]] || { printf '%s\n' 'Укажите исполняемый AppImage или распакованный AppDir АЕГИС 2.5.0.'; return 2; }
    aegis_test_image=$(realpath -- "$aegis_test_image")
    (cd -- "$aegis_test_temp" && "$aegis_test_image" --appimage-extract >/dev/null)
    aegis_test_app="$aegis_test_temp/squashfs-root"
  fi
  [[ -x "$aegis_test_app/runtime/bin/java" ]] || { printf '%s\n' 'Не найден встроенный Java runtime АЕГИС.'; return 2; }
  unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
  cd -- "$aegis_test_kit"
  aegis_test_cp="$aegis_test_kit/aegis-native-tests.jar:$aegis_test_kit/aegis-ui-tests.jar:$aegis_test_app/app/*"
}
aegis_native_java() {
  "$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError -cp "$aegis_test_cp" "$@"
}
