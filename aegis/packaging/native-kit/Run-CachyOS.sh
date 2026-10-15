#!/usr/bin/env bash
set -euo pipefail
umask 077
aegis_test_kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
aegis_test_image=${1:-"$aegis_test_kit/../AEGIS-1.0.0-CachyOS-x86_64.AppImage"}
if [[ ! -f "$aegis_test_image" && ! -d "$aegis_test_image/runtime" ]]; then
  printf '%s\n' 'Укажите путь к AppImage АЕГИС:'
  IFS= read -r aegis_test_image
fi
aegis_test_temp=$(mktemp -d -t aegis-native-kit-XXXXXXXX)
trap 'rm -rf -- "$aegis_test_temp"' EXIT
if [[ -d "$aegis_test_image/runtime" ]]; then
  aegis_test_app=$(cd -- "$aegis_test_image" && pwd)
else
  aegis_test_image=$(realpath -- "$aegis_test_image")
  [[ -x "$aegis_test_image" ]] || { printf '%s\n' 'Сначала дайте AppImage право запуска: chmod +x <AppImage>'; exit 2; }
  (cd -- "$aegis_test_temp" && "$aegis_test_image" --appimage-extract >/dev/null)
  aegis_test_app="$aegis_test_temp/squashfs-root"
fi
[[ -x "$aegis_test_app/runtime/bin/java" ]] || { printf '%s\n' 'Не найден встроенный runtime АЕГИС'; exit 2; }
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
cd -- "$aegis_test_kit"
printf '%s\n' 'Проверка АЕГИС на CachyOS. Будут открываться тестовые окна.'
"$aegis_test_app/runtime/bin/java" -Xmx768m -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError \
  -cp "$aegis_test_kit/aegis-native-tests.jar:$aegis_test_app/app/*" \
  org.securemail.client.security.NativeAcceptanceMain "$aegis_test_app" "$aegis_test_kit" --gui
printf '%s\n' 'Отчёт AEGIS-native-Linux-*.json сохранён рядом с этим файлом.' \
  'В отчёте нет паролей и ключей. Автоматической отправки нет.'
