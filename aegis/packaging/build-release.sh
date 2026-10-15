#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
root=$PWD
inputs=${AEGIS_BUILD_INPUTS:-"$root/.build-inputs"}
out=${AEGIS_OUTPUT:-"$root/dist"}
python3 packaging/fetch-dependencies.py "$inputs"
python3 packaging/prepare-inputs.py "$inputs"
python3 packaging/icons.py
export JAVA_HOME="$inputs/assets/jdk-linux/zulu21.52.203-ca-jdk21.0.12.1-linux_x64"
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew build :client-ui:stageApp :relay-server:installDist -PtargetPlatform=linux
./gradlew :client-ui:stageApp -PtargetPlatform=win
./gradlew :client-ui:messengerSmoke -PtargetPlatform=linux
chmod +x "$inputs/appimagetool-x86_64.AppImage"
mkdir -p "$inputs/appimagetool"
(cd "$inputs/appimagetool" && ../appimagetool-x86_64.AppImage --appimage-extract >/dev/null)
python3 packaging/package.py "$inputs" "$out" "$inputs/appimagetool/squashfs-root/AppRun"
python3 packaging/archive-source.py "$out"
