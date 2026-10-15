#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
inputs=${AEGIS_BUILD_INPUTS:-"$PWD/.build-inputs"}
out=${AEGIS_OUTPUT:-"$PWD/dist"}
# Source-build downloads only. No installed relay is touched.
python3 packaging/fetch-client-tools.py "$inputs"
python3 packaging/fetch-dependencies.py "$inputs"
python3 packaging/prepare-inputs.py "$inputs"
export JAVA_HOME="$inputs/assets/jdk-linux/zulu21.52.203-ca-jdk21.0.12.1-linux_x64"
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew test :client-ui:messengerSmoke :client-ui:pickerSmoke :client-ui:clientUiRegressionSmoke :client-ui:stageApp -PtargetPlatform=linux
./gradlew :client-ui:stageApp -PtargetPlatform=win
export NSISDIR="$inputs/nsis/usr/share/nsis"
python3 packaging/package-clients.py --inputs "$inputs" --out "$out" \
 --mingw "$inputs/assets/mingw/llvm-mingw-20260922-ucrt-ubuntu-22.04-x86_64/bin" \
 --makensis "$inputs/nsis/usr/bin/makensis" \
 --appimagetool "$inputs/appimagetool-x86_64.AppImage" --appimage-runtime "$inputs/runtime-x86_64"
python3 packaging/archive-clients.py "$out"

