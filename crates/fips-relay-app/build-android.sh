#!/usr/bin/env bash
# Build the shared engine first; never package a stale native library by accident.
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$APP_DIR/../.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${ANDROID_HOME:?Set ANDROID_HOME to an installed Android SDK (platform 36)}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
export NDK_HOME="$ANDROID_NDK_HOME"
[[ -d "$ANDROID_NDK_HOME" ]] || { echo "Install Android NDK 28.2.13676358" >&2; exit 1; }
cd "$REPO_DIR"
cargo ndk -t arm64-v8a --platform 30 -o "$APP_DIR/android/app/src/main/jniLibs" \
  build -p fips-relay-app --release --locked
gradle -p "$APP_DIR/android" :app:assembleDebug :app:lintDebug --console=plain
echo "Built $APP_DIR/android/app/build/outputs/apk/debug/app-debug.apk"
