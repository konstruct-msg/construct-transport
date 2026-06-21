#!/bin/bash
# build_ios.sh
# Builds construct-transport as ConstructTransport.xcframework and generates the
# UniFFI Swift bindings for the iOS/macOS app. Mirrors construct-engine's
# build_engine.sh.
#
# USAGE:
#   ./build_ios.sh              # iOS device + Simulator (default)
#   ./build_ios.sh --ios        # iOS device only (arm64)
#   ./build_ios.sh --sim        # iOS Simulator only (arm64 + x86_64 fat)
#   ./build_ios.sh --mac        # macOS native (arm64)
#   ./build_ios.sh --bindings   # regenerate Swift bindings only
#   ./build_ios.sh --clean      # cargo clean first
#   ./build_ios.sh --debug      # debug profile
#
# OUTPUT (into ../construct-messenger):
#   ConstructTransport.xcframework/                 — add to Xcode
#   ConstructMessenger/construct_transport.swift    — UniFFI Swift bindings
#
# How it links: ConstructTransport.xcframework is a SEPARATE static lib added
# alongside ConstructCore.xcframework and ConstructEngine.xcframework. It is NOT
# merged into libconstruct_core.a — each UniFFI crate gets its own FFI module
# (ConstructTransportFFI) so the RustBuffer/runtime types never collide.

set -e
set -o pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅${NC} $1"; }
fail() { echo -e "${RED}❌  $1${NC}"; exit 1; }
info() { echo -e "${BLUE}▸${NC}  $1"; }
warn() { echo -e "${YELLOW}⚠️${NC}   $1"; }
hdr()  { echo -e "\n${BOLD}━━━  $1  ━━━${NC}"; }

# ── Paths ─────────────────────────────────────────────────────────────────────
TRANSPORT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MESSENGER_ROOT="$(cd "$TRANSPORT_ROOT/../construct-messenger" 2>/dev/null && pwd)" || \
  fail "construct-messenger not found next to construct-transport."
XCFW_DEST="$MESSENGER_ROOT/ConstructTransport.xcframework"
SWIFT_DEST="$MESSENGER_ROOT/ConstructMessenger"
TMP="$TRANSPORT_ROOT/.build_tmp"
LIB="libconstruct_transport"

# ── Args ──────────────────────────────────────────────────────────────────────
BUILD_IOS=false; BUILD_SIM=false; BUILD_MAC=false
HAS_PLATFORM_FLAG=false; BINDINGS_ONLY=false; DO_CLEAN=false
PROFILE="release"; CARGO_FLAGS="--release"

for arg in "$@"; do
  case "$arg" in
    --ios)      BUILD_IOS=true; HAS_PLATFORM_FLAG=true ;;
    --sim)      BUILD_SIM=true; HAS_PLATFORM_FLAG=true ;;
    --mac)      BUILD_MAC=true; HAS_PLATFORM_FLAG=true ;;
    --bindings) BINDINGS_ONLY=true ;;
    --clean)    DO_CLEAN=true ;;
    --debug)    PROFILE="debug"; CARGO_FLAGS="" ;;
    -h|--help)
      echo "Usage: $0 [--ios] [--sim] [--mac] [--bindings] [--clean] [--debug]"
      echo "  Platform flags are additive. No flag → iOS device + Simulator."
      exit 0 ;;
    *) warn "Unknown argument: $arg" ;;
  esac
done

# Default (no platform flag): iOS device + Simulator (the app's targets).
if ! $HAS_PLATFORM_FLAG; then
  BUILD_IOS=true
  BUILD_SIM=true
fi

# ── Dependency checks ─────────────────────────────────────────────────────────
hdr "Dependencies"
command -v cargo   &>/dev/null || fail "cargo not installed (https://rustup.rs)"
command -v libtool &>/dev/null || fail "libtool not found (Xcode Command Line Tools)"
# Prefer an installed uniffi-bindgen (matches construct-engine, version 0.30),
# else fall back to the in-crate bin (version-locked to our uniffi dep).
if command -v uniffi-bindgen &>/dev/null; then
  BINDGEN=(uniffi-bindgen)
else
  BINDGEN=(cargo run --quiet --bin uniffi-bindgen --)
fi
ok "cargo $(cargo --version | cut -d' ' -f2) | bindgen: ${BINDGEN[*]} | libtool"

ensure_target() {
  rustup target list --installed 2>/dev/null | grep -q "^$1$" || {
    info "Adding rust target $1…"
    rustup target add "$1" 2>&1 | tail -2
  }
}

if $DO_CLEAN; then
  hdr "Cargo clean"; (cd "$TRANSPORT_ROOT" && cargo clean); ok "cleaned"
fi
rm -rf "$TMP" && mkdir -p "$TMP"

# ── UniFFI Swift bindings ─────────────────────────────────────────────────────
# uniffi-bindgen needs a dylib (not .a) to extract metadata. Build a host dylib
# only for generation; it is not part of the xcframework.
generate_bindings() {
  hdr "UniFFI Swift bindings"
  cd "$TRANSPORT_ROOT"
  local host_dylib="$TRANSPORT_ROOT/target/debug/$LIB.dylib"
  if [ ! -f "$host_dylib" ]; then
    info "Building host dylib for UniFFI metadata…"
    cargo build --lib 2>&1 | grep -E "^error|Finished" || true
  fi
  [ -f "$host_dylib" ] || fail "host dylib not found: $host_dylib"

  "${BINDGEN[@]}" generate \
    --library "$host_dylib" \
    --language swift \
    --out-dir "$TMP/bindings" 2>&1 | grep -vE "swiftformat|Warning: Unable" || true
  [ -f "$TMP/bindings/construct_transport.swift" ] || fail "bindgen produced no swift"

  cp "$TMP/bindings/construct_transport.swift" "$SWIFT_DEST/construct_transport.swift"
  ok "construct_transport.swift → $SWIFT_DEST"

  cp "$TMP/bindings/${LIB#lib}FFI.h" "$TMP/construct_transportFFI.h" 2>/dev/null \
    || cp "$TMP/bindings/construct_transportFFI.h" "$TMP/construct_transportFFI.h"
  if [ -f "$TMP/bindings/construct_transportFFI.modulemap" ]; then
    cp "$TMP/bindings/construct_transportFFI.modulemap" "$TMP/module.modulemap"
  else
    # Module name must match the generated Swift `import construct_transportFFI`.
    cat > "$TMP/module.modulemap" << 'EOF'
module construct_transportFFI {
    umbrella header "construct_transportFFI.h"
    export *
}
EOF
  fi
  ok "FFI headers saved"
}

# ── One target ────────────────────────────────────────────────────────────────
build_target() {
  local arch="$1"
  ensure_target "$arch"
  info "Building $arch ($PROFILE)…"
  cd "$TRANSPORT_ROOT"
  local deploy_env=""
  case "$arch" in
    aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios)
      deploy_env="IPHONEOS_DEPLOYMENT_TARGET=18.0" ;;
    aarch64-apple-darwin) deploy_env="MACOSX_DEPLOYMENT_TARGET=15.0" ;;
  esac

  local log="$TMP/cargo_${arch//\//_}.log"
  env $deploy_env cargo build --lib --target "$arch" $CARGO_FLAGS 2>&1 \
    | tee "$log" \
    | grep -E "^error\[|^error:|Finished" ; local st=("${PIPESTATUS[@]}") ; true
  [ "${st[0]}" -eq 0 ] || { tail -20 "$log"; fail "cargo build failed for $arch"; }

  local artifact="$TRANSPORT_ROOT/target/$arch/$PROFILE/$LIB.a"
  [ -f "$artifact" ] || fail "artifact missing: $artifact"
  ok "Built $arch ($(du -sh "$artifact" | cut -f1))"
}

# ── Run ───────────────────────────────────────────────────────────────────────
generate_bindings
$BINDINGS_ONLY && { rm -rf "$TMP"; hdr "Done (bindings only)"; exit 0; }

hdr "Static libraries"
$BUILD_IOS && build_target "aarch64-apple-ios"
if $BUILD_SIM; then
  build_target "aarch64-apple-ios-sim"
  build_target "x86_64-apple-ios"
fi
$BUILD_MAC && build_target "aarch64-apple-darwin"

# ── Assemble slices ───────────────────────────────────────────────────────────
hdr "Assembling ConstructTransport.xcframework"
make_headers_dir() {
  local dir="$1/Headers"; mkdir -p "$dir"
  cp "$TMP/construct_transportFFI.h" "$dir/"
  cp "$TMP/module.modulemap"         "$dir/"
}
XCARGS=()

if $BUILD_IOS; then
  d="$TMP/slice_ios"; mkdir -p "$d"
  cp "$TRANSPORT_ROOT/target/aarch64-apple-ios/$PROFILE/$LIB.a" "$d/$LIB.a"
  make_headers_dir "$d"
  XCARGS+=(-library "$d/$LIB.a" -headers "$d/Headers")
fi
if $BUILD_SIM; then
  d="$TMP/slice_sim"; mkdir -p "$d"
  lipo -create \
    "$TRANSPORT_ROOT/target/aarch64-apple-ios-sim/$PROFILE/$LIB.a" \
    "$TRANSPORT_ROOT/target/x86_64-apple-ios/$PROFILE/$LIB.a" \
    -output "$d/$LIB.a"
  make_headers_dir "$d"
  XCARGS+=(-library "$d/$LIB.a" -headers "$d/Headers")
fi
if $BUILD_MAC; then
  d="$TMP/slice_mac"; mkdir -p "$d"
  cp "$TRANSPORT_ROOT/target/aarch64-apple-darwin/$PROFILE/$LIB.a" "$d/$LIB.a"
  make_headers_dir "$d"
  XCARGS+=(-library "$d/$LIB.a" -headers "$d/Headers")
fi
[ "${#XCARGS[@]}" -gt 0 ] || fail "no slices to assemble — check platform flags."

rm -rf "$XCFW_DEST"
xcodebuild -create-xcframework "${XCARGS[@]}" -output "$XCFW_DEST" 2>&1 \
  | grep -v "^note:" || true
[ -f "$XCFW_DEST/Info.plist" ] || fail "xcodebuild -create-xcframework failed"
ok "ConstructTransport.xcframework → $XCFW_DEST"

rm -rf "$TMP"
echo ""
echo -e "${BOLD}Done.${NC}"
echo -e "  xcframework:    ${GREEN}$XCFW_DEST${NC}"
echo -e "  Swift bindings: ${GREEN}$SWIFT_DEST/construct_transport.swift${NC}"
echo ""
echo -e "${BOLD}Next in Xcode:${NC}"
echo "  1. Add ConstructTransport.xcframework to the app target"
echo "  2. Ensure construct_transport.swift is in the target"
echo "  3. ⌘⇧K Clean Build Folder, then build"
