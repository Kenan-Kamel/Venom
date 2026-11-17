#!/usr/bin/env bash
set -euo pipefail

#───────────────────────────────────────────────────────────
#  Install the 6 analysis tools that require system packages
#
#  These tools need sudo. Run as:
#    sudo bash scripts/install-tools.sh
#
#  Or install individually:
#    sudo bash scripts/install-tools.sh coccinelle
#    sudo bash scripts/install-tools.sh smatch ikos
#───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { printf "  ${GREEN}[OK]${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}[--]${NC}  %s\n" "$1"; }
info() { printf "  ${YELLOW}[..]${NC}  %s\n" "$1"; }

TOOLS="${@:-coccinelle smatch frama-c goblint ikos svf}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

install_coccinelle() {
    info "Installing Coccinelle (spatch)..."
    apt-get install -y -qq coccinelle 2>/dev/null && ok "Coccinelle" && return
    fail "Coccinelle — try: sudo apt-get install coccinelle"
}

install_smatch() {
    info "Installing Smatch..."
    apt-get install -y -qq libsqlite3-dev libssl-dev libxml2-dev 2>/dev/null || true
    if ! command -v smatch &>/dev/null; then
        local build_dir="/tmp/smatch-build-$$"
        git clone --depth 1 https://repo.or.cz/smatch.git "$build_dir" 2>/dev/null
        cd "$build_dir"
        make -j"$(nproc)" PREFIX="$INSTALL_PREFIX" 2>/dev/null
        make install PREFIX="$INSTALL_PREFIX" 2>/dev/null
        cd /
        rm -rf "$build_dir"
    fi
    command -v smatch &>/dev/null && ok "Smatch" || fail "Smatch"
}

install_frama_c() {
    info "Installing Frama-C..."
    # Try apt first
    apt-get install -y -qq frama-c 2>/dev/null && ok "Frama-C" && return
    # Fall back to opam
    if command -v opam &>/dev/null; then
        opam install frama-c -y 2>/dev/null && ok "Frama-C (opam)" && return
    fi
    # Install opam and then frama-c
    apt-get install -y -qq opam ocaml 2>/dev/null || true
    if command -v opam &>/dev/null; then
        opam init --bare -y 2>/dev/null || true
        opam install frama-c -y 2>/dev/null && ok "Frama-C (opam)" && return
    fi
    fail "Frama-C — try: opam install frama-c"
}

install_goblint() {
    info "Installing Goblint..."
    if command -v opam &>/dev/null; then
        opam install goblint -y 2>/dev/null && ok "Goblint" && return
    fi
    apt-get install -y -qq opam ocaml 2>/dev/null || true
    if command -v opam &>/dev/null; then
        opam init --bare -y 2>/dev/null || true
        opam install goblint -y 2>/dev/null && ok "Goblint" && return
    fi
    fail "Goblint — try: opam install goblint"
}

install_ikos() {
    info "Installing IKOS..."
    apt-get install -y -qq cmake llvm-dev libboost-all-dev libgmp-dev \
        libsqlite3-dev libtbb-dev libz-dev 2>/dev/null || true
    if ! command -v ikos &>/dev/null; then
        local build_dir="/tmp/ikos-build-$$"
        git clone --depth 1 https://github.com/NASA-SW-VnV/ikos.git "$build_dir" 2>/dev/null
        mkdir -p "$build_dir/build"
        cd "$build_dir/build"
        cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
            -DLLVM_CONFIG_EXECUTABLE="$(which llvm-config || which llvm-config-21)" 2>/dev/null
        make -j"$(nproc)" 2>/dev/null
        make install 2>/dev/null
        cd /
        rm -rf "$build_dir"
    fi
    command -v ikos &>/dev/null && ok "IKOS" || fail "IKOS — complex build, see https://github.com/NASA-SW-VnV/ikos"
}

install_svf() {
    info "Installing SVF (Saber)..."
    apt-get install -y -qq cmake 2>/dev/null || true
    if ! command -v saber &>/dev/null && ! command -v wpa &>/dev/null; then
        local build_dir="/tmp/svf-build-$$"
        git clone --depth 1 https://github.com/SVF-tools/SVF.git "$build_dir" 2>/dev/null
        cd "$build_dir"
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" 2>/dev/null
        make -j"$(nproc)" 2>/dev/null
        make install 2>/dev/null
        cd /
        rm -rf "$build_dir"
    fi
    (command -v saber &>/dev/null || command -v wpa &>/dev/null) && ok "SVF/Saber" || fail "SVF — see https://github.com/SVF-tools/SVF"
}

echo "════════════════════════════════════════════════════"
echo "  Venom — Installing Missing Analysis Tools"
echo "════════════════════════════════════════════════════"
echo ""

for tool in $TOOLS; do
    case "$tool" in
        coccinelle|spatch)  install_coccinelle ;;
        smatch)             install_smatch ;;
        frama-c|frama_c)    install_frama_c ;;
        goblint)            install_goblint ;;
        ikos)               install_ikos ;;
        svf|saber|saber-svf) install_svf ;;
        *) echo "Unknown tool: $tool" ;;
    esac
done

echo ""
echo "════════════════════════════════════════════════════"
echo "  Verify with: python3 -m venom --tui → Install Tools"
echo "════════════════════════════════════════════════════"
