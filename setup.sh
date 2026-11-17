#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  Venom — Static Analyzer Suite Setup"
echo "  16 analyzers from the Venom proposal"
echo "============================================"
echo ""

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG=apt
elif command -v dnf &>/dev/null; then
    PKG=dnf
elif command -v pacman &>/dev/null; then
    PKG=pacman
elif command -v brew &>/dev/null; then
    PKG=brew
else
    echo "ERROR: No supported package manager found (apt, dnf, pacman, brew)"
    exit 1
fi

echo "Package manager: $PKG"
echo ""

# ── Helper ──
try_install() {
    local label=$1; shift
    echo "  Installing $label..."
    if "$@" &>/dev/null; then
        echo "    OK"
    else
        echo "    FAILED — install manually"
    fi
}

# ── Phase 1: System packages ──
echo "═══ Phase 1: System Packages ═══"
echo ""

if [ "$PKG" = "apt" ]; then
    sudo apt-get update -qq 2>/dev/null || true

    echo "[1/16] GCC (with -fanalyzer)"
    try_install "gcc g++" sudo apt-get install -y -qq gcc g++

    echo "[2/16] Clang Static Analyzer"
    try_install "clang clang-tools" sudo apt-get install -y -qq clang clang-tools

    echo "[3/16] Cppcheck"
    try_install "cppcheck" sudo apt-get install -y -qq cppcheck

    echo "[4/16] clang-tidy"
    try_install "clang-tidy" sudo apt-get install -y -qq clang-tidy

    echo "[5/16] Sparse"
    try_install "sparse" sudo apt-get install -y -qq sparse

    echo "[6/16] Coccinelle (spatch)"
    try_install "coccinelle" sudo apt-get install -y -qq coccinelle

    echo "[7/16] Smatch"
    echo "  Smatch must be built from source:"
    echo "    git clone https://repo.or.cz/smatch.git && cd smatch && make && sudo make install"
    echo "    (skipping)"

    echo "[8/16] Frama-C"
    echo "  Install via opam (OCaml package manager):"
    echo "    opam install frama-c"
    echo "  Or: sudo apt-get install -y frama-c"
    try_install "frama-c" sudo apt-get install -y -qq frama-c

    echo "[9/16] IKOS"
    echo "  IKOS must be built from source (requires LLVM, cmake):"
    echo "    https://github.com/NASA-SW-VnV/ikos"
    echo "    (skipping — see README)"

    echo "[10/16] Goblint"
    echo "  Install via opam:"
    echo "    opam install goblint"
    echo "    (skipping — see README)"

    echo "[11/16] Facebook Infer"
    if ! command -v infer &>/dev/null; then
        echo "  Download binary release:"
        echo "    VERSION=v1.2.0"
        echo '    curl -sSL "https://github.com/facebook/infer/releases/download/$VERSION/infer-linux-x86_64-$VERSION.tar.xz" | sudo tar -C /opt -xJ'
        echo '    sudo ln -sf /opt/infer-linux-x86_64-$VERSION/bin/infer /usr/local/bin/infer'
        echo "    (skipping automatic download)"
    else
        echo "  Already installed"
    fi

    echo "[12/16] Saber/SVF"
    echo "  SVF requires LLVM; install from source:"
    echo "    https://github.com/SVF-tools/SVF"
    echo "    (skipping — see README)"

    echo "[13/16] CodeQL"
    if ! command -v codeql &>/dev/null; then
        echo "  Download from GitHub:"
        echo "    https://github.com/github/codeql-cli-binaries/releases"
        echo '    Extract and add to PATH, then: codeql pack download codeql/cpp-queries'
        echo "    (skipping automatic download)"
    else
        echo "  Already installed"
    fi

    echo "[14/16] Semgrep (Python)"
    echo "  (installed via pip in Phase 2)"

    echo "[15/16] Flawfinder (Python)"
    echo "  (installed via pip in Phase 2)"

    echo "[16/16] KNighter (Docker)"
    if command -v docker &>/dev/null; then
        echo "  Pulling KNighter Docker image..."
        try_install "knighter" docker pull knighterhub/knighter
    else
        echo "  Docker not found. Install Docker first, then:"
        echo "    docker pull knighterhub/knighter"
        echo "  Or build from source:"
        echo "    cd tools/KNighter && docker build -t knighter ."
    fi

fi

# ── Phase 2: Python packages ──
echo ""
echo "═══ Phase 2: Python Packages ═══"
echo ""

PIP_FLAGS=""
if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi

try_install "anthropic SDK" pip3 install $PIP_FLAGS anthropic
try_install "semgrep" pip3 install $PIP_FLAGS semgrep
try_install "flawfinder" pip3 install $PIP_FLAGS flawfinder

# ── Phase 3: Verification ──
echo ""
echo "============================================"
echo "  Verification — checking all 16 analyzers"
echo "============================================"
echo ""

TOTAL=0
FOUND=0

check_tool() {
    local label=$1
    local cmd=$2
    TOTAL=$((TOTAL + 1))
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>&1 | head -1 || echo "installed")
        printf "  [\e[32mOK\e[0m]  %-22s %s\n" "$label" "$ver"
        FOUND=$((FOUND + 1))
    else
        printf "  [\e[31m--\e[0m]  %-22s %s\n" "$label" "not found"
    fi
}

check_tool "GCC -fanalyzer"      gcc
check_tool "Clang SA"            clang
check_tool "Cppcheck"            cppcheck
check_tool "clang-tidy"          clang-tidy
check_tool "Semgrep"             semgrep
check_tool "Flawfinder"          flawfinder
check_tool "Sparse"              sparse
check_tool "Coccinelle (spatch)" spatch
check_tool "Smatch"              smatch
check_tool "Frama-C"             frama-c
check_tool "Goblint"             goblint
check_tool "Infer"               infer
check_tool "Saber/SVF"           saber
check_tool "CodeQL"              codeql
check_tool "KNighter (Docker)"  docker

echo ""
echo "$FOUND / $TOTAL analyzers available"
echo ""

if [ "$FOUND" -ge 5 ]; then
    echo "Good coverage. Run Venom with:"
    echo "  cd $(pwd)"
    echo "  python3 -m venom <target-dir> --no-llm --html -o output"
elif [ "$FOUND" -ge 3 ]; then
    echo "Minimum viable. More analyzers = better corroboration."
    echo "  python3 -m venom <target-dir> --no-llm --html -o output"
else
    echo "WARNING: Only $FOUND analyzers found."
    echo "Venom works best with 3+ for corroboration."
fi

echo ""
echo "For LLM triage (recommended):"
echo "  export ANTHROPIC_API_KEY=sk-ant-..."
echo "  python3 -m venom <target-dir> --html -o output"
