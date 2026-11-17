#!/usr/bin/env bash
set -euo pipefail

# Venom Demo — unified static analysis of a real C library
#
# Clones httpserver.h (a lightweight HTTP server in C), runs Venom's
# fast analyzers (Tier 1 + 2), and produces ranked results with reports.
#
# Optional: set ANTHROPIC_API_KEY to enable agentic LLM triage on top findings.
#
# Usage:
#   ./demo.sh              # run the demo
#   ./demo.sh --with-llm   # also run agentic LLM triage (needs API key)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="$SCRIPT_DIR/demo-target"
TOP_K="${TOP_K:-5}"
MODEL="${MODEL:-claude-sonnet-5-5}"

echo "=================================================="
echo "  VENOM Demo — Unified Static Analyzer for C/C++"
echo "=================================================="
echo

# Clone target library if not already present
if [ ! -d "$DEMO_DIR/httpserver" ]; then
    echo "[*] Cloning httpserver.h (lightweight HTTP server in C)..."
    mkdir -p "$DEMO_DIR"
    git clone --depth 1 https://github.com/jeremycw/httpserver.h.git "$DEMO_DIR/httpserver" 2>/dev/null
    echo "    Done."
else
    echo "[*] Using cached httpserver.h at $DEMO_DIR/httpserver"
fi
echo

# Check prerequisites
echo "[*] Checking tools..."
for tool in gcc cppcheck clang; do
    if ! command -v "$tool" &>/dev/null; then
        echo "    Missing: $tool — install it and re-run."
        exit 1
    fi
done
echo "    All required tools found."
echo

# LLM triage only if explicitly requested
LLM_FLAG="--no-llm"
if [[ "${1:-}" == "--with-llm" ]]; then
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        echo "[!] --with-llm requires ANTHROPIC_API_KEY to be set."
        exit 1
    fi
    echo "[*] Agentic LLM triage enabled (model: $MODEL)"
    LLM_FLAG=""
fi

# Run Venom
echo "[*] Running Venom on tinyexpr..."
echo
venom "$DEMO_DIR/httpserver" \
    --tiers 1 2 \
    -k "$TOP_K" \
    --model "$MODEL" \
    -v \
    -o "$SCRIPT_DIR/demo-output" \
    --html \
    $LLM_FLAG

echo
echo "[*] Demo complete."
echo "    Results: $SCRIPT_DIR/demo-output/venom-results.json"
echo "    SARIF:   $SCRIPT_DIR/demo-output/venom-results.sarif"
echo "    Viewer:  $SCRIPT_DIR/demo-output/index.html"
