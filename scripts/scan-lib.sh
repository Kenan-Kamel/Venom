#!/usr/bin/env bash
set -euo pipefail

#───────────────────────────────────────────────────────────
#  venom scan-lib — clone/pull a C/C++ project and scan it
#
#  Usage:
#    ./scripts/scan-lib.sh <git-url-or-local-path> [options]
#
#  Examples:
#    ./scripts/scan-lib.sh https://github.com/php/php-src
#    ./scripts/scan-lib.sh https://github.com/php/php-src --branch PHP-8.3 --subdir Zend
#    ./scripts/scan-lib.sh https://github.com/redis/redis --tiers 1 2
#    ./scripts/scan-lib.sh ./my-local-project
#
#  Options (passed through to venom):
#    --branch <branch>    Git branch to checkout (default: default branch)
#    --subdir <path>      Subdirectory within the repo to scan
#    --depth <n>          Shallow clone depth (default: 1 for speed)
#    --workspace <dir>    Where to clone repos (default: ~/.venom/repos)
#    --output <dir>       Output directory (default: ~/.venom/scans/<repo-name>)
#    --no-llm             Skip LLM triage
#    --html               Generate HTML viewer
#    --tiers N [N...]     Run only specified tiers
#    --exclude A [A...]   Exclude specified analyzers
#    --analyzers A [A...] Run only specified analyzers
#    -v                   Verbose output
#───────────────────────────────────────────────────────────

VENOM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Add locally installed tools to PATH
export PATH="$HOME/.local/share/infer/bin:$HOME/.local/share/codeql:$HOME/.local/bin:$PATH"

VENOM_HOME="${VENOM_HOME:-$HOME/.venom}"
WORKSPACE="${VENOM_HOME}/repos"
SCAN_DIR="${VENOM_HOME}/scans"
HISTORY_FILE="${VENOM_HOME}/scan-history.json"

BRANCH=""
SUBDIR=""
DEPTH=1
OUTPUT=""
VENOM_ARGS=()

usage() {
    head -25 "$0" | grep '^#' | sed 's/^#  \?//'
    exit 1
}

[ $# -lt 1 ] && usage

TARGET_ARG="$1"
shift

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --branch)     BRANCH="$2"; shift 2 ;;
        --subdir)     SUBDIR="$2"; shift 2 ;;
        --depth)      DEPTH="$2"; shift 2 ;;
        --workspace)  WORKSPACE="$2"; shift 2 ;;
        --output)     OUTPUT="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            VENOM_ARGS+=("$1"); shift ;;
    esac
done

mkdir -p "$WORKSPACE" "$SCAN_DIR"

# ── Resolve target ──────────────────────────────────────
is_url() {
    [[ "$1" =~ ^(https?://|git@|ssh://) ]]
}

repo_name_from_url() {
    local url="$1"
    url="${url%.git}"
    url="${url%/}"
    basename "$url"
}

if is_url "$TARGET_ARG"; then
    REPO_NAME=$(repo_name_from_url "$TARGET_ARG")
    REPO_DIR="$WORKSPACE/$REPO_NAME"
    GIT_URL="$TARGET_ARG"

    echo "════════════════════════════════════════════════════════════"
    echo "  Venom scan-lib"
    echo "════════════════════════════════════════════════════════════"
    echo "  Repository: $GIT_URL"
    echo "  Local path: $REPO_DIR"
    [ -n "$BRANCH" ] && echo "  Branch:     $BRANCH"
    [ -n "$SUBDIR" ] && echo "  Subdirectory: $SUBDIR"
    echo ""

    if [ -d "$REPO_DIR/.git" ]; then
        echo "  Updating existing clone..."
        cd "$REPO_DIR"
        git fetch --depth="$DEPTH" origin 2>/dev/null || git fetch origin 2>/dev/null
        if [ -n "$BRANCH" ]; then
            git checkout "$BRANCH" 2>/dev/null || git checkout -b "$BRANCH" "origin/$BRANCH" 2>/dev/null
            git pull origin "$BRANCH" --depth="$DEPTH" 2>/dev/null || git pull origin "$BRANCH" 2>/dev/null || true
        else
            git pull --depth="$DEPTH" 2>/dev/null || git pull 2>/dev/null || true
        fi
    else
        echo "  Cloning repository..."
        CLONE_ARGS=(--depth "$DEPTH")
        [ -n "$BRANCH" ] && CLONE_ARGS+=(--branch "$BRANCH")
        git clone "${CLONE_ARGS[@]}" "$GIT_URL" "$REPO_DIR" 2>&1 | tail -3
        cd "$REPO_DIR"
    fi

    SCAN_TARGET="$REPO_DIR"
elif [ -d "$TARGET_ARG" ]; then
    REPO_DIR=$(cd "$TARGET_ARG" && pwd)
    REPO_NAME=$(basename "$REPO_DIR")
    SCAN_TARGET="$REPO_DIR"
    GIT_URL=""

    echo "════════════════════════════════════════════════════════════"
    echo "  Venom scan-lib"
    echo "════════════════════════════════════════════════════════════"
    echo "  Local project: $REPO_DIR"
    [ -n "$SUBDIR" ] && echo "  Subdirectory: $SUBDIR"
    echo ""

    cd "$REPO_DIR"
else
    echo "Error: '$TARGET_ARG' is not a valid URL or directory" >&2
    exit 1
fi

# ── Gather git metadata ────────────────────────────────
COMMIT_HASH=""
COMMIT_SHORT=""
COMMIT_DATE=""
COMMIT_MSG=""
COMMIT_AUTHOR=""
BRANCH_NAME=""

if [ -d .git ] || git rev-parse --git-dir &>/dev/null 2>&1; then
    COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    COMMIT_DATE=$(git log -1 --format="%ci" 2>/dev/null || echo "unknown")
    COMMIT_MSG=$(git log -1 --format="%s" 2>/dev/null || echo "unknown")
    COMMIT_AUTHOR=$(git log -1 --format="%an" 2>/dev/null || echo "unknown")
    BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

    echo "  Commit:  $COMMIT_SHORT ($BRANCH_NAME)"
    echo "  Date:    $COMMIT_DATE"
    echo "  Author:  $COMMIT_AUTHOR"
    echo "  Message: $COMMIT_MSG"
    echo ""
fi

# ── Determine scan target ──────────────────────────────
if [ -n "$SUBDIR" ]; then
    SCAN_TARGET="$REPO_DIR/$SUBDIR"
    if [ ! -d "$SCAN_TARGET" ]; then
        echo "Error: subdirectory '$SUBDIR' not found in $REPO_DIR" >&2
        exit 1
    fi
fi

# ── Count C/C++ files ──────────────────────────────────
C_FILES=$(find "$SCAN_TARGET" -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' \) 2>/dev/null | wc -l)
echo "  C/C++ files found: $C_FILES"

if [ "$C_FILES" -eq 0 ]; then
    echo "Error: no C/C++ files found in $SCAN_TARGET" >&2
    exit 1
fi

# ── Determine output directory ──────────────────────────
if [ -z "$OUTPUT" ]; then
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    OUTPUT="$SCAN_DIR/$REPO_NAME/$COMMIT_SHORT-$TIMESTAMP"
fi
mkdir -p "$OUTPUT"

echo "  Output:  $OUTPUT"
echo ""

# ── Write git metadata for venom ───────────────────────
GIT_META_FILE="$OUTPUT/.venom-git-meta.json"
python3 -I - "$GIT_META_FILE" "$REPO_NAME" "$GIT_URL" "$BRANCH_NAME" \
    "$COMMIT_HASH" "$COMMIT_SHORT" "$COMMIT_DATE" "$COMMIT_MSG" "$COMMIT_AUTHOR" <<'PYEOF'
import json, sys
_, out_path, repo_name, repo_url, branch, chash, cshort, cdate, cmsg, cauthor = sys.argv
meta = {
    "repo_name": repo_name,
    "repo_url": repo_url,
    "branch": branch,
    "commit_hash": chash,
    "commit_short": cshort,
    "commit_date": cdate,
    "commit_message": cmsg,
    "commit_author": cauthor,
}
with open(out_path, "w") as f:
    json.dump(meta, f, indent=2)
PYEOF

# ── Run Venom ──────────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
echo ""


PYTHONPATH="$VENOM_ROOT:${PYTHONPATH:-}" python3 -m venom "$SCAN_TARGET" \
    -o "$OUTPUT" \
    --html \
    --git-meta "$GIT_META_FILE" \
    "${VENOM_ARGS[@]+"${VENOM_ARGS[@]}"}"

# ── Update scan history ────────────────────────────────
python3 -c "
import json, os
from datetime import datetime, timezone

history_file = '$HISTORY_FILE'
entry = {
    'repo_name': '$REPO_NAME',
    'repo_url': '$GIT_URL',
    'branch': '$BRANCH_NAME',
    'commit_hash': '$COMMIT_HASH',
    'commit_short': '$COMMIT_SHORT',
    'commit_date': '$COMMIT_DATE',
    'scan_time': datetime.now(timezone.utc).isoformat(),
    'output_dir': '$OUTPUT',
}

history = []
if os.path.exists(history_file):
    try:
        with open(history_file) as f:
            history = json.load(f)
    except (json.JSONDecodeError, IOError):
        history = []

history.append(entry)

# Keep last 500 entries
history = history[-500:]

with open(history_file, 'w') as f:
    json.dump(history, f, indent=2)

print()
print('  Scan recorded in history.')
print(f'  Total scans for {entry[\"repo_name\"]}: {sum(1 for h in history if h[\"repo_name\"] == entry[\"repo_name\"])}')
"

echo ""
echo "  Results: $OUTPUT"
echo "  Viewer:  $OUTPUT/index.html"
echo "  History: $HISTORY_FILE"
echo ""
