# Venom

**LLM-Assisted Unified Static Analyzer for Practical Bug Detection in C/C++**

Venom orchestrates 16 static analyzers across four tiers, deduplicates and ranks their findings using an evidence graph, and optionally triages the top candidates with Claude.

## Architecture

```
                Target C/C++ Code
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   ┌─────────┐   ┌──────────┐   ┌──────────┐
   │ Tier 1  │   │ Tier 2   │   │ Tier 3   │   Tier 4
   │ Fast    │   │ Path-    │   │ Whole-   │   Targeted
   │ Sweep   │   │ Sensitive│   │ Program  │   queries
   └────┬────┘   └────┬─────┘   └────┬─────┘
        └──────────────┼──────────────┘
                       ▼
              SARIF Normalization
              & Deduplication
                       │
                       ▼
              Interface Modeling
              (taint sources/sinks)
                       │
                       ▼
              Evidence Graph +
              Candidate Ranking
                       │
                       ▼
              LLM Triage (Claude)
                       │
                       ▼
              Reports (JSON, SARIF, HTML)
```

## Analyzers (16)

| Tier | Name | Type |
|------|------|------|
| 1 — Fast Sweep | cppcheck | Pattern-based checker |
| 1 | flawfinder | Lexical security scanner |
| 1 | sparse | Linux kernel checker |
| 1 | clang-tidy | Lint + static checks |
| 2 — Path-Sensitive | gcc -fanalyzer | GCC symbolic execution |
| 2 | clang-sa | Clang Static Analyzer |
| 2 | semgrep | Semantic grep patterns |
| 3 — Whole-Program | infer | Bi-abduction (Facebook) |
| 3 | ikos | Abstract interpretation (NASA) |
| 3 | frama-c-eva | Value analysis framework |
| 3 | saber-svf | Memory leak / use-after-free |
| 4 — Targeted | codeql | Query-based analysis (GitHub) |
| 4 | goblint | Concurrency analyzer |
| 4 | coccinelle | Semantic patch engine |
| 4 | smatch | Linux kernel checker |
| 4 | knighter | LLM-synthesized CSA checkers (ISE-UIUC) |

Venom runs whichever analyzers are installed and gracefully skips the rest. Three or more gives useful corroboration.

## Quick Start

```bash
# Install system analyzers (Ubuntu/Debian)
bash setup.sh

# Run on a directory
python3 -m venom path/to/code --no-llm --html -o output

# With LLM triage
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m venom path/to/code --html -o output

# Scan a remote repo
bash scripts/scan-lib.sh https://github.com/redis/redis --tiers 1 2

# Interactive TUI
python3 -m venom --tui
```

## Installation

```bash
pip install -e .          # core (no external deps)
pip install -e ".[llm]"   # + Claude API for triage
pip install -e ".[all]"   # + semgrep + flawfinder + Claude
```

## Usage

```
python3 -m venom <target> [options]

Options:
  -o, --output DIR       Output directory (default: output)
  -k, --top-k N          Top N candidates for LLM triage (default: 50)
  --no-llm               Skip LLM triage
  --tiers N [N...]       Run only these tiers (1-4)
  --analyzers A [A...]   Run only these analyzers
  --exclude A [A...]     Exclude analyzers
  --severity LEVEL       Minimum severity (critical/high/medium/low)
  --html                 Generate HTML viewer
  --json                 Output JSON to stdout
  --sarif                Output SARIF to stdout
  --tui                  Launch interactive TUI
  -v, --verbose          Verbose output
```

## Output

Each scan produces:

- `venom-results.json` — Full findings with scores, CWEs, and LLM verdicts
- `venom-results.sarif` — SARIF 2.1 for IDE/CI integration
- `venom-data.json` — Viewer data (findings + codebase map + evidence graph)
- `index.html` — Interactive HTML viewer (with `--html`)

## TUI

Launch with `python3 -m venom` (no arguments) or `python3 -m venom --tui`:

- **Run Scan** — configure and run analysis on a local directory
- **Scan Library** — clone and scan a git repository
- **Install Tools** — check status and install all 16 analyzers
- **Scan History** — browse past results with severity breakdowns
- **Open Viewer** — launch HTML viewer in browser

## Viewer

The standalone HTML viewer (`viewer/index.html`) provides:

- **Findings tab** — filterable, sortable list with severity charts and CWE breakdown
- **Codebase Map** — D3 treemap showing files sized by LOC or finding count, colored by severity
- Drill-down into directories and files with proportional line markers
- Drag-and-drop `venom-data.json` to load results

## How Scoring Works

Each finding gets a composite score from four signals:

| Signal | Weight | Source |
|--------|--------|--------|
| Corroboration | 30% | Number of analyzers reporting the same location + CWE |
| CWE Severity | 25% | CWE database severity classification |
| Taint Reachability | 25% | Source-to-sink data flow through the finding's function |
| Graph Centrality | 20% | PageRank of the function in the call graph |

## Project Structure

```
venom/
├── venom/
│   ├── cli.py              # CLI entry point
│   ├── tui.py              # Interactive terminal UI
│   ├── analyzers/           # 16 analyzer runners
│   │   ├── base.py          # Abstract analyzer base class
│   │   ├── cppcheck_runner.py
│   │   ├── infer_runner.py
│   │   └── ...
│   ├── sarif.py             # SARIF normalization & dedup
│   ├── interface.py         # Taint source/sink modeling
│   ├── ranking.py           # Evidence graph & PageRank scoring
│   ├── cwe.py               # CWE database
│   ├── triage.py            # LLM triage with Claude
│   └── report.py            # JSON/SARIF/HTML report generation
├── viewer/
│   └── index.html           # Standalone HTML viewer
├── scripts/
│   └── scan-lib.sh          # Clone-and-scan helper
├── samples/                 # Test C files with known bugs
├── tests/                   # Test suite
├── setup.sh                 # System-wide tool installer
└── pyproject.toml
```

## CS 494 — University of Illinois Chicago

Built for CS 494: Advanced Topics in Software Engineering.
