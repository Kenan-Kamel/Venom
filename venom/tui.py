#!/usr/bin/env python3
"""Venom TUI — interactive terminal interface for running scans, installing tools, and browsing history."""

import curses
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VENOM_HOME = Path(os.environ.get("VENOM_HOME", Path.home() / ".venom"))
HISTORY_FILE = VENOM_HOME / "scan-history.json"
SCANS_DIR = VENOM_HOME / "scans"
REPOS_DIR = VENOM_HOME / "repos"

TOOL_REGISTRY = [
    {
        "name": "cppcheck",
        "bin": "cppcheck",
        "tier": 1,
        "install_apt": "cppcheck",
        "install_cmd": "sudo apt-get install -y cppcheck",
        "desc": "Fast pattern-based C/C++ checker",
    },
    {
        "name": "flawfinder",
        "bin": "flawfinder",
        "tier": 1,
        "install_apt": "flawfinder",
        "install_cmd": "pip3 install flawfinder",
        "desc": "Lexical scanner for security flaws",
    },
    {
        "name": "sparse",
        "bin": "sparse",
        "tier": 1,
        "install_apt": "sparse",
        "install_cmd": "sudo apt-get install -y sparse",
        "desc": "Linux kernel semantic parser",
    },
    {
        "name": "clang-tidy",
        "bin": "clang-tidy",
        "tier": 1,
        "install_cmd": "pip3 install clang-tidy",
        "desc": "Clang-based linter & static analyzer",
    },
    {
        "name": "gcc (fanalyzer)",
        "bin": "gcc",
        "tier": 2,
        "install_apt": "gcc",
        "install_cmd": "sudo apt-get install -y gcc",
        "desc": "GCC -fanalyzer path-sensitive engine",
    },
    {
        "name": "clang (SA)",
        "bin": "scan-build",
        "tier": 2,
        "install_apt": "clang-tools",
        "install_cmd": "sudo apt-get install -y clang-tools",
        "desc": "Clang Static Analyzer",
    },
    {
        "name": "semgrep",
        "bin": "semgrep",
        "tier": 2,
        "install_cmd": "pip3 install semgrep",
        "desc": "Lightweight multi-language SAST",
    },
    {
        "name": "infer",
        "bin": "infer",
        "tier": 3,
        "install_cmd": "# Manual: download from https://github.com/facebook/infer/releases",
        "desc": "Facebook's bi-abduction analyzer",
    },
    {
        "name": "ikos",
        "bin": "ikos",
        "tier": 3,
        "install_apt": "ikos",
        "install_cmd": "sudo apt-get install -y ikos",
        "desc": "Abstract interpretation (NASA)",
    },
    {
        "name": "frama-c",
        "bin": "frama-c",
        "tier": 3,
        "install_cmd": "opam install frama-c",
        "desc": "Formal methods framework (EVA plugin)",
    },
    {
        "name": "codeql",
        "bin": "codeql",
        "tier": 4,
        "install_cmd": "# Manual: download from https://github.com/github/codeql-cli-binaries/releases",
        "desc": "GitHub's query-based analyzer",
    },
    {
        "name": "goblint",
        "bin": "goblint",
        "tier": 4,
        "install_cmd": "opam install goblint",
        "desc": "Thread-safety & concurrency analyzer",
    },
    {
        "name": "coccinelle",
        "bin": "spatch",
        "tier": 4,
        "install_apt": "coccinelle",
        "install_cmd": "sudo apt-get install -y coccinelle",
        "desc": "Semantic patch engine",
    },
    {
        "name": "smatch",
        "bin": "smatch",
        "tier": 4,
        "install_cmd": "# Build from source: https://github.com/error27/smatch",
        "desc": "Linux kernel static checker",
    },
    {
        "name": "knighter",
        "bin": "docker",
        "tier": 4,
        "install_cmd": "docker pull knighterhub/knighter",
        "desc": "LLM-synthesized CSA checkers (ISE-UIUC)",
    },
]

TIER_NAMES = {1: "Fast Sweep", 2: "Path-Sensitive", 3: "Whole-Program", 4: "Targeted"}

# ── Color pairs ──────────────────────────────────────────
C_NORMAL = 0
C_HEADER = 1
C_SELECTED = 2
C_OK = 3
C_WARN = 4
C_ERR = 5
C_MUTED = 6
C_ACCENT = 7
C_CRITICAL = 8
C_HIGH = 9
C_MEDIUM = 10
C_LOW = 11
C_TITLE = 12
def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_SELECTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_ERR, curses.COLOR_RED, -1)
    curses.init_pair(C_MUTED, curses.COLOR_WHITE, -1)
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN, -1)
    curses.init_pair(C_CRITICAL, curses.COLOR_RED, -1)
    curses.init_pair(C_HIGH, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_MEDIUM, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_LOW, curses.COLOR_GREEN, -1)
    curses.init_pair(C_TITLE, curses.COLOR_CYAN, -1)


def tool_installed(tool):
    if tool["bin"] is None:
        return True
    return shutil.which(tool["bin"]) is not None


def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    maxlen = w - x - 1 if y == h - 1 else w - x
    if maxlen <= 0:
        return
    try:
        win.addnstr(y, x, str(text), maxlen, attr)
    except curses.error:
        pass


def draw_header(stdscr, title, w):
    text = f" VENOM  {title}"
    safe_addstr(stdscr, 0, 0, text.ljust(w - 1), curses.color_pair(C_HEADER) | curses.A_BOLD)


def draw_footer(stdscr, text, h, w):
    safe_addstr(stdscr, h - 1, 0, text.ljust(w - 1), curses.color_pair(C_MUTED))


# ═══════════════════════════════════════════════════════════
#  Main Menu
# ═══════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("Run Scan", "Analyze a C/C++ project or directory"),
    ("Scan Library", "Clone and scan a git repository"),
    ("Install Tools", "Check and install analysis tools"),
    ("Scan History", "Browse past scan results"),
    ("Open Viewer", "Open HTML viewer for a scan"),
    ("Quit", "Exit Venom TUI"),
]


def main_menu(stdscr):
    curses.curs_set(0)
    init_colors()
    sel = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        if h < 10 or w < 40:
            safe_addstr(stdscr, 0, 0, "Terminal too small. Resize to 40x10+.", curses.A_BOLD)
            stdscr.refresh()
            stdscr.getch()
            continue

        draw_header(stdscr, "Main Menu", w)

        logo_y = 2
        logo_drip = [
            r"  ██▒   ██▒▓██████ ███▒   █▓ ▒█████  ███▄ ▄███▓",
            r" ▓██░  ██▒▓█   ▀  ▓██░   █▒▒██▒  ██▒▓██▒▀█▀ ██▒",
            r"  ▓██  ██▓▒███   ▒ ██  █▒░▒██░  ██▒▓██    ▓██░",
            r"  ▒██ ██▓░▒▓█  ▄  ░▓█  █▓ ▒██   ██░▒██    ▒██ ",
            r"   ▒██▓ ░ ░▒████▒ ░▒▓███▀▒░ ████▓▒░▒██▒   ░██▒",
            r"    ▒▓    ░░ ▒░ ░  ░▒   ▒  ░ ▒░▒░▒░░ ▒░   ░  ░",
            r"    ░▒     ░ ░  ░   ░   ░    ░ ▒ ▒░░  ░      ░",
            r"     ░       ░    ░ ░   ░  ░ ░ ░ ░ ░      ░   ",
            r"     ░       ░  ░   ░        ░ ░          ░    ",
            r"             ░                                  ",
        ]
        logo_small = [
            r" _   _____ _  _  ___  __  __ ",
            r"| | / / __| \| |/ _ \|  \/  |",
            r"| |/ /| _|| .` | (_) | |\/| |",
            r" \__/ |___|_|\_|\___/|_|  |_|",
        ]
        logo_tiny = ["  V E N O M"]

        if w >= 54:
            text_block = logo_drip
        elif w >= 34:
            text_block = logo_small
        else:
            text_block = [logo_tiny[0]]

        text_y = logo_y
        for i, line in enumerate(text_block):
            if text_y + i < h - 1:
                cx = max(0, (w - len(line)) // 2)
                if text_block is logo_drip:
                    if i < 5:
                        attr = curses.color_pair(C_ERR) | curses.A_BOLD
                    else:
                        attr = curses.color_pair(C_ERR)
                else:
                    attr = curses.color_pair(C_ACCENT) | curses.A_BOLD
                safe_addstr(stdscr, text_y + i, cx, line, attr)

        subtitle = "LLM-Assisted Unified Static Analyzer for C/C++"
        sub_y = text_y + len(text_block) + 1
        if sub_y < h - 1:
            safe_addstr(stdscr, sub_y, max(0, (w - len(subtitle)) // 2), subtitle, curses.color_pair(C_MUTED))

        menu_y = sub_y + 2
        for i, (label, desc) in enumerate(MENU_ITEMS):
            if menu_y + i * 2 >= h - 2:
                break
            prefix = "  >  " if i == sel else "     "
            attr = curses.color_pair(C_SELECTED) | curses.A_BOLD if i == sel else curses.A_NORMAL
            safe_addstr(stdscr, menu_y + i * 2, max(0, (w - 50) // 2), f"{prefix}{label}", attr)
            if i != sel:
                safe_addstr(stdscr, menu_y + i * 2 + 1, max(0, (w - 50) // 2) + 5, desc, curses.color_pair(C_MUTED))

        installed = sum(1 for t in TOOL_REGISTRY if tool_installed(t))
        total = len(TOOL_REGISTRY)
        draw_footer(stdscr, f"  Tools: {installed}/{total} installed  |  Up/Down: navigate  |  Enter: select  |  q: quit", h, w)

        stdscr.refresh()
        key = stdscr.getch()

        if key in (curses.KEY_UP, ord('k')):
            sel = (sel - 1) % len(MENU_ITEMS)
        elif key in (curses.KEY_DOWN, ord('j')):
            sel = (sel + 1) % len(MENU_ITEMS)
        elif key in (curses.KEY_ENTER, 10, 13):
            if sel == 0:
                run_scan_screen(stdscr)
            elif sel == 1:
                scan_library_screen(stdscr)
            elif sel == 2:
                install_tools_screen(stdscr)
            elif sel == 3:
                history_screen(stdscr)
            elif sel == 4:
                open_viewer_screen(stdscr)
            elif sel == 5:
                return
        elif key == ord('q'):
            return


# ═══════════════════════════════════════════════════════════
#  Install Tools Screen
# ═══════════════════════════════════════════════════════════

def install_tools_screen(stdscr):
    sel = 0
    scroll = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, "Install Tools", w)

        y = 2
        visible = h - 5
        current_tier = 0

        display_items = []
        for tool in TOOL_REGISTRY:
            if tool["tier"] != current_tier:
                current_tier = tool["tier"]
                display_items.append(("tier_header", tool["tier"]))
            display_items.append(("tool", tool))

        for idx in range(scroll, min(scroll + visible, len(display_items))):
            item_type, item_data = display_items[idx]
            row = y + (idx - scroll)
            if row >= h - 2:
                break

            if item_type == "tier_header":
                tier_num = item_data
                label = f"  Tier {tier_num}: {TIER_NAMES.get(tier_num, '')}"
                safe_addstr(stdscr, row, 0, label, curses.color_pair(C_TITLE) | curses.A_BOLD)
            else:
                tool = item_data
                is_installed = tool_installed(tool)
                is_sel = idx == sel

                status = " READY " if is_installed else "  ---  "
                status_color = C_OK if is_installed else C_ERR

                prefix = " > " if is_sel else "   "
                line_attr = curses.A_BOLD if is_sel else curses.A_NORMAL

                safe_addstr(stdscr, row, 0, prefix, line_attr)
                safe_addstr(stdscr, row, 3, f"[", curses.color_pair(C_MUTED))
                safe_addstr(stdscr, row, 4, status, curses.color_pair(status_color) | curses.A_BOLD)
                safe_addstr(stdscr, row, 4 + len(status), "]", curses.color_pair(C_MUTED))

                name_str = f" {tool['name']:16s}"
                safe_addstr(stdscr, row, 13, name_str, line_attr)
                safe_addstr(stdscr, row, 30, tool["desc"][:w - 31], curses.color_pair(C_MUTED))

        draw_footer(stdscr, "  Up/Down: navigate  |  Enter: install selected  |  a: install all missing  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')):
            sel = max(0, sel - 1)
            while sel > 0 and display_items[sel][0] == "tier_header":
                sel -= 1
            if sel < scroll:
                scroll = sel
        elif key in (curses.KEY_DOWN, ord('j')):
            sel = min(len(display_items) - 1, sel + 1)
            while sel < len(display_items) - 1 and display_items[sel][0] == "tier_header":
                sel += 1
            if sel >= scroll + visible:
                scroll = sel - visible + 1
        elif key in (curses.KEY_ENTER, 10, 13):
            if display_items[sel][0] == "tool":
                install_tool(stdscr, display_items[sel][1])
        elif key == ord('a'):
            install_all_missing(stdscr)
        elif key in (27, ord('q'), curses.KEY_BACKSPACE, 127):
            return


def install_tool(stdscr, tool):
    if tool_installed(tool):
        show_message(stdscr, f"{tool['name']} is already installed.", C_OK)
        return
    if not tool.get("install_cmd") or tool["install_cmd"].startswith("#"):
        show_message(stdscr, f"{tool['name']}: {tool.get('install_cmd', 'No auto-install available')}", C_WARN)
        return

    stdscr.erase()
    h, w = stdscr.getmaxyx()
    draw_header(stdscr, f"Installing {tool['name']}", w)
    safe_addstr(stdscr, 2, 2, f"Running: {tool['install_cmd']}", curses.color_pair(C_ACCENT))
    safe_addstr(stdscr, 4, 2, "Please wait...", curses.color_pair(C_MUTED))
    stdscr.refresh()

    curses.endwin()
    print(f"\n  Installing {tool['name']}...")
    print(f"  $ {tool['install_cmd']}\n")
    result = subprocess.run(tool["install_cmd"], shell=True)
    print(f"\n  {'Installed successfully!' if result.returncode == 0 else 'Installation failed.'}")
    print("  Press Enter to continue...")
    input()
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)
    init_colors()


def install_all_missing(stdscr):
    missing = [t for t in TOOL_REGISTRY if not tool_installed(t) and t.get("install_cmd") and not t["install_cmd"].startswith("#")]
    if not missing:
        show_message(stdscr, "All auto-installable tools are already present!", C_OK)
        return

    curses.endwin()
    print(f"\n  Installing {len(missing)} missing tools...\n")
    for tool in missing:
        print(f"  [{tool['name']}] {tool['install_cmd']}")
        result = subprocess.run(tool["install_cmd"], shell=True)
        status = "OK" if result.returncode == 0 else "FAILED"
        print(f"  [{tool['name']}] {status}\n")
    print("  Press Enter to continue...")
    input()
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)
    init_colors()


# ═══════════════════════════════════════════════════════════
#  Run Scan Screen
# ═══════════════════════════════════════════════════════════

def run_scan_screen(stdscr):
    fields = {
        "target": "",
        "output": "",
        "tiers": "1 2 3 4",
        "exclude": "",
        "severity": "",
        "top_k": "50",
        "no_llm": False,
        "html": True,
        "verbose": False,
    }
    field_order = ["target", "output", "tiers", "exclude", "severity", "top_k", "no_llm", "html", "verbose"]
    field_labels = {
        "target": "Target path",
        "output": "Output dir (blank=auto)",
        "tiers": "Tiers (1-4, space-sep)",
        "exclude": "Exclude analyzers",
        "severity": "Min severity (blank=all)",
        "top_k": "Top-K for LLM triage",
        "no_llm": "Skip LLM triage",
        "html": "Generate HTML viewer",
        "verbose": "Verbose output",
    }
    sel = 0
    editing = False
    edit_buf = ""

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, "Run Scan", w)

        y = 2
        safe_addstr(stdscr, y, 2, "Configure scan parameters:", curses.color_pair(C_TITLE) | curses.A_BOLD)
        y += 2

        for i, key in enumerate(field_order):
            is_sel = i == sel
            label = field_labels[key]
            val = fields[key]
            prefix = " > " if is_sel else "   "
            attr = curses.A_BOLD if is_sel else curses.A_NORMAL

            if isinstance(val, bool):
                check = "[x]" if val else "[ ]"
                safe_addstr(stdscr, y + i, 2, prefix, attr)
                safe_addstr(stdscr, y + i, 5, f"{label}: ", curses.color_pair(C_MUTED))
                col = curses.color_pair(C_OK) if val else curses.color_pair(C_ERR)
                safe_addstr(stdscr, y + i, 5 + len(label) + 2, check, col | curses.A_BOLD)
            else:
                display_val = edit_buf if (is_sel and editing) else str(val)
                safe_addstr(stdscr, y + i, 2, prefix, attr)
                safe_addstr(stdscr, y + i, 5, f"{label}: ", curses.color_pair(C_MUTED))
                val_attr = curses.color_pair(C_ACCENT) if display_val else curses.color_pair(C_MUTED)
                safe_addstr(stdscr, y + i, 5 + len(label) + 2, display_val or "(empty)", val_attr)
                if is_sel and editing:
                    curses.curs_set(1)
                    try:
                        stdscr.move(y + i, 5 + len(label) + 2 + len(display_val))
                    except curses.error:
                        pass

        run_y = y + len(field_order) + 2
        run_sel = sel == len(field_order)
        run_attr = curses.color_pair(C_OK) | curses.A_BOLD if run_sel else curses.color_pair(C_OK)
        run_prefix = " > " if run_sel else "   "
        safe_addstr(stdscr, run_y, 2, f"{run_prefix}[ START SCAN ]", run_attr)

        draw_footer(stdscr, "  Up/Down: navigate  |  Enter: edit/toggle  |  Tab: next field  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()

        if editing:
            current_key = field_order[sel]
            if key in (curses.KEY_ENTER, 10, 13):
                fields[current_key] = edit_buf
                editing = False
                curses.curs_set(0)
            elif key == 27:
                editing = False
                curses.curs_set(0)
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                edit_buf = edit_buf[:-1]
            elif 32 <= key < 127:
                edit_buf += chr(key)
        else:
            if key in (curses.KEY_UP, ord('k')):
                sel = max(0, sel - 1)
            elif key in (curses.KEY_DOWN, ord('j'), 9):
                sel = min(len(field_order), sel + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                if sel == len(field_order):
                    if not fields["target"]:
                        show_message(stdscr, "Target path is required!", C_ERR)
                    else:
                        execute_scan(stdscr, fields)
                        return
                else:
                    current_key = field_order[sel]
                    if isinstance(fields[current_key], bool):
                        fields[current_key] = not fields[current_key]
                    else:
                        editing = True
                        edit_buf = str(fields[current_key])
            elif key in (27, ord('q')):
                return


def execute_scan(stdscr, fields):
    target = os.path.expanduser(fields["target"])
    cmd = [sys.executable, "-m", "venom", target]

    if fields["output"]:
        cmd.extend(["-o", fields["output"]])
    if fields["tiers"].strip():
        cmd.extend(["--tiers"] + fields["tiers"].strip().split())
    if fields["exclude"].strip():
        cmd.extend(["--exclude"] + fields["exclude"].strip().split())
    if fields["severity"]:
        cmd.extend(["--severity", fields["severity"]])
    if fields["top_k"]:
        cmd.extend(["-k", fields["top_k"]])
    if fields["no_llm"]:
        cmd.append("--no-llm")
    if fields["html"]:
        cmd.append("--html")
    if fields["verbose"]:
        cmd.append("-v")

    curses.endwin()
    print(f"\n  Running: {' '.join(cmd)}\n")
    start_time = time.time()
    result = subprocess.run(cmd, cwd=str(Path(__file__).parent.parent))
    elapsed = time.time() - start_time

    print(f"\n  {'Scan completed' if result.returncode == 0 else 'Scan failed'} in {elapsed:.1f}s")

    _record_history(fields, elapsed, result.returncode)

    print("  Press Enter to continue...")
    input()
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)
    init_colors()


def _record_history(fields, elapsed, returncode):
    VENOM_HOME.mkdir(parents=True, exist_ok=True)
    target = os.path.abspath(os.path.expanduser(fields["target"]))

    entry = {
        "type": "local",
        "target": target,
        "output_dir": os.path.abspath(fields["output"]) if fields["output"] else "",
        "tiers": fields["tiers"],
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 1),
        "exit_code": returncode,
    }

    history = []
    try:
        if HISTORY_FILE.exists():
            history = json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass

    history.insert(0, entry)
    history = history[:500]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


# ═══════════════════════════════════════════════════════════
#  Scan Library Screen
# ═══════════════════════════════════════════════════════════

def scan_library_screen(stdscr):
    fields = {
        "url": "",
        "branch": "",
        "subdir": "",
        "tiers": "1 2 3 4",
        "exclude": "",
        "no_llm": False,
        "html": True,
    }
    field_order = ["url", "branch", "subdir", "tiers", "exclude", "no_llm", "html"]
    field_labels = {
        "url": "Git URL or local path",
        "branch": "Branch (blank=default)",
        "subdir": "Subdirectory to scan",
        "tiers": "Tiers (1-4, space-sep)",
        "exclude": "Exclude analyzers",
        "no_llm": "Skip LLM triage",
        "html": "Generate HTML viewer",
    }
    sel = 0
    editing = False
    edit_buf = ""

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, "Scan Library", w)

        y = 2
        safe_addstr(stdscr, y, 2, "Clone and scan a git repository:", curses.color_pair(C_TITLE) | curses.A_BOLD)
        y += 2

        for i, key in enumerate(field_order):
            is_sel = i == sel
            label = field_labels[key]
            val = fields[key]
            prefix = " > " if is_sel else "   "
            attr = curses.A_BOLD if is_sel else curses.A_NORMAL

            if isinstance(val, bool):
                check = "[x]" if val else "[ ]"
                safe_addstr(stdscr, y + i, 2, prefix, attr)
                safe_addstr(stdscr, y + i, 5, f"{label}: ", curses.color_pair(C_MUTED))
                col = curses.color_pair(C_OK) if val else curses.color_pair(C_ERR)
                safe_addstr(stdscr, y + i, 5 + len(label) + 2, check, col | curses.A_BOLD)
            else:
                display_val = edit_buf if (is_sel and editing) else str(val)
                safe_addstr(stdscr, y + i, 2, prefix, attr)
                safe_addstr(stdscr, y + i, 5, f"{label}: ", curses.color_pair(C_MUTED))
                val_attr = curses.color_pair(C_ACCENT) if display_val else curses.color_pair(C_MUTED)
                safe_addstr(stdscr, y + i, 5 + len(label) + 2, display_val or "(empty)", val_attr)
                if is_sel and editing:
                    curses.curs_set(1)
                    try:
                        stdscr.move(y + i, 5 + len(label) + 2 + len(display_val))
                    except curses.error:
                        pass

        run_y = y + len(field_order) + 2
        run_sel = sel == len(field_order)
        run_attr = curses.color_pair(C_OK) | curses.A_BOLD if run_sel else curses.color_pair(C_OK)
        run_prefix = " > " if run_sel else "   "
        safe_addstr(stdscr, run_y, 2, f"{run_prefix}[ START SCAN ]", run_attr)

        recently = _recent_repos()
        if recently:
            ry = run_y + 3
            safe_addstr(stdscr, ry, 2, "Recent repositories:", curses.color_pair(C_TITLE))
            for i, repo in enumerate(recently[:5]):
                if ry + 1 + i >= h - 2:
                    break
                safe_addstr(stdscr, ry + 1 + i, 4, f"- {repo}", curses.color_pair(C_MUTED))

        draw_footer(stdscr, "  Up/Down: navigate  |  Enter: edit/toggle  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()

        if editing:
            current_key = field_order[sel]
            if key in (curses.KEY_ENTER, 10, 13):
                fields[current_key] = edit_buf
                editing = False
                curses.curs_set(0)
            elif key == 27:
                editing = False
                curses.curs_set(0)
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                edit_buf = edit_buf[:-1]
            elif 32 <= key < 127:
                edit_buf += chr(key)
        else:
            if key in (curses.KEY_UP, ord('k')):
                sel = max(0, sel - 1)
            elif key in (curses.KEY_DOWN, ord('j'), 9):
                sel = min(len(field_order), sel + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                if sel == len(field_order):
                    if not fields["url"]:
                        show_message(stdscr, "Git URL is required!", C_ERR)
                    else:
                        execute_scan_lib(stdscr, fields)
                        return
                else:
                    current_key = field_order[sel]
                    if isinstance(fields[current_key], bool):
                        fields[current_key] = not fields[current_key]
                    else:
                        editing = True
                        edit_buf = str(fields[current_key])
            elif key in (27, ord('q')):
                return


def _recent_repos():
    try:
        if REPOS_DIR.exists():
            return sorted([d.name for d in REPOS_DIR.iterdir() if d.is_dir()])
    except OSError:
        pass
    return []


def execute_scan_lib(stdscr, fields):
    script = Path(__file__).parent.parent / "scripts" / "scan-lib.sh"
    if not script.exists():
        show_message(stdscr, "scan-lib.sh not found!", C_ERR)
        return

    cmd = ["bash", str(script), fields["url"]]
    if fields["branch"]:
        cmd.extend(["--branch", fields["branch"]])
    if fields["subdir"]:
        cmd.extend(["--subdir", fields["subdir"]])
    if fields["tiers"].strip():
        cmd.extend(["--tiers"] + fields["tiers"].strip().split())
    if fields["exclude"].strip():
        cmd.extend(["--exclude"] + fields["exclude"].strip().split())
    if fields["no_llm"]:
        cmd.append("--no-llm")
    if fields["html"]:
        cmd.append("--html")

    curses.endwin()
    print(f"\n  Running: {' '.join(cmd)}\n")
    start_time = time.time()
    result = subprocess.run(cmd)
    elapsed = time.time() - start_time

    print(f"\n  {'Scan completed' if result.returncode == 0 else 'Scan failed'} in {elapsed:.1f}s")
    print("  Press Enter to continue...")
    input()
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)
    init_colors()


# ═══════════════════════════════════════════════════════════
#  Scan History Screen
# ═══════════════════════════════════════════════════════════

def load_history():
    entries = []
    try:
        if HISTORY_FILE.exists():
            entries = json.loads(HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass

    known_dirs = {e.get("output_dir", "").rstrip("/") for e in entries}

    if SCANS_DIR.exists():
        for repo_dir in sorted(SCANS_DIR.iterdir()):
            if not repo_dir.is_dir():
                continue
            for scan_dir in sorted(repo_dir.iterdir(), reverse=True):
                if not scan_dir.is_dir():
                    continue
                results_file = scan_dir / "venom-results.json"
                if results_file.exists() and str(scan_dir).rstrip("/") not in known_dirs:
                    try:
                        with open(results_file) as f:
                            res = json.load(f)
                        meta = res.get("metadata", {})
                        git = meta.get("git", {})
                        entries.append({
                            "type": "library",
                            "repo_name": repo_dir.name,
                            "commit_short": git.get("commit_short", scan_dir.name.split("-")[0][:8]),
                            "branch": git.get("branch", ""),
                            "scan_time": meta.get("timestamp", ""),
                            "output_dir": str(scan_dir),
                            "findings_count": len(res.get("findings", [])),
                            "analyzers_used": meta.get("analyzers_used", []),
                        })
                    except (json.JSONDecodeError, OSError):
                        pass

    for e in entries:
        if "findings_count" not in e and e.get("output_dir"):
            rf = Path(e["output_dir"]) / "venom-results.json"
            if rf.exists():
                try:
                    with open(rf) as f:
                        res = json.load(f)
                    e["findings_count"] = len(res.get("findings", []))
                    e["analyzers_used"] = res.get("metadata", {}).get("analyzers_used", [])
                except (json.JSONDecodeError, OSError):
                    pass

    entries.sort(key=lambda e: e.get("scan_time", ""), reverse=True)
    return entries


def history_screen(stdscr):
    entries = load_history()
    sel = 0
    scroll = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, f"Scan History ({len(entries)} entries)", w)

        if not entries:
            safe_addstr(stdscr, h // 2, max(0, (w - 30) // 2), "No scan history found.", curses.color_pair(C_MUTED))
            draw_footer(stdscr, "  Esc: back", h, w)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (27, ord('q'), curses.KEY_BACKSPACE, 127):
                return
            continue

        y = 2
        col_w = max(60, w - 4)
        visible = (h - 5) // 3

        safe_addstr(stdscr, y, 2,
            f"{'#':>3s}  {'Type':8s}  {'Target/Repo':24s}  {'Commit':10s}  {'Time':20s}  {'Findings':>8s}",
            curses.color_pair(C_MUTED) | curses.A_BOLD)
        y += 1
        safe_addstr(stdscr, y, 2, "-" * min(col_w, w - 4), curses.color_pair(C_MUTED))
        y += 1

        for idx in range(scroll, min(scroll + visible, len(entries))):
            e = entries[idx]
            row = y + (idx - scroll) * 2
            if row >= h - 3:
                break

            is_sel = idx == sel
            attr = curses.color_pair(C_SELECTED) | curses.A_BOLD if is_sel else curses.A_NORMAL

            etype = e.get("type", "scan")[:8]
            target = e.get("repo_name") or e.get("target", "")
            if len(target) > 24:
                target = "..." + target[-21:]
            commit = e.get("commit_short", "")[:10]
            scan_time = e.get("scan_time", "")[:19].replace("T", " ")
            findings = str(e.get("findings_count", "?"))
            exit_code = e.get("exit_code")

            prefix = " > " if is_sel else "   "
            line = f"{idx+1:3d}  {etype:8s}  {target:24s}  {commit:10s}  {scan_time:20s}  {findings:>8s}"

            safe_addstr(stdscr, row, 0, prefix, attr)
            safe_addstr(stdscr, row, 3, line[:w-4], attr)

            if is_sel:
                out_dir = e.get("output_dir", "")
                if out_dir:
                    safe_addstr(stdscr, row + 1, 5, f"Output: {out_dir}"[:w-6], curses.color_pair(C_ACCENT))
                if exit_code is not None and exit_code != 0:
                    safe_addstr(stdscr, row + 1, 5, f"[exit code {exit_code}]", curses.color_pair(C_ERR))

        draw_footer(stdscr, "  Up/Down: navigate  |  Enter: view details  |  o: open in viewer  |  d: delete  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')):
            sel = max(0, sel - 1)
            if sel < scroll:
                scroll = sel
        elif key in (curses.KEY_DOWN, ord('j')):
            sel = min(len(entries) - 1, sel + 1)
            if sel >= scroll + visible:
                scroll = sel - visible + 1
        elif key in (curses.KEY_ENTER, 10, 13):
            if entries:
                history_detail_screen(stdscr, entries[sel])
        elif key == ord('o'):
            if entries:
                _open_viewer_for(stdscr, entries[sel])
        elif key == ord('d'):
            if entries:
                if confirm(stdscr, f"Delete scan entry #{sel+1}?"):
                    entries.pop(sel)
                    _save_history(entries)
                    sel = min(sel, len(entries) - 1)
        elif key in (27, ord('q'), curses.KEY_BACKSPACE, 127):
            return


def _save_history(entries):
    try:
        HISTORY_FILE.write_text(json.dumps(entries, indent=2))
    except OSError:
        pass


def history_detail_screen(stdscr, entry):
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, "Scan Details", w)

        y = 2
        fields = [
            ("Type", entry.get("type", "scan")),
            ("Target", entry.get("target") or entry.get("repo_name") or entry.get("repo_url", "")),
            ("Branch", entry.get("branch", "")),
            ("Commit", entry.get("commit_hash") or entry.get("commit_short", "")),
            ("Commit Date", entry.get("commit_date", "")),
            ("Scan Time", entry.get("scan_time", "")),
            ("Output Dir", entry.get("output_dir", "")),
            ("Elapsed", f"{entry.get('elapsed_seconds', '?')}s"),
            ("Exit Code", str(entry.get("exit_code", "?"))),
            ("Tiers", entry.get("tiers", "")),
        ]

        for label, val in fields:
            if not val or val == "?s":
                continue
            safe_addstr(stdscr, y, 2, f"{label + ':':<16s}", curses.color_pair(C_MUTED))
            safe_addstr(stdscr, y, 18, str(val)[:w - 20], curses.color_pair(C_ACCENT))
            y += 1

        out_dir = entry.get("output_dir", "")
        if out_dir and Path(out_dir).exists():
            results_file = Path(out_dir) / "venom-results.json"
            if results_file.exists():
                y += 1
                safe_addstr(stdscr, y, 2, "Results Summary:", curses.color_pair(C_TITLE) | curses.A_BOLD)
                y += 1
                try:
                    with open(results_file) as f:
                        res = json.load(f)
                    findings = res.get("findings", [])
                    summary = res.get("summary", {})

                    safe_addstr(stdscr, y, 4, f"Total findings: ", curses.color_pair(C_MUTED))
                    safe_addstr(stdscr, y, 20, str(len(findings)), curses.A_BOLD)
                    y += 1

                    by_sev = summary.get("by_severity", {})
                    sev_colors = {"critical": C_CRITICAL, "high": C_HIGH, "medium": C_MEDIUM, "low": C_LOW}
                    for sev in ["critical", "high", "medium", "low"]:
                        count = by_sev.get(sev, 0)
                        if count:
                            safe_addstr(stdscr, y, 6, f"{sev:>10s}: ", curses.color_pair(C_MUTED))
                            safe_addstr(stdscr, y, 18, str(count), curses.color_pair(sev_colors.get(sev, C_MUTED)) | curses.A_BOLD)
                            y += 1

                    analyzers_used = res.get("metadata", {}).get("analyzers_used", [])
                    if analyzers_used:
                        y += 1
                        safe_addstr(stdscr, y, 4, f"Analyzers: {', '.join(analyzers_used)}"[:w-6], curses.color_pair(C_MUTED))
                        y += 1

                    by_cwe = summary.get("by_cwe", {})
                    if by_cwe:
                        y += 1
                        safe_addstr(stdscr, y, 4, "Top CWEs:", curses.color_pair(C_TITLE))
                        y += 1
                        for cwe, count in sorted(by_cwe.items(), key=lambda x: -x[1])[:8]:
                            if y >= h - 3:
                                break
                            safe_addstr(stdscr, y, 6, f"{cwe:>28s}: {count}", curses.color_pair(C_MUTED))
                            y += 1

                except (json.JSONDecodeError, OSError):
                    safe_addstr(stdscr, y, 4, "Could not read results file.", curses.color_pair(C_ERR))

        draw_footer(stdscr, "  o: open in viewer  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key == ord('o'):
            _open_viewer_for(stdscr, entry)
        elif key in (27, ord('q'), curses.KEY_BACKSPACE, 127):
            return


# ═══════════════════════════════════════════════════════════
#  Open Viewer Screen
# ═══════════════════════════════════════════════════════════

def open_viewer_screen(stdscr):
    entries = load_history()
    entries = [e for e in entries if e.get("output_dir") and Path(e["output_dir"]).exists()]
    if not entries:
        show_message(stdscr, "No scan results with viewer found.", C_WARN)
        return

    sel = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        draw_header(stdscr, "Open Viewer", w)

        safe_addstr(stdscr, 2, 2, "Select a scan to open in browser:", curses.color_pair(C_TITLE))
        for i, e in enumerate(entries[:h-6]):
            is_sel = i == sel
            prefix = " > " if is_sel else "   "
            attr = curses.A_BOLD if is_sel else curses.A_NORMAL
            target = e.get("repo_name") or e.get("target", "unknown")
            if len(target) > 20:
                target = "..." + target[-17:]
            ts = e.get("scan_time", "")[:19].replace("T", " ")
            safe_addstr(stdscr, 4 + i, 2, f"{prefix}{target:20s}  {ts}", attr)

        draw_footer(stdscr, "  Enter: open in browser  |  Esc: back", h, w)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')):
            sel = max(0, sel - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            sel = min(len(entries) - 1, sel + 1)
        elif key in (curses.KEY_ENTER, 10, 13):
            _open_viewer_for(stdscr, entries[sel])
        elif key in (27, ord('q'), curses.KEY_BACKSPACE, 127):
            return


def _open_viewer_for(stdscr, entry):
    out_dir = entry.get("output_dir", "")
    if not out_dir:
        show_message(stdscr, "No output directory for this scan.", C_ERR)
        return

    viewer_html = Path(out_dir) / "index.html"
    venom_data = Path(out_dir) / "venom-data.json"

    if not viewer_html.exists():
        viewer_src = Path(__file__).parent.parent / "viewer" / "index.html"
        if viewer_src.exists():
            shutil.copy2(str(viewer_src), str(viewer_html))
        else:
            show_message(stdscr, "Viewer not found. Re-run with --html.", C_ERR)
            return

    if not venom_data.exists():
        show_message(stdscr, "venom-data.json not found in output dir.", C_ERR)
        return

    try:
        curses.endwin()

        port = 8384
        import http.server
        import threading

        os.chdir(out_dir)

        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", port), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        url = f"http://127.0.0.1:{port}/index.html"
        print(f"\n  Serving viewer at: {url}")
        print(f"  Output dir: {out_dir}")

        for opener in ["xdg-open", "open", "sensible-browser"]:
            if shutil.which(opener):
                subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
        else:
            print(f"  Open this URL manually: {url}")

        print("  Press Enter to stop server and return...")
        input()
        server.shutdown()

    except Exception as e:
        print(f"  Error: {e}")
        print(f"  You can open the file directly: {viewer_html}")
        print("  Press Enter to continue...")
        input()

    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    curses.curs_set(0)
    init_colors()


# ═══════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════

def show_message(stdscr, msg, color=C_MUTED):
    h, w = stdscr.getmaxyx()
    y = h // 2
    padded = f"  {msg}  "
    x = max(0, (w - len(padded)) // 2)
    safe_addstr(stdscr, y, x, padded, curses.color_pair(color) | curses.A_BOLD)
    safe_addstr(stdscr, y + 2, max(0, (w - 20) // 2), "Press any key...", curses.color_pair(C_MUTED))
    stdscr.refresh()
    stdscr.getch()


def confirm(stdscr, msg):
    h, w = stdscr.getmaxyx()
    y = h // 2
    padded = f"  {msg} (y/n)  "
    x = max(0, (w - len(padded)) // 2)
    safe_addstr(stdscr, y, x, padded, curses.color_pair(C_WARN) | curses.A_BOLD)
    stdscr.refresh()
    key = stdscr.getch()
    return key in (ord('y'), ord('Y'))


# ═══════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════

def run():
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        print("Error: TUI requires an interactive terminal.", file=sys.stderr)
        print("Run this command directly in your terminal, not piped.", file=sys.stderr)
        print("  python -m venom --tui", file=sys.stderr)
        sys.exit(1)
    try:
        curses.wrapper(main_menu)
    except curses.error as e:
        print(f"Error: Terminal initialization failed: {e}", file=sys.stderr)
        print("Make sure you're running in a proper terminal emulator.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
