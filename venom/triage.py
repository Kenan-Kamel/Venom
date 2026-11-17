import json
import os
import re

from .cwe import get_cwe
from .interface import find_function_at_line

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_AGENT_TURNS = 10

SYSTEM_PROMPT = """\
You are an expert security auditor triaging static analysis findings in C/C++ code.

You have tools to investigate the codebase. Your job is to determine whether each \
reported finding is a real, exploitable vulnerability or a false positive.

Investigation strategy:
1. Read the code at the reported location to understand what's happening
2. Trace data flow — where does input come from? Can an attacker control it?
3. Check for guards, sanitization, or bounds checks that prevent exploitation
4. Examine callers to determine if the vulnerable code is reachable from an entry point
5. Consider context — is this test code, dead code, or a production path?

When you have enough evidence, call submit_verdict with your assessment. Be thorough \
but efficient — focus on what determines exploitability."""

TOOLS = [
    {
        "name": "read_source_code",
        "description": "Read source code lines from a file. Use this to examine code around the reported vulnerability, follow function calls, or check for guards and sanitization.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Absolute path to the source file"},
                "start_line": {"type": "integer", "description": "Start line (1-based). Defaults to 1."},
                "end_line": {"type": "integer", "description": "End line (1-based). Defaults to start_line + 100."},
            },
            "required": ["file"],
        },
    },
    {
        "name": "get_function_info",
        "description": "Get information about a function: its file location, callers, callees, and taint sources/sinks in scope.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Name of the function to look up"},
            },
            "required": ["function_name"],
        },
    },
    {
        "name": "get_file_interface",
        "description": "Get the interface model for a source file: entry points, exported functions, taint sources and sinks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Absolute path to the source file"},
            },
            "required": ["file"],
        },
    },
    {
        "name": "search_code",
        "description": "Search for a regex pattern in a source file. Returns matching lines with line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "file": {"type": "string", "description": "Absolute path to the file to search"},
            },
            "required": ["pattern", "file"],
        },
    },
    {
        "name": "trace_callers",
        "description": "Trace the transitive caller chain of a function up to a given depth. Shows how attacker-controlled input might reach the vulnerable code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function to trace callers for"},
                "depth": {"type": "integer", "description": "Max trace depth (default: 3)"},
            },
            "required": ["function_name"],
        },
    },
    {
        "name": "list_source_files",
        "description": "List C/C++ source files in a directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Directory to list"},
            },
            "required": ["directory"],
        },
    },
    {
        "name": "submit_verdict",
        "description": "Submit your final assessment of this finding. Call this once when you have enough evidence. This ends the investigation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["confirmed", "likely", "unlikely", "false_positive"],
                },
                "confidence": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                },
                "reachable": {
                    "type": "string",
                    "enum": ["yes", "no", "unknown"],
                    "description": "Whether attacker-controlled input can reach this code",
                },
                "impact": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "explanation": {
                    "type": "string",
                    "description": "Detailed explanation with evidence",
                },
                "attack_scenario": {
                    "type": "string",
                    "description": "How this could be exploited, or why it cannot be",
                },
                "evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Key evidence supporting your verdict",
                },
            },
            "required": ["verdict", "confidence", "reachable", "impact", "explanation"],
        },
    },
]


class LLMTriager:
    def __init__(self, interface_modeler=None, evidence_graph=None, api_key=None,
                 model=None, verbose=False):
        self.modeler = interface_modeler
        self.graph = evidence_graph
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or DEFAULT_MODEL
        self.verbose = verbose
        self.client = None
        if HAS_ANTHROPIC and self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)

    @property
    def available(self):
        return self.client is not None

    def _execute_tool(self, name, input_data):
        try:
            if name == "read_source_code":
                return self._tool_read_source(input_data)
            elif name == "get_function_info":
                return self._tool_function_info(input_data)
            elif name == "get_file_interface":
                return self._tool_file_interface(input_data)
            elif name == "search_code":
                return self._tool_search_code(input_data)
            elif name == "trace_callers":
                return self._tool_trace_callers(input_data)
            elif name == "list_source_files":
                return self._tool_list_files(input_data)
            else:
                return f"Unknown tool: {name}"
        except Exception as e:
            return f"Error: {e}"

    def _tool_read_source(self, params):
        file_path = params["file"]
        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except (OSError, IOError) as e:
            return f"Cannot read {file_path}: {e}"

        start = max(1, params.get("start_line", 1))
        end = min(len(lines), params.get("end_line", start + 100))

        numbered = []
        for i in range(start - 1, end):
            numbered.append(f"{i + 1:5d}  {lines[i].rstrip()}")
        return "\n".join(numbered) if numbered else "No lines in range."

    def _tool_function_info(self, params):
        func_name = params["function_name"]
        info = {}

        if self.modeler:
            loc = self.modeler.function_locations.get(func_name)
            info["location"] = f"{loc['file']}:{loc['line']}" if loc else "not found"
            taint = self.modeler.get_function_taint(func_name)
            info["taint_sources"] = taint.get("sources", [])
            info["taint_sinks"] = taint.get("sinks", [])
            info["callers"] = self.modeler.get_callers(func_name)[:20]
            info["callees"] = self.modeler.get_callees(func_name)[:20]
            info["has_taint_flow"] = self.modeler.function_has_taint_flow(func_name)

        if self.graph:
            info["transitive_callers"] = list(self.graph.get_callers(func_name, depth=2))[:20]
            info["transitive_callees"] = list(self.graph.get_callees(func_name, depth=2))[:20]

        return json.dumps(info, indent=2) if info else f"No information found for '{func_name}'."

    def _tool_file_interface(self, params):
        file_path = params["file"]
        if not self.modeler:
            return "Interface modeler not available."

        iface = self.modeler.file_interfaces.get(file_path)
        if not iface:
            return f"No interface data for {file_path}."

        result = {
            "functions": iface.get("functions", []),
            "entry_points": iface.get("entry_points", []),
            "exported": iface.get("exported", []),
            "syscall_handlers": iface.get("syscall_handlers", []),
            "taint_sources": [
                f"{s['function']} uses {s['source']}" for s in iface.get("sources", [])
            ],
            "taint_sinks": [
                f"{s['function']} uses {s['sink']}" for s in iface.get("sinks", [])
            ],
        }
        return json.dumps(result, indent=2)

    def _tool_search_code(self, params):
        pattern = params["pattern"]
        file_path = params["file"]
        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except (OSError, IOError) as e:
            return f"Cannot read {file_path}: {e}"

        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"Invalid regex: {e}"

        matches = []
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                matches.append(f"{i:5d}  {line.rstrip()}")

        if not matches:
            return f"No matches for /{pattern}/ in {file_path}."
        return "\n".join(matches[:50])

    def _tool_trace_callers(self, params):
        func_name = params["function_name"]
        depth = params.get("depth", 3)

        if not self.graph:
            return "Evidence graph not available."

        callers = self.graph.get_callers(func_name, depth=depth)
        if not callers:
            return f"No callers found for '{func_name}'. It may be an entry point or unreferenced."

        result_lines = [f"Callers of {func_name} (depth {depth}):"]
        for caller in sorted(callers):
            loc = ""
            if self.modeler and caller in self.modeler.function_locations:
                l = self.modeler.function_locations[caller]
                loc = f" ({l['file']}:{l['line']})"
            taint = ""
            if self.modeler:
                t = self.modeler.get_function_taint(caller)
                if t.get("sources"):
                    taint = f" [TAINT SOURCES: {', '.join(t['sources'])}]"
            result_lines.append(f"  - {caller}{loc}{taint}")
        return "\n".join(result_lines)

    def _tool_list_files(self, params):
        directory = params["directory"]
        exts = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}
        files = []
        try:
            for root, _dirs, fnames in os.walk(directory):
                for fname in sorted(fnames):
                    if any(fname.endswith(ext) for ext in exts):
                        files.append(os.path.join(root, fname))
        except OSError as e:
            return f"Cannot list {directory}: {e}"
        return "\n".join(files) if files else "No C/C++ source files found."

    def triage_finding(self, finding):
        if not self.available:
            finding["triage"] = {
                "verdict": "untriaged",
                "reachable": "unknown",
                "impact": finding["severity"],
                "explanation": "LLM triage unavailable (no API key or anthropic not installed)",
                "attack_scenario": None,
            }
            return finding

        cwe = get_cwe(finding.get("cwe_id") or finding.get("cwe"))

        finding_desc = (
            f"## Static Analysis Finding to Investigate\n\n"
            f"- **CWE**: {finding.get('cwe_id', finding.get('cwe', 'unknown'))} — {cwe.get('name', 'Unknown')}\n"
            f"- **File**: {finding['file']}:{finding['line']}\n"
            f"- **Severity**: {finding['severity']}\n"
            f"- **Message**: {finding['message']}\n"
            f"- **Reported by**: {', '.join(finding.get('analyzers', [finding.get('analyzer', 'unknown')]))}\n"
        )

        if finding.get("function"):
            finding_desc += f"- **Function**: {finding['function']}\n"

        if finding.get("all_messages"):
            finding_desc += "\n### All analyzer messages:\n"
            for msg in finding["all_messages"]:
                finding_desc += f"- {msg}\n"

        finding_desc += (
            "\n\nInvestigate this finding. Read the code, trace the data flow, "
            "check for guards, and determine if this is exploitable. "
            "Call submit_verdict when you have your assessment."
        )

        messages = [{"role": "user", "content": finding_desc}]

        verdict_data = None
        agent_trace = []

        for turn in range(MAX_AGENT_TURNS):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=16000,
                    system=SYSTEM_PROMPT,
                    thinking={"type": "adaptive"},
                    tools=TOOLS,
                    messages=messages,
                )
            except Exception as e:
                finding["triage"] = {
                    "verdict": "error",
                    "reachable": "unknown",
                    "impact": finding["severity"],
                    "explanation": f"LLM agent error: {e}",
                    "attack_scenario": None,
                }
                return finding

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason != "tool_use":
                break

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if block.name == "submit_verdict":
                        verdict_data = block.input
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Verdict recorded.",
                        })
                        if self.verbose:
                            print(f"    verdict: {verdict_data.get('verdict')} "
                                  f"({verdict_data.get('confidence')} confidence)")
                    else:
                        result = self._execute_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result,
                        })
                        agent_trace.append({
                            "tool": block.name,
                            "input": block.input,
                        })
                        if self.verbose:
                            summary = json.dumps(block.input, separators=(",", ":"))
                            print(f"    [{block.name}] {summary[:80]}")

            messages.append({"role": "user", "content": tool_results})

            if verdict_data:
                break

        if verdict_data:
            finding["triage"] = {
                "verdict": verdict_data.get("verdict", "unknown"),
                "confidence": verdict_data.get("confidence", "medium"),
                "reachable": verdict_data.get("reachable", "unknown"),
                "impact": verdict_data.get("impact", finding["severity"]),
                "explanation": verdict_data.get("explanation", ""),
                "attack_scenario": verdict_data.get("attack_scenario"),
                "evidence": verdict_data.get("evidence", []),
                "agent_turns": len(agent_trace),
            }
        else:
            text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    text += block.text
            finding["triage"] = {
                "verdict": "unknown",
                "reachable": "unknown",
                "impact": finding["severity"],
                "explanation": text[:500] if text else "Agent did not submit a structured verdict.",
                "attack_scenario": None,
                "agent_turns": len(agent_trace),
            }

        return finding

    def triage_batch(self, findings, top_k=None):
        to_triage = findings[:top_k] if top_k else findings
        triaged = []
        for i, f in enumerate(to_triage):
            if self.verbose:
                print(f"  [{i + 1}/{len(to_triage)}] {f['file']}:{f['line']} "
                      f"— {f['message'][:60]}")
            triaged.append(self.triage_finding(f))

        remaining = findings[len(to_triage):]
        for f in remaining:
            f["triage"] = {
                "verdict": "untriaged",
                "reachable": "unknown",
                "impact": f["severity"],
                "explanation": "Not triaged (below top-k cutoff)",
                "attack_scenario": None,
            }
            triaged.append(f)

        return triaged
