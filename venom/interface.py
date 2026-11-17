import os
import re
from collections import defaultdict

TAINT_SOURCES = [
    "recv", "recvfrom", "recvmsg", "read", "fread", "pread",
    "scanf", "fscanf", "sscanf", "vscanf",
    "gets", "fgets", "getline", "getdelim",
    "getenv", "getc", "fgetc",
    "copy_from_user", "__copy_from_user", "get_user", "__get_user",
    "accept", "accept4",
    "mmap",
]

TAINT_SINKS = [
    "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "printf", "fprintf", "vprintf", "vfprintf",
    "system", "popen", "execl", "execle", "execlp", "execv", "execvp", "execve",
    "write", "fwrite", "pwrite", "send", "sendto", "sendmsg",
    "free", "realloc", "kfree",
    "malloc", "calloc", "kmalloc", "kzalloc", "vmalloc",
    "ioctl",
]

_FUNC_DEF_RE = re.compile(
    r"^[ \t]*(?:static\s+|inline\s+|extern\s+|__attribute__\S+\s+)*"
    r"(?:(?:unsigned|signed|long|short|const|volatile|struct|enum|union)\s+)*"
    r"\w+[\s*]+"
    r"(\w+)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)

_FUNC_CALL_RE = re.compile(r"\b(\w+)\s*\(")

_SYSCALL_RE = re.compile(r"SYSCALL_DEFINE\d+\s*\(\s*(\w+)")
_COMPAT_SYS_RE = re.compile(r"\bcompat_sys_(\w+)")
_IOCTL_RE = re.compile(r"(\w*ioctl\w*)\s*\(")
_MODULE_INIT_RE = re.compile(r"module_init\s*\(\s*(\w+)\s*\)")
_INIT_FUNC_RE = re.compile(r"__init\s+\w+\s+(\w+)\s*\(")
_EXPORT_ATTR_RE = re.compile(r'__attribute__\s*\(\s*\(\s*visibility\s*\(\s*"default"\s*\)\s*\)\s*\)')


class InterfaceModeler:
    def __init__(self):
        self.file_interfaces = {}
        self.function_taint = defaultdict(lambda: {"sources": [], "sinks": []})
        self.call_graph = defaultdict(set)
        self.function_locations = {}

    def analyze_file(self, file_path):
        try:
            with open(file_path, "r", errors="replace") as f:
                content = f.read()
        except (OSError, IOError):
            return {}

        lines = content.split("\n")
        interface = {
            "sources": [],
            "sinks": [],
            "entry_points": [],
            "exported": [],
            "syscall_handlers": [],
            "functions": [],
        }

        functions = []
        for m in _FUNC_DEF_RE.finditer(content):
            name = m.group(1)
            start_line = content[:m.start()].count("\n") + 1
            functions.append({"name": name, "line": start_line, "offset": m.start()})
            self.function_locations[name] = {"file": file_path, "line": start_line}

        interface["functions"] = [f["name"] for f in functions]

        func_bodies = self._extract_function_bodies(content, functions)

        for func_name, body in func_bodies.items():
            calls = set(_FUNC_CALL_RE.findall(body))
            self.call_graph[func_name] = calls

            for src in TAINT_SOURCES:
                if src in calls:
                    self.function_taint[func_name]["sources"].append(src)
                    interface["sources"].append({"function": func_name, "source": src})

            for sink in TAINT_SINKS:
                if sink in calls:
                    self.function_taint[func_name]["sinks"].append(sink)
                    interface["sinks"].append({"function": func_name, "sink": sink})

        for m in _SYSCALL_RE.finditer(content):
            handler = f"sys_{m.group(1)}"
            interface["syscall_handlers"].append(handler)
            interface["entry_points"].append(handler)

        for m in _COMPAT_SYS_RE.finditer(content):
            interface["syscall_handlers"].append(f"compat_sys_{m.group(1)}")

        for m in _MODULE_INIT_RE.finditer(content):
            interface["entry_points"].append(m.group(1))

        for m in _INIT_FUNC_RE.finditer(content):
            interface["entry_points"].append(m.group(1))

        if re.search(r"\bmain\s*\(", content):
            interface["entry_points"].append("main")

        if file_path.endswith(".h"):
            for func in functions:
                interface["exported"].append(func["name"])

        for func in functions:
            start = func["offset"]
            prefix = content[max(0, start - 200):start]
            if _EXPORT_ATTR_RE.search(prefix):
                interface["exported"].append(func["name"])

        self.file_interfaces[file_path] = interface
        return interface

    def _extract_function_bodies(self, content, functions):
        bodies = {}
        for i, func in enumerate(functions):
            start = func["offset"]
            brace_count = 0
            in_func = False
            end = start
            for j in range(start, len(content)):
                if content[j] == "{":
                    brace_count += 1
                    in_func = True
                elif content[j] == "}":
                    brace_count -= 1
                    if in_func and brace_count == 0:
                        end = j + 1
                        break
            bodies[func["name"]] = content[start:end]
        return bodies

    def analyze_directory(self, dir_path, extensions=(".c", ".h", ".cpp", ".cc", ".cxx")):
        for root, _dirs, files in os.walk(dir_path):
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    fpath = os.path.join(root, fname)
                    self.analyze_file(fpath)

    def get_interface_context(self, file_path):
        iface = self.file_interfaces.get(file_path, {})
        return {
            "sources": iface.get("sources", []),
            "sinks": iface.get("sinks", []),
            "is_entry_point": bool(iface.get("entry_points")),
            "is_exported": bool(iface.get("exported")),
            "entry_points": iface.get("entry_points", []),
            "exported": iface.get("exported", []),
            "syscall_handlers": iface.get("syscall_handlers", []),
        }

    def get_function_taint(self, func_name):
        return dict(self.function_taint.get(func_name, {"sources": [], "sinks": []}))

    def function_has_taint_flow(self, func_name):
        taint = self.function_taint.get(func_name, {})
        return bool(taint.get("sources")) and bool(taint.get("sinks"))

    def function_touches_taint(self, func_name):
        taint = self.function_taint.get(func_name, {})
        if taint.get("sources") or taint.get("sinks"):
            return True
        for callee in self.call_graph.get(func_name, set()):
            callee_taint = self.function_taint.get(callee, {})
            if callee_taint.get("sources") or callee_taint.get("sinks"):
                return True
        return False

    def get_callers(self, func_name):
        callers = []
        for caller, callees in self.call_graph.items():
            if func_name in callees:
                callers.append(caller)
        return callers

    def get_callees(self, func_name):
        return list(self.call_graph.get(func_name, set()))


def find_function_at_line(file_path, line_no):
    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except (OSError, IOError):
        return None

    best = None
    for m in _FUNC_DEF_RE.finditer(content):
        func_line = content[:m.start()].count("\n") + 1
        if func_line <= line_no:
            best = m.group(1)
        else:
            break
    return best
