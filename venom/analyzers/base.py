import hashlib
import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod


class Analyzer(ABC):
    C_EXTENSIONS = {".c", ".h"}
    CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".c++", ".h++"}
    ALL_EXTENSIONS = C_EXTENSIONS | CPP_EXTENSIONS

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    def version(self) -> str:
        return "unknown"

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        ...

    # ── helpers ──

    @staticmethod
    def which(name: str) -> str | None:
        return shutil.which(name)

    @staticmethod
    def run(cmd: list[str], *, timeout: int = 300, **kw) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            **kw,
        )

    def collect_files(self, target_path: str, extensions: set[str] | None = None) -> list[str]:
        exts = extensions or self.ALL_EXTENSIONS
        if os.path.isfile(target_path):
            if os.path.splitext(target_path)[1].lower() in exts:
                return [os.path.abspath(target_path)]
            return []
        result = []
        for root, _dirs, files in os.walk(target_path):
            for f in sorted(files):
                if os.path.splitext(f)[1].lower() in exts:
                    result.append(os.path.join(root, f))
        return result

    @staticmethod
    def read_snippet(filepath: str, line: int, context: int = 3) -> str:
        try:
            with open(filepath, errors="replace") as fh:
                lines = fh.readlines()
            start = max(0, line - 1 - context)
            end = min(len(lines), line + context)
            return "".join(lines[start:end])
        except OSError:
            return ""

    @staticmethod
    def make_id(*parts: str) -> str:
        h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
        return h

    @staticmethod
    def parse_gcc_diag(line: str) -> dict | None:
        m = re.match(
            r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+"
            r"(?P<sev>warning|error|note):\s+(?P<msg>.+?)(?:\s+\[(?P<flag>-W[^\]]+)\])?\s*$",
            line,
        )
        if not m:
            return None
        return m.groupdict()

    def finding(
        self,
        *,
        file: str,
        line: int,
        column: int = 0,
        message: str,
        severity: str = "warning",
        cwe: int | None = None,
        category: str = "",
        confidence: str = "medium",
        extra: dict | None = None,
    ) -> dict:
        fid = self.make_id(self.name, file, str(line), message)
        d = {
            "id": fid,
            "file": file,
            "line": line,
            "column": column,
            "message": message,
            "severity": severity,
            "cwe": cwe,
            "analyzer": self.name,
            "category": category,
            "confidence": confidence,
            "code_snippet": self.read_snippet(file, line),
        }
        if extra:
            d.update(extra)
        return d
