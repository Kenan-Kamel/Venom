import os
import re
import tempfile

from .base import Analyzer

CWE_MAP = {
    "valid": 476,
    "valid_read": 125,
    "valid_write": 787,
    "division_by_zero": 369,
    "signed_overflow": 190,
    "unsigned_overflow": 190,
    "pointer_comparison": 467,
    "mem_access": 125,
    "initialization": 457,
    "dangling": 416,
    "shift": 682,
    "float_to_int": 681,
    "is_nan_or_infinite": 681,
}

_ALARM_RE = re.compile(
    r"\[eva(?::alarm)?\]\s+(\S+):(\d+):\s+(Warning|Error):\s+(.+)"
)
_ASSERT_RE = re.compile(r"assert\s+\\(\w+)")

CONFIDENCE_HIGH = {"valid", "valid_read", "valid_write", "division_by_zero", "dangling"}


class FramaCAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "frama-c-eva"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["frama-c", "-version"])
            return r.stdout.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("frama-c") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS)
        if not files:
            return []

        findings: list[dict] = []
        for fpath in files:
            try:
                findings.extend(self._analyze_file(fpath))
            except Exception:
                continue
        return findings

    def _analyze_file(self, fpath: str) -> list[dict]:
        r = self.run([
            "frama-c", "-eva",
            "-eva-precision", "3",
            "-kernel-msg-key", "alarm",
            "-eva-warn-undefined-pointer-comparison", "all",
            "-no-val-show-progress",
            fpath,
        ], timeout=180)

        combined = r.stdout + "\n" + r.stderr
        findings = []
        seen = set()

        for m in _ALARM_RE.finditer(combined):
            src_file = m.group(1)
            line = int(m.group(2))
            level = m.group(3)
            message = m.group(4).strip()

            key = (src_file, line, message[:60])
            if key in seen:
                continue
            seen.add(key)

            if not os.path.isabs(src_file):
                src_file = os.path.abspath(src_file)

            cwe, category = self._classify(message)
            confidence = "high" if category in CONFIDENCE_HIGH else "medium"

            findings.append(self.finding(
                file=src_file,
                line=line,
                message=message,
                severity="error" if level == "Error" else "warning",
                cwe=cwe,
                category=f"eva:{category}",
                confidence=confidence,
            ))

        return findings

    def _classify(self, message: str) -> tuple[int | None, str]:
        msg_lower = message.lower()

        am = _ASSERT_RE.search(message)
        if am:
            kind = am.group(1).lower()
            if kind in ("valid", "valid_read"):
                if "null" in msg_lower or "0" in msg_lower:
                    return 476, "valid"
                return CWE_MAP.get(kind), kind
            if kind == "valid_write":
                return 787, "valid_write"
            if kind in CWE_MAP:
                return CWE_MAP[kind], kind

        if "division by zero" in msg_lower:
            return 369, "division_by_zero"
        if "signed overflow" in msg_lower:
            return 190, "signed_overflow"
        if "unsigned overflow" in msg_lower:
            return 190, "unsigned_overflow"
        if "dangling" in msg_lower:
            return 416, "dangling"
        if "uninitialized" in msg_lower or "initialization" in msg_lower:
            return 457, "initialization"
        if "out of bounds" in msg_lower or "mem_access" in msg_lower:
            return 125, "mem_access"
        if "shift" in msg_lower:
            return 682, "shift"

        return None, "unknown"
