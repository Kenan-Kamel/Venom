import os
import re
import tempfile

from .base import Analyzer

COCCI_SCRIPTS = {
    "null_deref": {
        "cwe": 476,
        "severity": "high",
        "description": "Dereference without NULL check after allocation",
        "script": r"""
@r@
expression E;
statement S;
position p;
@@

  E = \(malloc\|calloc\|realloc\|kmalloc\|kzalloc\|vmalloc\|kzalloc_node\|kcalloc\)(...);
  ... when != E == NULL
      when != E != NULL
      when != !E
      when != E
      when != if (E)
      when != if (!E)
  E@p->...

@script:python@
p << r.p;
@@
coccilib.report.print_report(p[0], "NULL dereference: pointer used without NULL check after allocation")
""",
    },
    "double_free": {
        "cwe": 415,
        "severity": "critical",
        "description": "Double free of pointer",
        "script": r"""
@r@
expression E;
position p1, p2;
@@

  \(free\|kfree\|vfree\)(E@p1);
  ... when != E = ...
  \(free\|kfree\|vfree\)(E@p2);

@script:python@
p2 << r.p2;
@@
coccilib.report.print_report(p2[0], "Double free: pointer freed twice without reassignment")
""",
    },
    "use_after_free": {
        "cwe": 416,
        "severity": "critical",
        "description": "Use of pointer after free",
        "script": r"""
@r@
expression E;
position p;
@@

  \(free\|kfree\|vfree\)(E);
  ... when != E = ...
(
  E@p->...
|
  *E@p
|
  E@p[...]
)

@script:python@
p << r.p;
@@
coccilib.report.print_report(p[0], "Use after free: pointer dereferenced after being freed")
""",
    },
    "unchecked_alloc": {
        "cwe": 476,
        "severity": "high",
        "description": "Return value of allocation not checked",
        "script": r"""
@r@
expression E;
type T;
position p;
@@

(
  E@p = (T)\(malloc\|calloc\|kmalloc\|kzalloc\|vmalloc\|kcalloc\)(...);
|
  E@p = \(malloc\|calloc\|kmalloc\|kzalloc\|vmalloc\|kcalloc\)(...);
)
  ... when != E == NULL
      when != E != NULL
      when != !E
      when != if (\(E\|!E\))
      when forall
  E->...

@script:python@
p << r.p;
@@
coccilib.report.print_report(p[0], "Unchecked allocation: return value not checked before use")
""",
    },
}

_REPORT_RE = re.compile(
    r"^(\S+):(\d+):(\d+)?[-\d]*:\s*(.+)"
)


class CoccinelleAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "coccinelle"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["spatch", "--version"])
            return r.stdout.strip() or r.stderr.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("spatch") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        files = self.collect_files(target_path, self.C_EXTENSIONS | {".cpp", ".cc"})
        if not files:
            return []

        findings: list[dict] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for script_name, script_info in COCCI_SCRIPTS.items():
                cocci_path = os.path.join(tmpdir, f"{script_name}.cocci")
                with open(cocci_path, "w") as f:
                    f.write(script_info["script"])

                for fpath in files:
                    try:
                        findings.extend(
                            self._run_script(cocci_path, fpath, script_name, script_info)
                        )
                    except Exception:
                        continue

        return findings

    def _run_script(
        self,
        cocci_path: str,
        fpath: str,
        script_name: str,
        script_info: dict,
    ) -> list[dict]:
        r = self.run([
            "spatch",
            "--very-quiet",
            "--sp-file", cocci_path,
            fpath,
        ], timeout=60)

        combined = r.stdout + "\n" + r.stderr
        findings = []
        seen = set()

        for line in combined.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _REPORT_RE.match(line)
            if m:
                src_file = m.group(1)
                line_no = int(m.group(2))
                col = int(m.group(3)) if m.group(3) else 0
                msg = m.group(4).strip()

                key = (src_file, line_no, script_name)
                if key in seen:
                    continue
                seen.add(key)

                if not msg or msg.startswith("-") or msg.startswith("+"):
                    msg = script_info["description"]

                findings.append(self.finding(
                    file=src_file if os.path.isabs(src_file) else os.path.abspath(src_file),
                    line=line_no,
                    column=col,
                    message=msg,
                    severity=script_info["severity"],
                    cwe=script_info["cwe"],
                    category=f"coccinelle:{script_name}",
                    confidence="high",
                ))

        return findings
