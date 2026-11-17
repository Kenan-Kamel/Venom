import xml.etree.ElementTree as ET

from .base import Analyzer

CWE_MAP = {
    "nullPointer": 476,
    "nullPointerRedundantCheck": 476,
    "nullPointerDefaultArg": 476,
    "memleak": 401,
    "resourceLeak": 775,
    "bufferAccessOutOfBounds": 120,
    "arrayIndexOutOfBounds": 120,
    "arrayIndexOutOfBoundsCond": 120,
    "outOfBounds": 787,
    "uninitvar": 457,
    "uninitdata": 457,
    "uninitStructMember": 457,
    "doubleFree": 415,
    "deallocuse": 416,
    "useAfterFree": 416,
    "mismatchAllocDealloc": 762,
    "leakReturnValNotUsed": 401,
    "integerOverflow": 190,
    "signedIntegerOverflow": 190,
    "shiftTooManyBits": 682,
    "negativeIndex": 129,
    "formatString": 134,
    "invalidPrintfArgType_sint": 134,
    "invalidScanfArgType_int": 134,
    "wrongPrintfScanfArgNum": 134,
    "divisionByZero": 369,
    "zerodiv": 369,
    "danglingLifetime": 562,
    "returnDanglingLifetime": 562,
    "containerOutOfBounds": 120,
    "stringLiteralWrite": 843,
}

SEVERITY_NORM = {
    "error": "error",
    "warning": "warning",
    "style": "info",
    "performance": "info",
    "portability": "info",
    "information": "info",
}

CONFIDENCE_HIGH_IDS = {
    "nullPointer", "memleak", "doubleFree", "deallocuse",
    "bufferAccessOutOfBounds", "arrayIndexOutOfBounds",
    "divisionByZero", "useAfterFree",
}


class CppcheckAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "cppcheck"

    @property
    def version(self) -> str:
        if not self.is_available():
            return "n/a"
        try:
            r = self.run(["cppcheck", "--version"])
            return r.stdout.strip()
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        return self.which("cppcheck") is not None

    def analyze(self, target_path: str, build_dir: str | None = None) -> list[dict]:
        if not self.is_available():
            return []

        cmd = [
            "cppcheck",
            "--xml", "--xml-version=2",
            "--enable=all",
            "--inconclusive",
            "--force",
            "--quiet",
            target_path,
        ]
        try:
            r = self.run(cmd, timeout=300)
        except Exception:
            return []

        return self._parse_xml(r.stderr)

    def _parse_xml(self, xml_str: str) -> list[dict]:
        if not xml_str.strip():
            return []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return []

        findings = []
        for error in root.iter("error"):
            eid = error.get("id", "")
            sev = error.get("severity", "warning")
            msg = error.get("msg", "")
            verbose = error.get("verbose", msg)
            cwe_attr = error.get("cwe")

            if eid in ("missingIncludeSystem", "missingInclude", "toomanyconfigs", "unmatchedSuppression"):
                continue

            cwe_val = CWE_MAP.get(eid)
            if cwe_val is None and cwe_attr:
                try:
                    cwe_val = int(cwe_attr)
                except (ValueError, TypeError):
                    pass

            for loc in error.iter("location"):
                fpath = loc.get("file", "")
                line = int(loc.get("line", 0))
                col = int(loc.get("column", 0))

                findings.append(self.finding(
                    file=fpath, line=line, column=col,
                    message=verbose or msg,
                    severity=SEVERITY_NORM.get(sev, "warning"),
                    cwe=cwe_val,
                    category=eid,
                    confidence="high" if eid in CONFIDENCE_HIGH_IDS else "medium",
                ))
                break
            else:
                findings.append(self.finding(
                    file="<unknown>", line=0, column=0,
                    message=verbose or msg,
                    severity=SEVERITY_NORM.get(sev, "warning"),
                    cwe=cwe_val,
                    category=eid,
                    confidence="low",
                ))

        return findings
