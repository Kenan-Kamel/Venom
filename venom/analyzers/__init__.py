from .gcc_fanalyzer import GccFanalyzer
from .csa import ClangStaticAnalyzer
from .cppcheck_runner import CppcheckAnalyzer
from .flawfinder_runner import FlawfinderAnalyzer
from .clang_tidy_runner import ClangTidyAnalyzer
from .semgrep_runner import SemgrepAnalyzer
from .sparse_runner import SparseAnalyzer
from .infer_runner import InferAnalyzer
from .ikos_runner import IkosAnalyzer
from .codeql_runner import CodeQLAnalyzer
from .smatch_runner import SmatchAnalyzer
from .framac_runner import FramaCAnalyzer
from .goblint_runner import GoblintAnalyzer
from .svf_runner import SvfSaberAnalyzer
from .coccinelle_runner import CoccinelleAnalyzer
from .knighter_runner import KNighterAnalyzer

ALL_ANALYZERS = [
    GccFanalyzer,
    ClangStaticAnalyzer,
    CppcheckAnalyzer,
    FlawfinderAnalyzer,
    ClangTidyAnalyzer,
    SemgrepAnalyzer,
    SparseAnalyzer,
    InferAnalyzer,
    IkosAnalyzer,
    CodeQLAnalyzer,
    SmatchAnalyzer,
    FramaCAnalyzer,
    GoblintAnalyzer,
    SvfSaberAnalyzer,
    CoccinelleAnalyzer,
    KNighterAnalyzer,
]

ANALYZER_TIERS = {
    1: {
        "name": "Fast sweep",
        "description": "Lexical and pattern-based scanners — broad coverage, fast execution",
        "analyzers": ["cppcheck", "flawfinder", "sparse", "clang-tidy"],
    },
    2: {
        "name": "Path-sensitive",
        "description": "Symbolic execution per translation unit — confirms or kills Tier 1 hits",
        "analyzers": ["gcc-fanalyzer", "clang-sa", "semgrep"],
    },
    3: {
        "name": "Whole-program",
        "description": "Abstract interpretation and bi-abduction — tracks bugs across files",
        "analyzers": ["infer", "ikos", "frama-c-eva", "saber-svf"],
    },
    4: {
        "name": "Targeted",
        "description": "Domain-specific and query-based — taint flows, concurrency, API misuse, novel patterns",
        "analyzers": ["codeql", "goblint", "coccinelle", "smatch", "knighter"],
    },
}


def get_analyzer_tier(name):
    for tier_num, tier_info in ANALYZER_TIERS.items():
        if name in tier_info["analyzers"]:
            return tier_num
    return 0


def get_all_analyzers():
    return [cls() for cls in ALL_ANALYZERS]


def get_analyzers_by_tier():
    instances = {a.name: a for a in get_all_analyzers()}
    tiers = {}
    for tier_num in sorted(ANALYZER_TIERS.keys()):
        tier_info = ANALYZER_TIERS[tier_num]
        tiers[tier_num] = {
            "name": tier_info["name"],
            "description": tier_info["description"],
            "analyzers": [instances[n] for n in tier_info["analyzers"] if n in instances],
        }
    return tiers
