#!/usr/bin/env python3
"""Venom: LLM-Assisted Unified Static Analyzer for C/C++ Bug Detection."""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="venom",
        description="Venom — LLM-assisted unified static analyzer for practical bug detection in C/C++",
    )
    parser.add_argument("target", nargs="?", help="Target directory or file to analyze")
    parser.add_argument("--tui", action="store_true", help="Launch interactive TUI")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    parser.add_argument("-k", "--top-k", type=int, default=50, help="Number of top candidates for LLM triage")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM triage step")
    parser.add_argument("--analyzers", nargs="+", help="Run only these analyzers (by name)")
    parser.add_argument("--exclude", nargs="+", help="Exclude these analyzers (by name)")
    parser.add_argument("--tiers", nargs="+", type=int, choices=[1, 2, 3, 4],
                        help="Run only these tiers (1=fast sweep, 2=path-sensitive, 3=whole-program, 4=targeted)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Minimum severity to report")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    parser.add_argument("--sarif", action="store_true", help="Output SARIF to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--html", action="store_true", help="Generate HTML viewer")
    parser.add_argument("--no-guided-focus", action="store_true",
                        help="Disable guided focusing (don't use Tier 1 hotspots to focus later tiers)")
    parser.add_argument("--git-meta", help="Path to JSON file with git metadata (from scan-lib.sh)")
    parser.add_argument("--model", default=None,
                        help="LLM model for triage (default: claude-sonnet-5-5)")
    args = parser.parse_args()

    if args.tui or (not args.target and sys.stdin.isatty()):
        from venom.tui import run
        run()
        return

    if not args.target:
        parser.error("target is required (or use --tui for interactive mode)")

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"Error: target '{args.target}' does not exist", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    print(f"{'='*60}")
    print(f"  VENOM — Unified Static Analyzer for C/C++")
    print(f"{'='*60}")
    print(f"  Target: {target}")
    print(f"  Output: {output_dir}")
    print()

    # Phase 1: Tiered Alarm Collection
    print("[1/5] Alarm Collection — running static analyzers...")
    from venom.analyzers import get_analyzers_by_tier, get_all_analyzers, ANALYZER_TIERS

    tiers = get_analyzers_by_tier()
    active_tiers = args.tiers or sorted(tiers.keys())

    all_findings = []
    available_analyzers = []
    hotspot_files = set()
    tier_findings = {}

    for tier_num in sorted(active_tiers):
        tier_info = tiers.get(tier_num)
        if not tier_info:
            continue

        tier_analyzers = tier_info["analyzers"]

        if args.analyzers:
            tier_analyzers = [a for a in tier_analyzers if a.name in args.analyzers]
        if args.exclude:
            tier_analyzers = [a for a in tier_analyzers if a.name not in args.exclude]

        if not tier_analyzers:
            continue

        print(f"\n  ── Tier {tier_num}: {tier_info['name']} ──")
        if args.verbose:
            print(f"     {tier_info['description']}")

        findings_this_tier = []
        for analyzer in tier_analyzers:
            if not analyzer.is_available():
                print(f"  [{analyzer.name}] not installed — skipping")
                continue
            print(f"  [{analyzer.name}] running...", end=" ", flush=True)
            t0 = time.time()
            findings = analyzer.analyze(target)
            dt = time.time() - t0
            findings_this_tier.extend(findings)
            available_analyzers.append(analyzer.name)
            print(f"{len(findings)} findings ({dt:.1f}s)")

        all_findings.extend(findings_this_tier)
        tier_findings[tier_num] = findings_this_tier

        for f in findings_this_tier:
            if f.get("file"):
                hotspot_files.add(f["file"])

        if not args.no_guided_focus and tier_num < max(active_tiers) and hotspot_files:
            n_hotspots = len(hotspot_files)
            if args.verbose:
                print(f"     Hotspot files from Tier {tier_num}: {n_hotspots} files flagged")

    if not all_findings:
        print("\n  No findings from any analyzer.")
        _write_empty_output(output_dir, target, available_analyzers, args)
        sys.exit(0)

    print(f"\n  Total raw findings: {len(all_findings)}")
    print(f"  Analyzers used: {', '.join(dict.fromkeys(available_analyzers))}")

    # Phase 2: SARIF Normalization & Deduplication
    print("\n[2/5] Normalizing and deduplicating findings...")
    from venom.sarif import SarifNormalizer

    normalizer = SarifNormalizer()
    normalizer.ingest(all_findings)
    unified = normalizer.deduplicate()
    print(f"  Unified findings after dedup: {len(unified)}")

    # Phase 3: Interface Modeling
    print("\n[3/5] Interface modeling — identifying taint sources and sinks...")
    from venom.interface import InterfaceModeler

    modeler = InterfaceModeler()
    if os.path.isdir(target):
        modeler.analyze_directory(target)
    else:
        modeler.analyze_file(target)
    interface_ctx = modeler.file_interfaces
    n_sources = sum(len(v.get("sources", [])) for v in interface_ctx.values())
    n_sinks = sum(len(v.get("sinks", [])) for v in interface_ctx.values())
    print(f"  Files modeled: {len(interface_ctx)}")
    print(f"  Taint sources: {n_sources}, Taint sinks: {n_sinks}")

    # Phase 4: Ranking
    print("\n[4/5] Building evidence graph and ranking candidates...")
    from venom.ranking import EvidenceGraph, CandidateRanker

    graph = EvidenceGraph()
    graph.build_from_interface(modeler)
    print(f"  Functions: {len(graph.function_files)}, Calls: {sum(len(v) for v in graph.call_graph.values())}")

    ranker = CandidateRanker(graph, modeler)
    ranked = ranker.rank(unified)
    print(f"  Ranked candidates: {len(ranked)}")

    if args.severity:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_sev = sev_order[args.severity]
        ranked = [f for f in ranked if sev_order.get(f.get("severity", "low"), 3) <= min_sev]
        print(f"  After severity filter (>= {args.severity}): {len(ranked)}")

    # Phase 5: LLM Triage
    if not args.no_llm:
        print(f"\n[5/5] LLM triage — assessing top {min(args.top_k, len(ranked))} candidates...")
        from venom.triage import LLMTriager

        triager = LLMTriager(interface_modeler=modeler, evidence_graph=graph,
                             model=args.model, verbose=args.verbose)
        if triager.available:
            print(f"  Model: {triager.model} (agentic)")
            ranked = triager.triage_batch(ranked, top_k=args.top_k)
            confirmed = sum(1 for f in ranked if f.get("triage", {}).get("verdict") == "confirmed")
            likely = sum(1 for f in ranked if f.get("triage", {}).get("verdict") == "likely")
            total_turns = sum(f.get("triage", {}).get("agent_turns", 0) for f in ranked)
            print(f"  LLM verdicts: {confirmed} confirmed, {likely} likely bugs")
            print(f"  Agent investigation: {total_turns} tool calls across {min(args.top_k, len(ranked))} findings")
        else:
            print("  No ANTHROPIC_API_KEY set — skipping LLM triage")
            print("  Set ANTHROPIC_API_KEY to enable agentic LLM triage")
    else:
        print("\n[5/5] LLM triage — skipped (--no-llm)")

    # Generate outputs
    print(f"\n{'='*60}")
    print("  Generating reports...")
    from venom.report import ReportGenerator

    git_meta = {}
    if args.git_meta and os.path.exists(args.git_meta):
        try:
            with open(args.git_meta) as f:
                git_meta = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    metadata = {
        "target": target,
        "analyzers_used": list(dict.fromkeys(available_analyzers)),
        "tiers_run": active_tiers,
        "git": git_meta,
    }
    generator = ReportGenerator(ranked, metadata, evidence_graph=graph, interface_modeler=modeler)

    generator.generate_json(os.path.join(output_dir, "venom-results.json"))
    print(f"  JSON:  {output_dir}/venom-results.json")

    generator.generate_sarif(os.path.join(output_dir, "venom-results.sarif"))
    print(f"  SARIF: {output_dir}/venom-results.sarif")

    html_data_path = os.path.join(output_dir, "venom-data.json")
    base = target if os.path.isdir(target) else os.path.dirname(target)
    generator.generate_html_data(html_data_path, base_path=base)
    print(f"  Data:  {output_dir}/venom-data.json")

    if args.html:
        _copy_viewer(output_dir)
        print(f"  HTML:  {output_dir}/index.html")

    # Summary
    print(f"\n{'='*60}")
    _print_summary(ranked, active_tiers)
    print(f"{'='*60}")

    if args.json:
        json.dump(ranked, sys.stdout, indent=2)
    if args.sarif:
        json.dump(generator._build_sarif(), sys.stdout, indent=2)


def _print_summary(findings, tiers_run=None):
    from collections import Counter

    severities = Counter(f.get("severity", "unknown") for f in findings)
    print("  Summary:")
    for sev in ["critical", "high", "medium", "low"]:
        if severities[sev]:
            print(f"    {sev.upper():10s}: {severities[sev]}")

    if tiers_run:
        from venom.analyzers import ANALYZER_TIERS
        tier_labels = ", ".join(f"T{t} ({ANALYZER_TIERS[t]['name']})" for t in tiers_run)
        print(f"\n  Tiers run: {tier_labels}")

    cwes = Counter(f.get("cwe_id") for f in findings if f.get("cwe_id"))
    if cwes:
        print(f"\n  Top CWEs:")
        for cwe_id, count in cwes.most_common(10):
            name = findings[0].get("cwe_name", "") if findings else ""
            for f in findings:
                if f.get("cwe_id") == cwe_id:
                    name = f.get("cwe_name", "")
                    break
            print(f"    CWE-{str(cwe_id):4s}: {count:3d}  ({name})")

    analyzers = Counter()
    for f in findings:
        for a in f.get("analyzers", [f.get("analyzer", "unknown")]):
            analyzers[a] += 1
    if analyzers:
        print(f"\n  By analyzer:")
        for name, count in analyzers.most_common():
            print(f"    {name:20s}: {count}")

    llm_verdicts = Counter(f.get("triage", {}).get("verdict") for f in findings if f.get("triage", {}).get("verdict"))
    if llm_verdicts:
        print(f"\n  LLM verdicts:")
        for verdict, count in llm_verdicts.most_common():
            print(f"    {verdict:15s}: {count}")


def _write_empty_output(output_dir, target, available_analyzers, args):
    from venom.report import ReportGenerator
    gen = ReportGenerator([], {"target": target, "analyzers_used": available_analyzers})
    gen.generate_json(os.path.join(output_dir, "venom-results.json"))
    gen.generate_sarif(os.path.join(output_dir, "venom-results.sarif"))
    gen.generate_html_data(os.path.join(output_dir, "venom-data.json"))
    if args.html:
        _copy_viewer(output_dir)


def _copy_viewer(output_dir):
    viewer_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "viewer", "index.html")
    if os.path.exists(viewer_src):
        import shutil
        shutil.copy2(viewer_src, os.path.join(output_dir, "index.html"))


if __name__ == "__main__":
    main()
