"""`python -m redteam <command>` - run the scan, print/write the report.

    redteam full [--out report.md]        the main deliverable: all 3 chat targets
                                           + the agent probes, one combined report
    redteam scan --target raw|guarded|hardened [--out FILE]
    redteam agent-scan [--out FILE]       agent tool-safety controls only
"""

from __future__ import annotations

import argparse
import sys

from .chat_targets import GuardedChatTarget, RawChatTarget
from .report import render_markdown, summarize_target
from .agent_probes import run_agent_probes
from .runner import FullScanResult, run_chat_scan, run_full_scan

_TARGETS = {
    "raw": lambda: RawChatTarget(),
    "guarded": lambda: GuardedChatTarget(validate_schema=False),
    "hardened": lambda: GuardedChatTarget(validate_schema=True),
}


def _write(text: str, out: str | None) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote {out} ({len(text)} chars)")
    else:
        print(text)


def cmd_full(args: argparse.Namespace) -> int:
    result = run_full_scan()
    report = render_markdown(result, generated_at=args.generated_at)
    _write(report, args.out)
    guarded_vulns = sum(1 for f in result.guarded_findings if f.is_finding and f.verdict.value == "vulnerable")
    agent_vulns = sum(1 for f in result.agent_findings if f.is_finding)
    print(f"\nguarded target: {guarded_vulns} vulnerabilities | agent surface: {agent_vulns} vulnerabilities", file=sys.stderr)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    target = _TARGETS[args.target]()
    findings = run_chat_scan(target)
    summary = summarize_target(target.name, findings)
    lines = [f"# Scan: {target.name}", "", f"attacks run: {summary['total_attacks']}",
              f"vulnerabilities: {summary['vulnerabilities']}", f"false positives: {summary['false_positives']}",
              f"pass rate: {summary['pass_rate']:.0%}", ""]
    for f in findings:
        if f.is_finding:
            lines.append(f"- [{f.severity.value.upper()}] {f.attack.id} ({f.attack.category}): {f.attack.technique}")
    _write("\n".join(lines), args.out)
    return 0


def cmd_agent_scan(args: argparse.Namespace) -> int:
    findings = run_agent_probes()
    lines = ["# Agent tool-safety probe results", ""]
    for f in findings:
        status = "VULNERABLE" if f.is_finding else "control holds"
        lines.append(f"- [{f.severity.value.upper()}] {f.id} ({f.category}) -> {status}: {f.evidence}")
    _write("\n".join(lines), args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redteam", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_full = sub.add_parser("full", help="run everything, write the combined report")
    p_full.add_argument("--out", default=None)
    p_full.add_argument("--generated-at", dest="generated_at", default="(unset - pass --generated-at for a reproducible report)")
    p_full.set_defaults(func=cmd_full)

    p_scan = sub.add_parser("scan", help="scan one chat target")
    p_scan.add_argument("--target", choices=sorted(_TARGETS), required=True)
    p_scan.add_argument("--out", default=None)
    p_scan.set_defaults(func=cmd_scan)

    p_agent = sub.add_parser("agent-scan", help="run the agent tool-safety probes only")
    p_agent.add_argument("--out", default=None)
    p_agent.set_defaults(func=cmd_agent_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
