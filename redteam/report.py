"""Render a FullScanResult into a committable Markdown vulnerability report.

Shaped like a real pentest deliverable: executive summary, an OWASP coverage
matrix (including the categories this target legitimately can't exercise, with a
reason - overclaiming coverage is worse than admitting a gap), then every finding
grouped by target, worst severity first, then recommendations.

No `datetime.now()` in here - the caller passes `generated_at` in, so the report
is reproducible byte-for-byte in tests and notebooks.
"""

from __future__ import annotations

from . import SEVERITY_ORDER, Severity
from .agent_probes import AgentFinding
from .attacks import BASELINE_ATTACKS
from .owasp import applicable_categories, label, not_applicable_categories
from .runner import FullScanResult
from .scoring import Finding, Verdict

_SEV_ORDER = list(Severity)


def _severity_counts(items) -> dict[Severity, int]:
    counts = {s: 0 for s in Severity}
    for item in items:
        if item.is_finding:
            counts[item.severity] += 1
    return counts


def _sorted_findings(items):
    return sorted((i for i in items if i.is_finding), key=lambda i: SEVERITY_ORDER[i.severity])


def summarize_target(name: str, findings: list[Finding]) -> dict:
    total = len(findings)
    vulns = [f for f in findings if f.verdict is Verdict.VULNERABLE]
    false_pos = [f for f in findings if f.verdict is Verdict.FALSE_POSITIVE]
    return {
        "name": name,
        "total_attacks": total,
        "vulnerabilities": len(vulns),
        "false_positives": len(false_pos),
        "pass_rate": round(1 - (len(vulns) + len(false_pos)) / total, 3) if total else 1.0,
        "severity_counts": _severity_counts(findings),
    }


def _fmt_severity_row(counts: dict[Severity, int]) -> str:
    return " | ".join(f"{s.value.upper()}: {counts[s]}" for s in _SEV_ORDER if s != Severity.INFO or counts[s])


def _finding_table(findings: list[Finding]) -> str:
    if not findings:
        return "_No findings - every attack in this run was handled correctly._\n"
    lines = ["| severity | id | OWASP | technique | evidence |", "| --- | --- | --- | --- | --- |"]
    for f in _sorted_findings(findings):
        kind = "VULNERABLE" if f.verdict is Verdict.VULNERABLE else "FALSE POSITIVE"
        cat = label(f.attack.category) if f.attack.category in ("LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM10") else f.attack.category
        payload = f.attack.payload.replace("|", "\\|")
        evidence = f"payload: `{payload}` -> action={'BLOCK' if f.outcome.blocked else 'REDACT' if f.outcome.redacted else 'ALLOW'} ({kind}). {f.attack.note}"
        lines.append(f"| {f.severity.value.upper()} | {f.attack.id} | {cat} | {f.attack.technique} | {evidence.replace('|', chr(92)+'|')} |")
    return "\n".join(lines) + "\n"


def _agent_finding_table(findings: list[AgentFinding]) -> str:
    lines = ["| severity | id | OWASP | technique | verdict | evidence |", "| --- | --- | --- | --- | --- | --- |"]
    for f in findings:
        verdict_str = "VULNERABLE" if f.is_finding else "control holds"
        lines.append(
            f"| {f.severity.value.upper()} | {f.id} | {label(f.category)} | {f.technique} | {verdict_str} | "
            f"{f.evidence.replace('|', chr(92)+'|')} |"
        )
    return "\n".join(lines) + "\n"


def render_markdown(result: FullScanResult, *, generated_at: str) -> str:
    raw_summary = summarize_target("raw (no guard)", result.raw_findings)
    guarded_summary = summarize_target("guarded (default config)", result.guarded_findings)
    hardened_summary = summarize_target("guarded (schema-hardened)", result.hardened_findings)
    agent_vulns = [f for f in result.agent_findings if f.is_finding]

    lines: list[str] = []
    lines.append("# LLM Red-Team & Jailbreak Benchmark Report")
    lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append("")
    lines.append(
        "Scope: a support-bot guardrails layer (`safeguard`, from a companion project) "
        "and a tool-calling agent (`tool_agent`, from another companion project), "
        "attacked with prompt-injection/jailbreak payloads and excessive-agency/"
        "unbounded-consumption probes, scored against the OWASP Top 10 for LLM "
        "Applications (2025)."
    )
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| target | attacks run | vulnerabilities | false positives | pass rate |")
    lines.append("| --- | --- | --- | --- | --- |")
    for s in (raw_summary, guarded_summary, hardened_summary):
        lines.append(f"| {s['name']} | {s['total_attacks']} | {s['vulnerabilities']} | {s['false_positives']} | {s['pass_rate']:.0%} |")
    lines.append(f"| agent tool-safety controls | {len(result.agent_findings)} | {len(agent_vulns)} | 0 | "
                  f"{(1 - len(agent_vulns)/len(result.agent_findings)):.0%} |" if result.agent_findings else "")
    lines.append("")
    baseline_ids = {a.id for a in BASELINE_ATTACKS}
    baseline_findings = [f for f in result.guarded_findings if f.attack.id in baseline_ids]
    baseline_blocked = sum(1 for f in baseline_findings if not f.is_finding)
    lines.append(
        f"**Headline: the guard correctly blocks all {baseline_blocked}/{len(baseline_ids)} of the "
        "well-known textbook attacks it was explicitly built for, but "
        f"{guarded_summary['vulnerabilities']} of the {guarded_summary['total_attacks']} attacks in this "
        "run still get through the default-configured guard** - almost all of them obfuscated "
        "variants of those same patterns. Red-teaming exists to find exactly this gap between "
        "'blocks the attacks we tested it on' and 'blocks the attacks a real adversary tries'."
    )
    lines.append("")

    lines.append("## OWASP Top 10 for LLM Applications (2025) Coverage")
    lines.append("")
    lines.append("| code | category | status | findings (guarded, default config) |")
    lines.append("| --- | --- | --- | --- |")
    for c in applicable_categories():
        n = sum(1 for f in result.guarded_findings if f.is_finding and f.attack.category == c.code)
        n += sum(1 for f in result.agent_findings if f.is_finding and f.category == c.code)
        lines.append(f"| {c.code}:2025 | {c.name} | tested | {n} |")
    for c in not_applicable_categories():
        lines.append(f"| {c.code}:2025 | {c.name} | not applicable | - ({c.note}) |")
    lines.append("")

    lines.append("## Findings - Guarded Target (default config) - the system under test")
    lines.append("")
    lines.append(_finding_table(result.guarded_findings))

    lines.append("## Findings - Schema-Hardened Target (`validate_schema=True`)")
    lines.append("")
    lines.append(_finding_table(result.hardened_findings))

    lines.append("## Findings - Raw Target (no guard, baseline)")
    lines.append("")
    lines.append(_finding_table(result.raw_findings))

    lines.append("## Agent Surface - Excessive Agency (LLM06) / Unbounded Consumption (LLM10)")
    lines.append("")
    lines.append(_agent_finding_table(result.agent_findings))

    lines.append("## Recommendations")
    lines.append("")
    recs = []
    guarded_vulns = {f.attack.id: f for f in result.guarded_findings if f.verdict is Verdict.VULNERABLE}
    if any(a.startswith("bp_leet") or a.startswith("bp_spacing") or a.startswith("bp_zero_width") for a in guarded_vulns):
        recs.append("Add Unicode normalization (NFKC) and leetspeak/character-spacing folding "
                     "before running the injection regex - or replace/augment the regex list with "
                     "an LLM classifier (`use_llm=True` is already wired up in `safeguard`).")
    if any(a.startswith("bp_reveal_synonym") or a.startswith("bp_role_synonym") for a in guarded_vulns):
        recs.append("Expand the injection pattern list's verb synonyms (leak/expose/output/disclose; "
                     "imagine/envision/suppose), or move fuzzy-paraphrase detection to the LLM classifier path.")
    if any(a.startswith("bp_topic_stuffing") for a in guarded_vulns):
        recs.append("Score topic relevance on the DOMINANT intent of the message, not on ANY shared "
                     "vocabulary - e.g. require the domain-term ratio to exceed a threshold, or classify "
                     "intent with an LLM rather than counting keyword overlap.")
    if any(a.startswith("bp_mod_") for a in guarded_vulns):
        recs.append("Content moderation as an exact-phrase blocklist is a floor, not a ceiling (the "
                     "knowledge folder already says this) - route ambiguous/paraphrased requests to a "
                     "real moderation classifier instead of only a fixed phrase list.")
    if any(a.startswith("pii_card") for a in guarded_vulns):
        recs.append("CRITICAL: loosen the PII regex separator class from `[ -]?` to `[ -.]?` (or better, "
                     "strip all non-digit characters before matching) - the card-number bypass works "
                     "identically whether or not the guard is even present.")
    if any(a.startswith("out_broken_json") for a in guarded_vulns):
        recs.append("Turn on `validate_schema=True` by default for any bot mode that returns structured "
                     "output - this scan shows it is a config flag away from being enforced, not a missing feature.")
    if agent_vulns:
        recs.append("Investigate the agent-surface findings above immediately - a VULNERABLE verdict "
                     "there means a foundational safety control (AST whitelist, table allow-list, "
                     "parameterised query, or step ceiling) failed, not a pattern-matching edge case.")
    if not recs:
        recs.append("No open findings against the hardened configuration - re-run this scan on every "
                     "change to the guard's pattern lists.")
    lines.extend(f"- {r}" for r in recs)
    lines.append("")

    return "\n".join(lines)
