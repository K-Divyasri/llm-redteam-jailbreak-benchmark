"""Fire every attack at a target and collect the verdicts. The orchestration layer."""

from __future__ import annotations

from dataclasses import dataclass, field

from .agent_probes import AgentFinding, run_agent_probes
from .attacks import ALL_CHAT_ATTACKS, Attack
from .chat_targets import GuardedChatTarget, RawChatTarget
from .scoring import Finding, score


def run_chat_scan(target, attacks: list[Attack] | None = None) -> list[Finding]:
    """Run every attack (or a given subset) against one chat target."""
    attacks = attacks if attacks is not None else ALL_CHAT_ATTACKS
    findings: list[Finding] = []
    for attack in attacks:
        outcome = target.probe(attack)
        findings.append(score(attack, target.name, outcome))
    return findings


@dataclass
class FullScanResult:
    """Everything a single `redteam full` run produces: three chat targets + the agent probes."""

    raw_findings: list[Finding]
    guarded_findings: list[Finding]
    hardened_findings: list[Finding]
    agent_findings: list[AgentFinding] = field(default_factory=list)


def run_full_scan() -> FullScanResult:
    """The main deliverable: scan raw, default-guarded, and schema-hardened chat
    targets plus the agent's tool-safety controls, all in one pass."""
    raw = RawChatTarget()
    guarded = GuardedChatTarget(validate_schema=False)
    hardened = GuardedChatTarget(validate_schema=True)
    return FullScanResult(
        raw_findings=run_chat_scan(raw),
        guarded_findings=run_chat_scan(guarded),
        hardened_findings=run_chat_scan(hardened),
        agent_findings=run_agent_probes(),
    )
