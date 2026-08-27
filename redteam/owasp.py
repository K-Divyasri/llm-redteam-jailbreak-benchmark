"""The OWASP Top 10 for LLM Applications (2025) - the scorecard this scan reports against.

Published 2024-11-18 by the OWASP GenAI Security Project (v2.0, codes LLM01:2025
through LLM10:2025). This module just holds the names and a short note on whether
this particular target (an offline rule-based chatbot + tool agent) can even
exercise each category - a mature audit says "not applicable, here's why" for the
categories that don't fit, rather than forcing every category to produce a finding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspCategory:
    code: str
    name: str
    applicable: bool
    note: str


CATEGORIES: dict[str, OwaspCategory] = {
    "LLM01": OwaspCategory(
        "LLM01", "Prompt Injection", True,
        "Directly testable: the guard's injection detector is a fixed regex pattern "
        "list, and pattern lists have edges.",
    ),
    "LLM02": OwaspCategory(
        "LLM02", "Sensitive Information Disclosure", True,
        "Directly testable: PII redaction is regex-based on both input and output.",
    ),
    "LLM03": OwaspCategory(
        "LLM03", "Supply Chain", False,
        "N/A offline - no third-party model/plugin dependency chain in the "
        "deterministic target. Would apply to the pinned litellm/gemini dependency "
        "used only by the optional --real path.",
    ),
    "LLM04": OwaspCategory(
        "LLM04", "Data and Model Poisoning", False,
        "N/A - there is no training, fine-tuning, or embedding pipeline anywhere in "
        "this target to poison.",
    ),
    "LLM05": OwaspCategory(
        "LLM05", "Improper Output Handling", True,
        "Directly testable: the bot has a demo mode that returns structurally "
        "invalid JSON on purpose (`broken=True`), and the schema guard is opt-in.",
    ),
    "LLM06": OwaspCategory(
        "LLM06", "Excessive Agency", True,
        "Directly testable on the agent surface: does a tool argument escape its "
        "sandbox, can the topic guard's scope be talked around.",
    ),
    "LLM07": OwaspCategory(
        "LLM07", "System Prompt Leakage", True,
        "Only testable in --real mode - the offline deterministic bot has no real "
        "system prompt to leak. Skipped by default; documented as a coverage gap.",
    ),
    "LLM08": OwaspCategory(
        "LLM08", "Vector and Embedding Weaknesses", False,
        "N/A - no vector store or RAG retrieval step in this target.",
    ),
    "LLM09": OwaspCategory(
        "LLM09", "Misinformation", False,
        "N/A offline - a rule-based canned-response bot cannot hallucinate; it can "
        "only return one of a fixed set of true statements. Only a real generative "
        "model (the --real path) can be probed for this.",
    ),
    "LLM10": OwaspCategory(
        "LLM10", "Unbounded Consumption", True,
        "Directly testable on the agent surface: does the tool-call loop have a "
        "hard step ceiling.",
    ),
}


def applicable_categories() -> list[OwaspCategory]:
    return [c for c in CATEGORIES.values() if c.applicable]


def not_applicable_categories() -> list[OwaspCategory]:
    return [c for c in CATEGORIES.values() if not c.applicable]


def label(code: str) -> str:
    """'LLM01' -> 'LLM01:2025 Prompt Injection'."""
    c = CATEGORIES[code]
    return f"{c.code}:2025 {c.name}"
