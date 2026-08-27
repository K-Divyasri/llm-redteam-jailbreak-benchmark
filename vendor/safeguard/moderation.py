"""Block plainly unsafe requests -- the content-moderation guard.

Separate from injection (which attacks the *system*), moderation is about the
*content*: requests to help with violence, self-harm, weapons, or clearly
illegal activity. A support bot should refuse these outright, whatever else is
going on.

The offline version is a small keyword/phrase blocklist grouped by category. It
is intentionally minimal -- real moderation is a hard, evolving problem and the
grown-up answer is a dedicated classifier (an LLM, or a service like OpenAI's
moderation endpoint). We ship the hook and a handful of unambiguous phrases so
the pipeline is complete and testable offline, and we're honest in the docs that
a keyword list is a floor, not a ceiling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Category -> phrases that, taken as a request for help, we refuse. Kept short,
# unambiguous, and about ACTIONS ("how to make a bomb"), not mere mentions, to
# limit false positives on ordinary text.
_BLOCKLIST: dict[str, list[str]] = {
    "violence": ["make a bomb", "build a bomb", "build a weapon", "make a weapon", "hurt someone", "kill someone"],
    "self_harm": ["kill myself", "end my life", "hurt myself"],
    "illicit": ["launder money", "buy stolen card", "counterfeit money", "hack into"],
}

_COMPILED: dict[str, list[re.Pattern[str]]] = {
    cat: [re.compile(re.escape(p), re.I) for p in phrases] for cat, phrases in _BLOCKLIST.items()
}


@dataclass
class ModerationResult:
    """Whether a message tripped the content blocklist."""

    flagged: bool
    categories: list[str] = field(default_factory=list)


def moderate(text: str) -> ModerationResult:
    """Flag `text` if it matches any blocked phrase, and say which categories."""
    categories: list[str] = []
    for category, patterns in _COMPILED.items():
        if any(p.search(text) for p in patterns):
            categories.append(category)
    return ModerationResult(flagged=bool(categories), categories=categories)
