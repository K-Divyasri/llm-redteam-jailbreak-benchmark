"""Find and redact personal data (PII) with regex -- the workhorse guard.

PII = Personally Identifiable Information: emails, phone numbers, social security
numbers, credit cards. Two reasons to strip it:

  1. Before it reaches the model or your logs. You don't want a customer's card
     number sitting in a prompt sent to a third-party API, or printed into a log
     file that ten people can read.
  2. Out of the model's reply, in case it echoes something sensitive back.

Regex is the right tool here: PII has *shape*. A US SSN is three digits, a dash,
two digits, a dash, four digits. An email has an @ with text either side. We
match the shape and replace the match with a tag like `[SSN]`.

One honest caveat we teach: regex catches well-formed PII, not everything. A name
("John Smith") has no fixed shape, so regex misses it -- that's what the optional
LLM classifier and libraries like Presidio are for. But regex is fast, free, and
catches the highest-risk, best-structured items, so it's always the first line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIHit:
    """One piece of PII found in a text."""

    kind: str          # "email", "phone", "ssn", "credit_card"
    value: str         # the exact text that matched
    start: int         # character offset where it starts
    end: int           # character offset where it ends


# Order matters: we run these in sequence, and more specific patterns (SSN,
# credit card) go before looser ones (phone) so a card isn't mislabelled.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# 13-16 digits, optionally split by single spaces or dashes -- validated by the
# Luhn check below so we don't flag every long number. The lookarounds keep us
# from swallowing a trailing separator or matching inside a longer number.
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,15}(?!\d)")
# US-style phone: optional +1, area code (maybe parenthesised), 7 digits.
_PHONE = re.compile(
    r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
)


def luhn_ok(digits: str) -> bool:
    """The checksum every real credit-card number satisfies.

    Doubling every second digit from the right (and subtracting 9 if the result
    is over 9) must sum to a multiple of 10. Using it here means a random
    16-digit order number won't be redacted as a card -- far fewer false alarms.
    """
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_pii(text: str) -> list[PIIHit]:
    """Return every PII match in `text`, sorted by position, non-overlapping.

    We claim characters greedily in priority order (email, ssn, card, phone) so
    that, e.g., the digits inside an SSN aren't also grabbed by the phone rule.
    """
    hits: list[PIIHit] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < e and s < end for s, e in claimed)

    for kind, pattern in (("email", _EMAIL), ("ssn", _SSN), ("credit_card", _CARD), ("phone", _PHONE)):
        for m in pattern.finditer(text):
            if kind == "credit_card" and not luhn_ok(m.group()):
                continue  # looks card-shaped but fails the checksum -- skip
            if overlaps(m.start(), m.end()):
                continue
            claimed.append((m.start(), m.end()))
            hits.append(PIIHit(kind, m.group(), m.start(), m.end()))

    hits.sort(key=lambda h: h.start)
    return hits


def redact(text: str, *, hits: list[PIIHit] | None = None) -> tuple[str, list[PIIHit]]:
    """Replace every PII match with a `[KIND]` tag. Returns (clean_text, hits).

    We rebuild the string left to right from the match offsets, so overlapping or
    out-of-order matches can't corrupt it.
    """
    hits = hits if hits is not None else find_pii(text)
    if not hits:
        return text, hits
    out: list[str] = []
    cursor = 0
    for h in sorted(hits, key=lambda x: x.start):
        out.append(text[cursor:h.start])
        out.append(f"[{h.kind.upper()}]")
        cursor = h.end
    out.append(text[cursor:])
    return "".join(out), hits
