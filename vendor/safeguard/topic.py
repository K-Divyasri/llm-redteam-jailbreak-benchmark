"""Keep the bot on its job: refuse off-topic requests.

A support bot for a bank should answer questions about accounts, cards and
transfers -- not write your homework, tell jokes, or opine on politics. Letting
it wander is a cost risk (you're paying for tokens), a brand risk, and an attack
surface (off-topic is often step one of a jailbreak). So we scope it.

The offline check is deliberately simple: we keep a lexicon of in-domain words
and measure how much of the message overlaps it. No overlap on a real request =
probably off-topic. This is a blunt instrument -- it can't tell that "how do I
move money to my sister" is in-domain despite using no banking keyword -- which
is precisely the kind of nuance the optional LLM classifier handles better. We
teach both, and default to the free one.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# The bank-support domain. In a real system you'd grow this from your own docs.
DOMAIN_TERMS: frozenset[str] = frozenset(
    """
    account accounts balance transfer transfers deposit deposits withdraw withdrawal
    card cards credit debit statement statements loan loans mortgage interest rate
    payment payments bill autopay overdraft fee fees routing swift iban branch atm
    pin login password reset username signin sign-in fraud dispute chargeback refund
    wire ach checking savings money fund funds bank banking northwind
    """.split()
)


@dataclass
class TopicResult:
    """Whether a message is inside the bot's remit."""

    on_topic: bool
    matched_terms: list[str] = field(default_factory=list)


def _words(text: str) -> list[str]:
    return [w.strip(".,!?;:'\"()").lower() for w in text.split()]


def check_topic(text: str, *, domain: frozenset[str] = DOMAIN_TERMS) -> TopicResult:
    """On-topic if the message shares at least one domain term.

    Short greetings ("hi", "thanks") are allowed through as on-topic so the bot
    can be polite; the guard is aimed at substantive off-topic requests.
    """
    words = _words(text)
    if len(words) <= 3:  # greetings / pleasantries: don't nag
        return TopicResult(on_topic=True, matched_terms=[])
    matched = [w for w in words if w in domain]
    return TopicResult(on_topic=bool(matched), matched_terms=sorted(set(matched)))
