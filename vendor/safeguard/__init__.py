"""safeguard - a guardrails layer you wrap around a chatbot.

A raw LLM will happily do things you don't want in production: follow a "ignore
your instructions" attack buried in user text, repeat a customer's card number
back into a log, answer questions miles outside its job, or return malformed
JSON that crashes the next system along. A guardrails layer sits on both sides
of the model and stops that:

    user text ─► INPUT GUARDS ─► (the bot) ─► OUTPUT GUARDS ─► safe reply
                 injection?                    leaked PII?
                 PII to redact?                valid schema?
                 off-topic?                    injection echoed back?
                 unsafe?

Everything here runs OFFLINE by default: the detectors are regex and rules, the
schema check is pydantic, and the demo bot is a deterministic stub. No API key,
no network -- so the whole test suite and the red-team report run on a bare
laptop. Flip on the optional LLM classifier (`--llm`) when you want a model's
judgement on the fuzzy cases (subtle injections, nuanced moderation).
"""

from __future__ import annotations

from enum import Enum


class Action(str, Enum):
    """What a guard decided to do with a piece of text."""

    ALLOW = "allow"      # nothing wrong, pass it through
    REDACT = "redact"    # something sensitive found and masked, but continue
    BLOCK = "block"      # unsafe enough to stop here and refuse


# The guard categories we report on, in a stable order for scorecards/reports.
CATEGORIES: tuple[str, ...] = ("injection", "pii", "topic", "moderation", "schema")

# The default LLM used by the optional classifier. Free-first: Gemini's flash
# tier. Override with SAFEGUARD_MODEL, e.g. "groq/llama-3.1-8b-instant".
DEFAULT_MODEL = "gemini/gemini-1.5-flash"

__all__ = ["Action", "CATEGORIES", "DEFAULT_MODEL"]
