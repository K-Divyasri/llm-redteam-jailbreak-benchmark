"""The orchestrator: run every guard, in order, around the bot.

This is the one class the rest of the world uses. You hand it a user message; it
runs the input guards, calls the bot only if the message survives, runs the
output guards on the reply, and hands back a `GuardReport` that says what
happened and gives you a safe string to show the user.

The ordering is deliberate:

    INPUT   moderation -> injection -> topic  (any of these BLOCKS and refuses)
            pii  (REDACT: mask before the bot or a log ever sees it)
    BOT     called only with the redacted, allowed text
    OUTPUT  pii  (REDACT: catch anything the bot echoed)
            schema  (BLOCK: never pass invalid structured output downstream)

Blocking guards run before the redacting one so we don't waste work masking a
message we're about to refuse. Refusals are specific ("I can't follow
instructions that override my guidelines") because a good refusal tells the user
what happened without leaking how the guard works.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import Action
from . import injection as injection_mod
from . import llm as llm_mod
from . import moderation as moderation_mod
from . import pii as pii_mod
from . import topic as topic_mod
from .bot import BotConfig, reply
from .schema import validate_output

_REFUSALS = {
    "moderation": "I can't help with that request.",
    "injection": "I can't follow instructions that try to override my guidelines. How can I help with your Northwind Bank account?",
    "topic": "I can only help with Northwind Bank accounts, cards, transfers and loans.",
    "schema": "Sorry - I couldn't produce a valid response. Please try rephrasing.",
}


@dataclass
class GuardReport:
    """The full record of one guarded exchange."""

    action: Action              # ALLOW, REDACT (something masked), or BLOCK (refused)
    reply: str                  # the safe text to show the user
    input_redacted: str         # the user text after input PII masking
    fired: dict[str, object] = field(default_factory=dict)  # which guards fired + detail
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK


class Guard:
    """Wrap a bot with input and output guardrails."""

    def __init__(
        self,
        *,
        injection_threshold: float = injection_mod.THRESHOLD,
        domain=topic_mod.DOMAIN_TERMS,
        check_topic: bool = True,
        validate_schema: bool = False,
        use_llm: bool = False,
        model: str | None = None,
    ) -> None:
        self.injection_threshold = injection_threshold
        self.domain = domain
        self.check_topic = check_topic
        self.validate_schema = validate_schema
        self.use_llm = use_llm
        self.model = model

    # -- input side ------------------------------------------------------- #
    def inspect_input(self, text: str) -> tuple[Action, str, dict, list[str]]:
        """Run the input guards. Returns (action, redacted_text, fired, reasons)."""
        fired: dict[str, object] = {}
        reasons: list[str] = []

        mod = moderation_mod.moderate(text)
        if mod.flagged or self._llm_says("moderation", text):
            fired["moderation"] = mod.categories or ["llm"]
            reasons.append("unsafe content")
            return Action.BLOCK, text, fired, reasons

        inj = injection_mod.detect_injection(text, threshold=self.injection_threshold)
        if inj.is_injection or self._llm_says("injection", text):
            fired["injection"] = {"score": inj.score, "matched": inj.matched or ["llm"]}
            reasons.append("prompt injection")
            return Action.BLOCK, text, fired, reasons

        if self.check_topic:
            top = topic_mod.check_topic(text, domain=self.domain)
            llm_off = self._llm_says("topic", text)  # True == off-topic
            if (not top.on_topic) or llm_off:
                fired["topic"] = {"matched_terms": top.matched_terms}
                reasons.append("off-topic")
                return Action.BLOCK, text, fired, reasons

        redacted, hits = pii_mod.redact(text)
        if hits:
            fired["pii"] = [h.kind for h in hits]
            reasons.append(f"redacted {len(hits)} PII item(s) from input")
            return Action.REDACT, redacted, fired, reasons

        return Action.ALLOW, text, fired, reasons

    # -- output side ------------------------------------------------------ #
    def inspect_output(self, text: str) -> tuple[Action, str, dict, list[str]]:
        fired: dict[str, object] = {}
        reasons: list[str] = []
        action = Action.ALLOW
        out = text

        redacted, hits = pii_mod.redact(out)
        if hits:
            fired["pii"] = [h.kind for h in hits]
            reasons.append(f"redacted {len(hits)} PII item(s) from output")
            out = redacted
            action = Action.REDACT

        if self.validate_schema:
            result = validate_output(out)
            if not result.valid:
                fired["schema"] = result.error
                reasons.append(f"invalid output schema: {result.error}")
                return Action.BLOCK, _REFUSALS["schema"], fired, reasons

        return action, out, fired, reasons

    # -- full pipeline ---------------------------------------------------- #
    def __call__(self, text: str, *, bot_config: BotConfig | None = None, offline: bool = True) -> GuardReport:
        in_action, redacted, in_fired, in_reasons = self.inspect_input(text)
        if in_action is Action.BLOCK:
            category = next(iter(in_fired))  # the guard that blocked
            return GuardReport(Action.BLOCK, _REFUSALS[category], text, in_fired, in_reasons)

        raw = reply(redacted, bot_config, offline=offline, model=self.model)
        out_action, safe, out_fired, out_reasons = self.inspect_output(raw)

        fired = {**in_fired, **out_fired}
        reasons = in_reasons + out_reasons
        if out_action is Action.BLOCK:
            return GuardReport(Action.BLOCK, safe, redacted, fired, reasons)
        action = Action.REDACT if (in_action is Action.REDACT or out_action is Action.REDACT) else Action.ALLOW
        return GuardReport(action, safe, redacted, fired, reasons)

    # -- helpers ---------------------------------------------------------- #
    def _llm_says(self, kind: str, text: str) -> bool:
        """True only if the LLM classifier is on AND flags the text."""
        if not self.use_llm:
            return False
        return llm_mod.llm_flag(kind, text, model=self.model) is True
