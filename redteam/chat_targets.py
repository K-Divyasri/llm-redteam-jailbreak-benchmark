"""The two things under attack: an unguarded bot, and the same bot behind `safeguard`.

Both targets expose the identical `.probe(attack) -> ProbeOutcome` interface, so the
runner (runner.py) doesn't know or care which one it's scanning - that symmetry is
what makes the raw-vs-guarded COMPARISON meaningful: every attack sees exactly the
same bot underneath, only the presence of the guard differs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import _vendor  # noqa: F401  (wires sys.path before the imports below)
from safeguard import Action
from safeguard.bot import BotConfig, reply
from safeguard.guard import Guard

from .attacks import Attack


@dataclass
class ProbeOutcome:
    """What actually happened when one attack was fired at one target."""

    blocked: bool          # True if the target refused/blocked the request
    redacted: bool          # True if something was masked but the request still proceeded
    response_text: str
    fired: dict            # which guard(s) fired, empty dict for the unguarded target
    input_seen: str = ""    # the text that actually reached the bot (post input-PII-redaction, if any)


class RawChatTarget:
    """The bot with NO guard in front of it - calls `safeguard.bot.reply` directly."""

    name = "raw (no guard)"

    def probe(self, attack: Attack) -> ProbeOutcome:
        config = BotConfig(leak=attack.leak, structured=attack.structured, broken=attack.broken)
        text = reply(attack.payload, config)
        # The raw bot has no concept of blocking or redacting - it always "allows",
        # and nothing ever touches the input before the bot sees it verbatim.
        return ProbeOutcome(blocked=False, redacted=False, response_text=text, fired={}, input_seen=attack.payload)


class GuardedChatTarget:
    """The bot wrapped in `safeguard.Guard` - the thing this OWASP scan is auditing."""

    def __init__(self, *, validate_schema: bool = False) -> None:
        self._guard = Guard(validate_schema=validate_schema)
        self.name = "guarded (schema-hardened)" if validate_schema else "guarded (default config)"

    def probe(self, attack: Attack) -> ProbeOutcome:
        config = BotConfig(leak=attack.leak, structured=attack.structured, broken=attack.broken)
        report = self._guard(attack.payload, bot_config=config)
        return ProbeOutcome(
            blocked=report.action is Action.BLOCK,
            redacted=report.action is Action.REDACT,
            response_text=report.reply,
            fired=report.fired,
            # `input_redacted` is the message AFTER input-side PII masking (or the
            # original text unchanged if nothing was found/blocked) - this is what
            # proves whether the guard actually caught PII in the request, since the
            # canned bot's own reply never echoes the user's text unless leak=True.
            input_seen=report.input_redacted,
        )
