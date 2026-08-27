"""A tiny stand-in chatbot, so the guards have something to wrap.

The star of this project is the guardrails layer, not the bot. So the bot is a
deliberately dumb, deterministic stub: it looks at a few keywords and returns a
canned Northwind Bank support answer. No model, no key, same output every time --
which keeps the guard tests reproducible.

Two extra modes exist for red-teaming the OUTPUT side of the pipeline:

    leak=True       the bot parrots the user's text back, so if a card number
                    got through the input guard we can prove the output guard
                    still catches it.
    structured=True the bot returns JSON, so we can exercise the schema guard
                    (and a `broken` variant returns invalid JSON on purpose).

Set `offline=False` to route through a real model via LiteLLM instead.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class BotConfig:
    leak: bool = False          # echo user text back (to test output PII guard)
    structured: bool = False    # return JSON (to test the schema guard)
    broken: bool = False        # return INVALID JSON (to fail the schema guard)


_CANNED: list[tuple[tuple[str, ...], str]] = [
    (("balance", "account"), "You can see your balance on the app home screen or by signing in to online banking."),
    (("transfer", "wire", "ach", "send", "move"), "To transfer money, open the app, tap Transfer, choose the account, and confirm."),
    (("card", "debit", "credit"), "You can freeze or replace a card in the app under Cards, or call us to report it lost."),
    (("password", "login", "pin", "reset", "signin", "sign-in"), "Use 'Forgot password' on the sign-in page; we'll email a reset link that lasts one hour."),
    (("loan", "mortgage", "interest", "rate"), "Loan and mortgage rates are on the Rates page; you can start an application in the app."),
    (("fraud", "dispute", "chargeback", "stolen", "unauthorized"), "For fraud or a disputed charge, freeze the card in the app and we'll open a case."),
]


def _canned_answer(text: str) -> str:
    low = text.lower()
    for keywords, reply in _CANNED:
        if any(k in low for k in keywords):
            return reply
    return "I can help with Northwind Bank accounts, cards, transfers and loans. What do you need?"


def _category(text: str) -> str:
    low = text.lower()
    if any(k in low for k in ("card", "debit", "credit")):
        return "card"
    if any(k in low for k in ("transfer", "wire", "ach", "send", "move")):
        return "transfer"
    if any(k in low for k in ("loan", "mortgage", "interest", "rate")):
        return "loan"
    if any(k in low for k in ("balance", "account", "statement")):
        return "account"
    return "other"


def reply(text: str, config: BotConfig | None = None, *, offline: bool = True, model: str | None = None) -> str:
    """Produce the bot's raw (un-guarded) reply for `text`."""
    config = config or BotConfig()
    if not offline:
        return _real_reply(text, model)

    answer = _canned_answer(text)
    if config.leak:
        # Echo the user's text -- the classic way sensitive input leaks into output.
        answer = f"You said: {text}. {answer}"
    if config.broken:
        return '{"answer": "' + answer + '", "category": "account", "escalate": '  # truncated -> invalid JSON
    if config.structured:
        return json.dumps({"answer": answer, "category": _category(text), "escalate": False})
    return answer


def _real_reply(text: str, model: str | None) -> str:
    """A grounded, on-scope reply from a real model (imported lazily)."""
    import os

    from litellm import completion  # noqa: PLC0415

    model = model or os.environ.get("SAFEGUARD_MODEL", "gemini/gemini-1.5-flash")
    messages = [
        {"role": "system", "content": "You are Northwind Bank's support assistant. Answer only bank-account questions, briefly."},
        {"role": "user", "content": text},
    ]
    resp = completion(model=model, messages=messages, temperature=0)
    return resp.choices[0].message.content or ""
