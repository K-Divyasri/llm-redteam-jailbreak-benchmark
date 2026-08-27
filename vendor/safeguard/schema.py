"""Validate the model's OUTPUT against a schema -- the last guard.

When a bot is supposed to return structured data (a JSON object the next system
consumes), "usually valid" isn't good enough: one malformed reply crashes the
pipeline. So we validate the output against a pydantic schema and treat a failure
as a guard trip -- retry, repair, or refuse, but never pass junk downstream.

Our demo schema is a support-bot reply: an answer string, a category, and
whether the request should be escalated to a human. pydantic checks the shape
and the types, and (because we set it up that way) rejects unknown fields and
out-of-range values. This is the same idea as "structured outputs" in the model
APIs, done defensively on your side so you don't depend on the model behaving.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ValidationError


class SupportReply(BaseModel):
    """The shape a structured support answer must take."""

    model_config = {"extra": "forbid"}  # reject unexpected fields

    answer: str
    category: Literal["account", "card", "transfer", "loan", "other"]
    escalate: bool


@dataclass
class SchemaResult:
    """The outcome of validating one output string."""

    valid: bool
    data: dict | None = None
    error: str | None = None


def validate_output(text: str, model: type[BaseModel] = SupportReply) -> SchemaResult:
    """Parse `text` as JSON and validate it against `model`.

    Returns a clean result either way -- valid with the parsed data, or invalid
    with a short human-readable reason. Never raises, so the caller can decide
    what to do (retry, repair, refuse) without a try/except of its own.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        return SchemaResult(valid=False, error=f"not valid JSON: {exc.msg}")
    try:
        obj = model.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first["loc"]) or "(root)"
        return SchemaResult(valid=False, error=f"{loc}: {first['msg']}")
    return SchemaResult(valid=True, data=obj.model_dump())
