"""The real model path: genuine function-calling through LiteLLM.

`LiteLLMModel` has the exact same `.decide(messages)` method as `FakeModel`, and
returns the same `Decision` shape. That's the point — the agent loop in agent.py
doesn't know or care whether a neural network or a pile of regexes is choosing the
tools. Swapping the brain is a one-line change.

LiteLLM gives us one function, `completion(...)`, that speaks tool-calling to every
major provider (Gemini, Claude, OpenAI, Groq, ...) in the OpenAI format. The
response's `message.tool_calls` is a list of requested calls, each with a name and
a JSON string of arguments — which we normalise into our `ToolCall` objects.

Default model is Gemini's free tier, so you can try real tool use for free. Point
`--model` at `claude-sonnet-5` or `openai/gpt-...` and it just works, as long as
the matching key is in your .env.
"""

from __future__ import annotations

import json
import os

from .fake_model import Decision, ToolCall
from .schemas import TOOL_SCHEMAS

DEFAULT_MODEL = "gemini/gemini-1.5-flash"

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools. When a tool can answer part "
    "of the user's request, call it rather than guessing. You may call several tools. "
    "After you have the tool results, give a short, direct answer."
)


class LiteLLMModel:
    """Wraps LiteLLM's `completion` to expose the same interface as FakeModel."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        # Load a .env if one exists, so keys don't have to be exported by hand.
        try:
            from dotenv import load_dotenv

            load_dotenv()
        except Exception:
            pass

    def decide(self, messages: list[dict]) -> Decision:  # pragma: no cover - needs a key + network
        from litellm import completion

        # The real model wants a system prompt up front; add one if the caller
        # didn't already include it.
        msgs = messages
        if not messages or messages[0].get("role") != "system":
            msgs = [{"role": "system", "content": SYSTEM_PROMPT}, *messages]

        response = completion(
            model=self.model,
            messages=msgs,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            temperature=0,
        )
        message = response.choices[0].message

        raw_calls = getattr(message, "tool_calls", None) or []
        if raw_calls:
            calls = []
            for tc in raw_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
            return Decision(tool_calls=calls)

        return Decision(content=message.content or "")


def has_api_key() -> bool:
    """True if some provider key is set, so the CLI can warn before a --real run."""
    return any(os.environ.get(k) for k in
               ("GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY", "GROQ_API_KEY"))
