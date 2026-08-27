"""A deterministic, offline stand-in for a real LLM's tool-choosing.

Real function-calling works like this: you send the model the conversation plus
the tool schemas; it replies EITHER with a normal text answer OR with a request to
call one or more tools (a name + JSON arguments for each). Your loop runs the
tools, sends the results back, and asks again.

This `FakeModel` reproduces that exact contract with plain keyword rules instead of
a neural network. It looks at the user's message, decides which tool(s) apply, and
returns the same shape a real model would. When it's handed tool results, it writes
a short final answer. Because it's rule-based it needs no API key and gives the
same answer every time — perfect for learning the *loop* without paying for or
depending on a model. Swap in `llm.py` (the `--real` flag) and the loop is
identical; only the brain changes.

It is deliberately not clever. Its job is to make the plumbing visible, and to be
honest about that: it's a simulation of tool selection, not real understanding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """One request from the model to run a tool."""

    id: str
    name: str
    arguments: dict


@dataclass
class Decision:
    """What the model decided this turn: call tools, or answer with text.

    Exactly one of these is set, mirroring a real model turn: `tool_calls` (it
    wants tools run) or `content` (it's done and this is the answer).
    """

    tool_calls: list[ToolCall] = field(default_factory=list)
    content: str | None = None


# Departments/cities/categories the fake router knows how to pull out of a sentence.
_DEPARTMENTS = ["engineering", "sales", "marketing", "support", "finance"]
_CITIES = ["london", "paris", "tokyo", "berlin", "austin", "toronto"]
_CATEGORIES = ["hardware", "software", "accessories"]

_MATH_PCT = re.compile(r"(\d+(?:\.\d+)?)\s*(?:%|percent)\s*of\s*(\d+(?:\.\d+)?)", re.I)
# A run of arithmetic characters starting/ending on a digit or paren, so that
# "(3 + 4) * 5 - 2" is captured whole (leading paren included).
_MATH_EXPR = re.compile(r"[\d(][\d\s.+\-*/%()]*[\d)]")
_WEATHER = re.compile(r"(?:weather|temperature|forecast|how (?:hot|cold|warm))"
                      r".*?\b(?:in|for|at)\s+([a-z][a-z\s]*?)(?:\?|,|\.| and | today|$)", re.I)


class FakeModel:
    """Rule-based tool selector with the same interface as the real model path."""

    def __init__(self) -> None:
        self._call_counter = 0

    def _next_id(self) -> str:
        # Deterministic, sequential ids (never random — the same run must reproduce).
        self._call_counter += 1
        return f"call_{self._call_counter}"

    def decide(self, messages: list[dict]) -> Decision:
        """Given the running conversation, return the next model move."""
        last = messages[-1]

        # If we just fed tool results back, it's time to write the final answer.
        if last.get("role") == "tool":
            return Decision(content=self._final_answer(messages))

        user_text = str(last.get("content", ""))
        calls = self._pick_tools(user_text)
        if calls:
            return Decision(tool_calls=calls)

        # Nothing matched a tool — fall back to a web search if it looks like a
        # question, otherwise a polite shrug.
        if "?" in user_text or user_text.lower().split()[:1] in (["what"], ["who"], ["define"]):
            return Decision(tool_calls=[ToolCall(self._next_id(), "web_search",
                                                 {"query": user_text})])
        return Decision(content="I can do maths, weather, web lookups, and company "
                                "database queries. Try asking me one of those.")

    # -- the keyword rules ------------------------------------------------- #

    def _pick_tools(self, text: str) -> list[ToolCall]:
        calls: list[ToolCall] = []
        low = text.lower()

        # Maths: "X% of Y" first (clearer), then any bare arithmetic expression.
        pct = _MATH_PCT.search(text)
        if pct:
            x, y = float(pct.group(1)), float(pct.group(2))
            calls.append(ToolCall(self._next_id(), "do_math", {"expression": f"{x / 100} * {y}"}))
        else:
            expr = _MATH_EXPR.search(text)
            if expr and any(op in expr.group(0) for op in "+-*/"):
                calls.append(ToolCall(self._next_id(), "do_math",
                                      {"expression": expr.group(0).strip()}))

        # Weather: "weather in <city>".
        wx = _WEATHER.search(text)
        if wx:
            calls.append(ToolCall(self._next_id(), "get_weather",
                                  {"city": wx.group(1).strip()}))

        # Database: employees or products.
        if any(w in low for w in ("employee", "who works", "staff", "department")):
            args: dict = {"table": "employees"}
            for dept in _DEPARTMENTS:
                if dept in low:
                    args["department"] = dept.title()
                    break
            for city in _CITIES:
                if city in low:
                    args["city"] = city.title()
                    break
            calls.append(ToolCall(self._next_id(), "query_database", args))
        elif any(w in low for w in ("product", "catalog", "in stock")):
            args = {"table": "products"}
            for cat in _CATEGORIES:
                if cat in low:
                    args["category"] = cat.title()
                    break
            calls.append(ToolCall(self._next_id(), "query_database", args))

        return calls

    # -- writing the final answer from tool results ------------------------ #

    def _final_answer(self, messages: list[dict]) -> str:
        results = [m["content"] for m in messages if m.get("role") == "tool"]
        if not results:
            return "I couldn't find anything useful."
        if len(results) == 1:
            return results[0]
        return "Here's what I found:\n" + "\n".join(results)
