"""Tool schemas + the registry that ties tool names to Python functions.

The model doesn't see your Python code. It sees a JSON *description* of each tool:
the name, what it does, and what arguments it takes. That description is the
"schema". When the model wants a tool, it replies with the tool's name and a blob
of JSON arguments; the agent loop looks the name up here and runs the real function.

We use the OpenAI-style schema shape (`{"type": "function", "function": {...}}`)
because that's what LiteLLM speaks to every provider — Gemini, Claude, OpenAI —
through one interface. Anthropic's native API uses a slightly flatter shape; the
knowledge folder shows both.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .tools import do_math, get_weather, query_database, web_search

# The JSON schemas the model reads. Descriptions matter: the model decides *when*
# to call a tool almost entirely from these words, so they're written to be clear
# about the trigger ("Use this when the user asks about...").
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "do_math",
            "description": "Evaluate an arithmetic expression. Use this whenever the user "
                           "asks to calculate, compute, or work out a number (percentages, "
                           "sums, products, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "The arithmetic to evaluate, e.g. '15 * (3 + 2)' or '0.15 * 240'.",
                    }
                },
                "required": ["expression"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a city. Use this when the user asks "
                           "about weather, temperature, or conditions somewhere.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "The city name, e.g. 'Paris'."}
                },
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search for general knowledge / definitions on the web. Use this "
                           "when the user asks a factual 'what is X' style question that isn't "
                           "maths, weather, or something in the company database.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to search for."}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "Look up rows in the company database (read-only). Use this when the "
                           "user asks about employees or products the company stores.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {"type": "string", "enum": ["employees", "products"],
                              "description": "Which table to look in."},
                    "department": {"type": "string", "description": "Filter employees by department (optional)."},
                    "city": {"type": "string", "description": "Filter employees by city (optional)."},
                    "category": {"type": "string", "description": "Filter products by category (optional)."},
                },
                "required": ["table"],
            },
        },
    },
]

# Maps a tool name to the actual Python function that runs it.
TOOLS: dict[str, Callable[..., str]] = {
    "do_math": do_math,
    "get_weather": get_weather,
    "web_search": web_search,
    "query_database": query_database,
}


def dispatch_tool(name: str, arguments: dict[str, Any] | str) -> str:
    """Run the named tool with the given arguments and return its string result.

    This is the one place the agent loop actually executes a tool. It:
      - looks the name up (unknown name -> a friendly error the model can read),
      - accepts arguments as a dict or a JSON string (models send a JSON string),
      - drops any arguments the function doesn't accept and reports bad input
        instead of raising — a single broken tool call should never crash the loop.
    """
    if name not in TOOLS:
        return f"Error: no tool named '{name}'. Available tools: {', '.join(TOOLS)}."

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except json.JSONDecodeError:
            return f"Error: tool '{name}' was called with arguments that aren't valid JSON."
    if not isinstance(arguments, dict):
        return f"Error: tool '{name}' expects an object of arguments."

    func = TOOLS[name]
    # Keep only kwargs the function actually declares, so a hallucinated extra
    # argument doesn't blow up the call.
    valid = set(func.__code__.co_varnames[: func.__code__.co_argcount])
    kwargs = {k: v for k, v in arguments.items() if k in valid}
    try:
        return func(**kwargs)
    except TypeError as exc:  # usually a missing required argument
        return f"Error calling '{name}': {exc}"
