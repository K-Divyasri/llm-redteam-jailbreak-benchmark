"""Function-Calling Assistant — an LLM that decides which tool to run.

The whole idea of an "agent" in 2026 fits in one sentence: you give a language
model a list of tools (functions it can call), it looks at the user's request and
picks the right one, your code runs that tool, you hand the result back, and the
model turns it into an answer. That back-and-forth is the "agent loop", and it's
the foundation everything fancier (ReAct, multi-agent, computer use) is built on.

The package is split so each file does one job:

    tools.py       the four real tools (do_math, get_weather, web_search,
                   query_database), each with a JSON schema and a Python function
    fake_model.py  a deterministic offline "model" that picks tools by keyword —
                   so the whole loop runs with NO API key and NO internet
    llm.py         the real model path via LiteLLM (Gemini/Claude/OpenAI), which
                   does genuine function-calling
    agent.py       the agent loop itself: ask -> maybe call tools -> feed results
                   back -> repeat, with guardrails against runaway loops
    cli.py         the command-line front door
    schemas.py     the tool JSON schemas + the registry that ties names to funcs

Nothing here needs a key to run: `python -m tool_agent "what is 12% of 240?"`
works offline via the fake model. Add `--real` (and a key in .env) to use a
genuine LLM doing the tool selection.
"""

from __future__ import annotations

from .schemas import TOOL_SCHEMAS, TOOLS, dispatch_tool
from .agent import Agent, AgentResult, Step

__all__ = [
    "TOOL_SCHEMAS",
    "TOOLS",
    "dispatch_tool",
    "Agent",
    "AgentResult",
    "Step",
]

__version__ = "0.1.0"
