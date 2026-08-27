"""Command-line front door for the assistant.

    python -m tool_agent "what is 15% of 240?"
    python -m tool_agent "weather in Paris and who works in Engineering?" --verbose
    python -m tool_agent "weather in Berlin" --real --model gemini/gemini-1.5-flash
    python -m tool_agent --list-tools

By default it uses the offline FakeModel, so it runs with no key and no network.
`--real` switches to a genuine LLM via LiteLLM (needs a key in .env).
"""

from __future__ import annotations

import argparse
import sys

from .agent import Agent
from .fake_model import FakeModel
from .schemas import TOOL_SCHEMAS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tool_agent",
        description="An assistant that decides which tool to call to answer you.",
    )
    p.add_argument("question", nargs="?", help="what you want to ask the assistant")
    p.add_argument("--real", action="store_true",
                   help="use a real LLM via LiteLLM instead of the offline fake model")
    p.add_argument("--model", default=None,
                   help="model string for --real (default: gemini/gemini-1.5-flash)")
    p.add_argument("--max-steps", type=int, default=5,
                   help="guardrail: max reason/act rounds before giving up (default 5)")
    p.add_argument("--live-weather", action="store_true",
                   help="let get_weather call the real (keyless) Open-Meteo API")
    p.add_argument("--verbose", action="store_true",
                   help="print each tool call as it happens (the agent loop, live)")
    p.add_argument("--list-tools", action="store_true", help="list available tools and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_tools:
        print("Available tools:\n")
        for schema in TOOL_SCHEMAS:
            fn = schema["function"]
            print(f"  {fn['name']:<15} {fn['description']}")
        return 0

    if not args.question:
        print("Ask me something, e.g.:  python -m tool_agent \"what is 15% of 240?\"")
        print("Run with --list-tools to see what I can do.")
        return 1

    # Pick the brain.
    if args.real:
        from .llm import DEFAULT_MODEL, LiteLLMModel, has_api_key

        if not has_api_key():
            print("--real needs an API key. Copy .env.example to .env and add a free")
            print("Gemini key from https://aistudio.google.com/apikey, then try again.")
            return 1
        model = LiteLLMModel(model=args.model or DEFAULT_MODEL)
        print(f"[using real model: {model.model}]\n")
    else:
        model = FakeModel()
        if args.model:
            print("[note: --model is ignored without --real; using the offline fake model]\n")

    agent = Agent(model, max_steps=args.max_steps, live_weather=args.live_weather)
    result = agent.run(args.question, verbose=args.verbose)

    if args.verbose and result.steps:
        print()  # blank line after the live trace
    print(result.answer)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
