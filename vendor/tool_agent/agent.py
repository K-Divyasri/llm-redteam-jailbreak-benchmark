"""The agent loop — the one idea this whole project exists to teach.

Pseudocode for the entire thing:

    messages = [the user's question]
    loop:
        decision = model.decide(messages)          # think
        if decision is a final answer: return it
        for each tool the model asked for:         # act
            result = run_the_tool(...)
            messages.append(result)                # observe
        # loop again so the model can use what it just learned

That's it. Everything else here is bookkeeping and guardrails: recording each step
so you can see what happened, and refusing to loop forever if the model keeps
asking for tools without ever answering.

The `Agent` takes any object with a `.decide(messages) -> Decision` method, so the
exact same loop drives the offline `FakeModel` and the real `LiteLLMModel`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import dispatch_tool


@dataclass
class Step:
    """A record of one tool call and what it returned — for showing your work."""

    tool: str
    arguments: dict
    result: str


@dataclass
class AgentResult:
    """The outcome of a run: the final answer plus the full trace."""

    answer: str
    steps: list[Step] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    stopped_early: bool = False


class Agent:
    """Runs the reason -> act -> observe loop with a chosen model."""

    def __init__(self, model, max_steps: int = 5, live_weather: bool = False) -> None:
        self.model = model
        self.max_steps = max_steps  # guardrail: never loop more than this many times
        self.live_weather = live_weather

    def run(self, user_message: str, verbose: bool = False) -> AgentResult:
        messages: list[dict] = [{"role": "user", "content": user_message}]
        steps: list[Step] = []

        for _ in range(self.max_steps):
            decision = self.model.decide(messages)

            # The model gave a plain answer -> we're done.
            if not decision.tool_calls:
                answer = decision.content or "(no answer)"
                messages.append({"role": "assistant", "content": answer})
                return AgentResult(answer=answer, steps=steps, messages=messages)

            # The model asked for one or more tools. Record the request in the
            # history in the exact shape a real provider expects, then run them.
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.name, "arguments": _as_json(c.arguments)}}
                    for c in decision.tool_calls
                ],
            })

            for call in decision.tool_calls:
                args = dict(call.arguments)
                # The agent, not the model, decides whether weather is live.
                if call.name == "get_weather" and self.live_weather:
                    args.setdefault("live", True)
                if verbose:
                    print(f"  -> calling {call.name}({args})")
                result = dispatch_tool(call.name, args)
                if verbose:
                    print(f"     {result.splitlines()[0][:80]}")
                steps.append(Step(tool=call.name, arguments=call.arguments, result=result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": result,
                })

        # We ran out of steps without the model ever settling on an answer. Stop
        # cleanly rather than looping forever — this is a real, important guardrail.
        fallback = ("I wasn't able to finish within the step limit. Here's what I "
                    "gathered:\n" + "\n".join(s.result for s in steps)) if steps else \
                   "I couldn't complete that within the step limit."
        messages.append({"role": "assistant", "content": fallback})
        return AgentResult(answer=fallback, steps=steps, messages=messages, stopped_early=True)


def _as_json(obj) -> str:
    import json

    return json.dumps(obj)
