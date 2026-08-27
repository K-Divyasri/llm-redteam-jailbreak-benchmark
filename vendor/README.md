# vendor/ - the two things this project attacks

This project doesn't build its own chatbot or agent - it builds the RED TEAM that
attacks somebody else's. The two targets are copied byte-for-byte from two earlier,
separately-repo'd projects in this same roadmap:

| package | copied from | what it is |
| --- | --- | --- |
| `safeguard/` | `ai/17-guardrails-safety-layer/build_from_scratch/safeguard/` | The guardrails layer (injection/PII/topic/moderation/schema guards) wrapped around a demo "Northwind Bank" support bot. |
| `tool_agent/` | `ai/11-function-calling-assistant/build_from_scratch/tool_agent/` | A tool-calling agent (calculator/weather/search/database) with a hand-rolled reason-act-observe loop. |

**Not one line has been changed.** This is the same "vendored unchanged, wrap
around it" pattern used when Project 15 turned the ReAct research agent into a
production API: every project in this roadmap is pushed to its own separate
GitHub repo, so importing across project folders at runtime would break the moment
someone clones just this one. Copying the exact files means this project is fully
self-contained and reproducible from a single `git clone`.

`generate_data.py` is also copied unchanged (from Project 11) - it builds the tiny
SQLite database `tool_agent`'s `query_database` tool reads. Run it once:

```
python generate_data.py
```

(`redteam/_vendor.py` puts this directory on `sys.path` automatically, so the rest
of the package just does `import safeguard` / `import tool_agent` like normal.)

## Why attack someone else's code instead of writing a vulnerable bot from scratch

Because that's what a real red-team engagement looks like: you're handed a system
someone else built and asked "is this actually safe, or does it just look safe
because nobody's tried hard to break it yet?" Reusing `safeguard` - a project that
already ships its OWN 19-case red-team suite and passes it 19/19 - makes the
finding in this project's report a genuine, non-trivial discovery: a system that
already believes it's tested can still have real gaps.
