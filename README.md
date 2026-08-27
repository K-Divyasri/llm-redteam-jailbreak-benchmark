# LLM Red-Team & Jailbreak Benchmark

An offensive red-team harness. It attacks two things vendored unchanged from
earlier projects in this roadmap - a chatbot guardrails layer (`safeguard`) and a
tool-calling agent (`tool_agent`) - with prompt-injection, jailbreak, and
excessive-agency/unbounded-consumption payloads, then scores every result against
the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
and writes a severity-ranked vulnerability report.

This is the offensive counterpart to a guardrails project: instead of building
defenses, this builds the attacker that finds out whether they actually work. Same
shape as Microsoft's [PyRIT](https://github.com/microsoft/PyRIT) and NVIDIA's
[garak](https://github.com/NVIDIA/garak) (probes + detectors/scorers), hand-rolled
here so every line is inspectable.

Runs **entirely offline** - no API key, no network - because both targets are
deterministic, rule-based stand-ins. Every number in `REPORT.md` reproduces
exactly on a bare laptop. An optional `--real` path in `redteam/real_llm.py` tests
actual system-prompt leakage against a real model, gated behind a key.

## Quickstart

```
pip install -r requirements.txt
cd vendor && python generate_data.py && cd ..   # builds the agent's SQLite fixture, once

python -m pytest                          # 28 tests, offline, no key needed
python -m redteam full --out REPORT.md --generated-at "$(date -u +%Y-%m-%dT%H:%MZ)"
streamlit run app.py                      # interactive report browser
```

## Headline result (verified, reproducible)

| target | attacks run | vulnerabilities | pass rate |
| --- | --- | --- | --- |
| raw (no guard) | 29 | 26 | 10% |
| guarded (default config) | 29 | 16 | 45% |
| guarded (schema-hardened) | 29 | 0 (3 false positives) | 90% |
| agent tool-safety controls | 4 | 0 | 100% |

The guard correctly blocks all 5 of the well-known textbook attacks it was built
for - but 16 of 29 attacks in this run, mostly obfuscated variants of those exact
same patterns (leetspeak, zero-width Unicode, verb synonyms, keyword-stuffing),
still get through. See `REPORT.md` for every finding with its exact payload,
mechanism, and OWASP category, or run the scan yourself - nothing here is
hand-picked, every finding is regression-tested in `tests/`.

## Package layout

```
redteam/
  attacks.py        the attack corpus (baseline + 16 confirmed bypasses + benign sanity set)
  owasp.py           the OWASP Top 10:2025 categories + which ones this target can exercise
  chat_targets.py    RawChatTarget / GuardedChatTarget - what gets attacked
  agent_probes.py    excessive-agency / unbounded-consumption probes on tool_agent
  scoring.py         attack + outcome -> SECURE / VULNERABLE / FALSE_POSITIVE
  runner.py          orchestrates a full scan across all targets + probes
  report.py          renders the Markdown vulnerability report
  real_llm.py        optional LLM07 probe against a real model (needs a key)
  cli.py             `python -m redteam full|scan|agent-scan`
vendor/              safeguard + tool_agent, copied unchanged - see vendor/README.md
tests/               28 pytest cases, all offline
app.py               Streamlit report browser
```

## Why the guarded target still fails 16 attacks

Every bypass in `redteam/attacks.py` was found by literally running the payload
against the real vendored detector and confirming it scored under threshold
*before* it was added to the corpus. Four mechanism families cover almost all of them:

1. **Character-level evasion** - leetspeak (`1gnore`), spacing (`I g n o r e`),
   zero-width Unicode (invisible when rendered) all defeat literal-substring regex.
2. **Synonym substitution** - `leak`/`output the text of` mean `reveal` but aren't
   in the pattern list; `imagine you are` means `pretend to be` but isn't either.
3. **Indirect framing** - translation wrappers and roleplay/narrative jailbreaks
   never contain a single sentence with an imperative override verb.
4. **Regex-shape gaps** - the PII card-number regex allows one separator character
   between digit groups; two spaces or a dot breaks the match completely, and this
   holds true whether or not the guard is even in front of the bot.

None of this is a criticism unique to `safeguard` - it's what regex-based guards
are; the report's own recommendations point at the two realistic fixes (`use_llm`
classifier fallback, already wired into `safeguard`; and tightening the specific
regexes named above).
