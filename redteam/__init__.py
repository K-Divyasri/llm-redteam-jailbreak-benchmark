"""redteam - an offensive red-team harness for an existing chatbot + agent stack.

Where `safeguard` (a separate project) is the DEFENDER - a guardrails layer you wrap
around a bot - this package is the ATTACKER. It throws a big, adversarial payload set
at both an unprotected target and a guarded one, scores every response against the
OWASP Top 10 for LLM Applications (2025), and writes a severity-ranked vulnerability
report. This is the same shape as real tools like Microsoft's PyRIT (probes +
orchestrators + scorers) and NVIDIA's garak (probes + detectors) - we hand-roll a
small version so every line is inspectable, and name the real tools in the knowledge
folder for when you need the full-scale version.

Two independent surfaces get attacked:

    chat surface   - a support-bot guard (input: moderation/injection/topic/PII,
                      output: PII/schema) - attacked with prompt-injection and
                      jailbreak payloads, many hand-tuned to slip past the specific
                      regexes the guard uses.
    agent surface   - a tool-calling agent (calculator/weather/search/database) -
                      attacked with excessive-agency and unbounded-consumption
                      probes: can a malicious tool argument escape the sandbox, can
                      the loop be forced to run forever.

Everything runs OFFLINE by default: no API key, no network. The chatbot and agent
under test are both deterministic rule-based stand-ins (vendored unchanged from two
earlier projects), so the whole scan - and its severity numbers - reproduce exactly
on a bare laptop. An optional `--real` path (needs a key) tests actual prompt-leak
behaviour against a real LLM with a real system-prompt secret.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """How bad a confirmed finding is. Ordered worst-first for sorting/reporting."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Sort key: lower number = more severe. Use as `sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])`.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Free-first default, matching the rest of this AI-engineer track (LiteLLM + Gemini).
# Override with REDTEAM_MODEL. Only used by the optional --real system-prompt-leak probe.
DEFAULT_MODEL = "gemini/gemini-1.5-flash"

__all__ = ["Severity", "SEVERITY_ORDER", "DEFAULT_MODEL"]
