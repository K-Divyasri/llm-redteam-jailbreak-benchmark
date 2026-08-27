from redteam.report import render_markdown, summarize_target
from redteam.runner import run_full_scan


def test_full_scan_reproducible_counts():
    """Everything here is deterministic (no randomness anywhere in the corpus or
    the targets), so a full scan must produce the exact same counts every run -
    that reproducibility is what makes the report trustworthy as a regression gate."""
    result = run_full_scan()
    raw_summary = summarize_target("raw", result.raw_findings)
    guarded_summary = summarize_target("guarded", result.guarded_findings)
    hardened_summary = summarize_target("hardened", result.guarded_findings)

    assert raw_summary["vulnerabilities"] > guarded_summary["vulnerabilities"], (
        "the guard must catch strictly more than the unguarded bot"
    )
    assert guarded_summary["vulnerabilities"] >= 10, "expected a large confirmed-bypass count"
    assert guarded_summary["false_positives"] == 0, "the benign sanity set must never be blocked"
    assert len(result.agent_findings) == 4
    assert all(not f.is_finding for f in result.agent_findings), "all agent-surface controls must hold"


def test_render_markdown_is_reproducible_given_a_fixed_timestamp():
    result = run_full_scan()
    r1 = render_markdown(result, generated_at="2026-01-01")
    r2 = render_markdown(result, generated_at="2026-01-01")
    assert r1 == r2


def test_render_markdown_contains_owasp_codes_and_recommendations():
    result = run_full_scan()
    report = render_markdown(result, generated_at="2026-01-01")
    assert "LLM01:2025" in report
    assert "LLM02:2025" in report
    assert "OWASP Top 10 for LLM Applications (2025) Coverage" in report
    assert "## Recommendations" in report
    assert "not applicable" in report
