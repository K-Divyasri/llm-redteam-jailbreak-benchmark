from redteam.agent_probes import (
    probe_database_sql_injection,
    probe_database_table_allowlist,
    probe_math_sandbox_escape,
    probe_unbounded_loop,
    run_agent_probes,
)
from redteam.scoring import Verdict


def test_math_sandbox_holds_against_code_injection():
    finding = probe_math_sandbox_escape()
    assert finding.verdict is Verdict.SECURE


def test_database_allowlist_holds():
    finding = probe_database_table_allowlist()
    assert finding.verdict is Verdict.SECURE


def test_database_sql_injection_holds():
    finding = probe_database_sql_injection()
    assert finding.verdict is Verdict.SECURE


def test_unbounded_loop_guard_holds():
    finding = probe_unbounded_loop(max_steps=5)
    assert finding.verdict is Verdict.SECURE
    assert "steps_taken=5" in finding.evidence


def test_run_agent_probes_returns_four_findings():
    findings = run_agent_probes()
    assert len(findings) == 4
    assert all(f.verdict is Verdict.SECURE for f in findings)
