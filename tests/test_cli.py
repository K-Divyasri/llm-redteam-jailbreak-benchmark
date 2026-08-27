from redteam.cli import main


def test_cli_full_writes_report(tmp_path):
    out = tmp_path / "report.md"
    code = main(["full", "--generated-at", "2026-01-01", "--out", str(out)])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# LLM Red-Team & Jailbreak Benchmark Report")


def test_cli_scan_guarded(tmp_path):
    out = tmp_path / "scan.md"
    code = main(["scan", "--target", "guarded", "--out", str(out)])
    assert code == 0
    assert "vulnerabilities" in out.read_text(encoding="utf-8")


def test_cli_agent_scan(tmp_path):
    out = tmp_path / "agent.md"
    code = main(["agent-scan", "--out", str(out)])
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "agent_math_escape" in text
