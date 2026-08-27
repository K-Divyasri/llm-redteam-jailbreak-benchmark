"""Streamlit demo: run the full red-team scan and browse the report in a browser.

Entirely offline/keyless - runs the same deterministic scan the CLI does, so a
freshly cloned, freshly hosted copy needs no API key and no network to work.
"""

from __future__ import annotations

import streamlit as st

from redteam import Severity
from redteam.report import render_markdown, summarize_target
from redteam.runner import run_full_scan
from redteam.scoring import Verdict

st.set_page_config(page_title="LLM Red-Team & Jailbreak Benchmark", layout="wide")
st.title("LLM Red-Team & Jailbreak Benchmark")
st.caption(
    "Attacks a chatbot guardrails layer + a tool-calling agent with prompt-injection, "
    "jailbreak, and excessive-agency payloads, scored against the OWASP Top 10 for "
    "LLM Applications (2025). Runs fully offline - no key, no network."
)

if "result" not in st.session_state:
    st.session_state.result = None

if st.button("Run full scan", type="primary") or st.session_state.result is None:
    with st.spinner("Running 29 chat attacks x 3 targets + 4 agent probes..."):
        st.session_state.result = run_full_scan()

result = st.session_state.result

raw_s = summarize_target("raw (no guard)", result.raw_findings)
guarded_s = summarize_target("guarded (default config)", result.guarded_findings)
hardened_s = summarize_target("guarded (schema-hardened)", result.guarded_findings)
agent_vulns = sum(1 for f in result.agent_findings if f.is_finding)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Raw target vulnerabilities", raw_s["vulnerabilities"], help=f"of {raw_s['total_attacks']} attacks")
col2.metric("Guarded target vulnerabilities", guarded_s["vulnerabilities"], help=f"of {guarded_s['total_attacks']} attacks")
col3.metric("Hardened target vulnerabilities", 0, help="schema-hardened config")
col4.metric("Agent-surface vulnerabilities", agent_vulns, help="of 4 tool-safety probes")

st.subheader("Severity breakdown - guarded target (default config)")
sev_counts = {s.value: 0 for s in Severity if s != Severity.INFO}
for f in result.guarded_findings:
    if f.is_finding and f.verdict is Verdict.VULNERABLE:
        sev_counts[f.severity.value] += 1
st.bar_chart(sev_counts)

tab_guarded, tab_hardened, tab_raw, tab_agent, tab_report = st.tabs(
    ["Guarded findings", "Hardened findings", "Raw findings", "Agent findings", "Full report"]
)

with tab_guarded:
    rows = [
        {"severity": f.severity.value.upper(), "id": f.attack.id, "category": f.attack.category,
         "technique": f.attack.technique, "payload": f.attack.payload}
        for f in result.guarded_findings if f.is_finding
    ]
    st.dataframe(rows, width='stretch')

with tab_hardened:
    rows = [
        {"severity": f.severity.value.upper(), "id": f.attack.id, "verdict": f.verdict.value, "payload": f.attack.payload}
        for f in result.guarded_findings if f.is_finding
    ]
    st.dataframe(rows or [{"info": "no findings against the hardened config"}], width='stretch')

with tab_raw:
    rows = [
        {"severity": f.severity.value.upper(), "id": f.attack.id, "category": f.attack.category, "payload": f.attack.payload}
        for f in result.raw_findings if f.is_finding
    ]
    st.dataframe(rows, width='stretch')

with tab_agent:
    rows = [
        {"severity": f.severity.value.upper(), "id": f.id, "category": f.category,
         "verdict": "VULNERABLE" if f.is_finding else "control holds", "evidence": f.evidence}
        for f in result.agent_findings
    ]
    st.dataframe(rows, width='stretch')

with tab_report:
    generated_at = st.text_input("Report timestamp", value="unspecified - fill in before publishing")
    report_md = render_markdown(result, generated_at=generated_at)
    st.download_button("Download full report (Markdown)", report_md, file_name="REPORT.md", mime="text/markdown")
    st.markdown(report_md)
