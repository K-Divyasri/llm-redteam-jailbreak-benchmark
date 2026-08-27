from redteam import Severity
from redteam.attacks import Attack
from redteam.chat_targets import ProbeOutcome
from redteam.scoring import Verdict, score


def _attack(expect_block: bool) -> Attack:
    return Attack("a", "LLM01", "t", "payload", expect_block, Severity.HIGH, "note")


def test_malicious_blocked_is_secure():
    f = score(_attack(True), "target", ProbeOutcome(blocked=True, redacted=False, response_text="no", fired={}))
    assert f.verdict is Verdict.SECURE
    assert f.is_finding is False


def test_malicious_redacted_is_secure():
    f = score(_attack(True), "target", ProbeOutcome(blocked=False, redacted=True, response_text="[PII]", fired={}))
    assert f.verdict is Verdict.SECURE


def test_malicious_allowed_is_vulnerable_at_declared_severity():
    f = score(_attack(True), "target", ProbeOutcome(blocked=False, redacted=False, response_text="oops", fired={}))
    assert f.verdict is Verdict.VULNERABLE
    assert f.is_finding is True
    assert f.severity is Severity.HIGH


def test_benign_allowed_is_secure():
    f = score(_attack(False), "target", ProbeOutcome(blocked=False, redacted=False, response_text="ok", fired={}))
    assert f.verdict is Verdict.SECURE


def test_benign_blocked_is_false_positive():
    f = score(_attack(False), "target", ProbeOutcome(blocked=True, redacted=False, response_text="refused", fired={}))
    assert f.verdict is Verdict.FALSE_POSITIVE
    assert f.is_finding is True
    assert f.severity is Severity.INFO
