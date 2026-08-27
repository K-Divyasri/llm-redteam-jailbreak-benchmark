from redteam.attacks import ALL_CHAT_ATTACKS, BASELINE_ATTACKS, BENIGN_ATTACKS, MALICIOUS_ATTACKS
from redteam.owasp import CATEGORIES


def test_all_ids_unique():
    ids = [a.id for a in ALL_CHAT_ATTACKS]
    assert len(ids) == len(set(ids))


def test_every_malicious_attack_has_a_valid_owasp_code_or_na():
    for a in MALICIOUS_ATTACKS:
        assert a.category in CATEGORIES or a.category == "N/A"


def test_benign_attacks_expect_allow():
    assert BENIGN_ATTACKS
    assert all(not a.expect_block for a in BENIGN_ATTACKS)


def test_baseline_attacks_expect_block():
    assert BASELINE_ATTACKS
    assert all(a.expect_block for a in BASELINE_ATTACKS)


def test_corpus_has_meaningful_size():
    # A real benchmark needs breadth - guard against someone accidentally deleting most of it.
    assert len(ALL_CHAT_ATTACKS) >= 20
