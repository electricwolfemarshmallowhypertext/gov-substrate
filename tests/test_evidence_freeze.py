from scripts.verify_evidence_freeze import verify


def test_phase10_evidence_ledger_is_complete_and_hashes_match():
    assert verify() == {"artifacts": 24, "claims": 9}
