from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "docs/CERTIFICATION-HARNESS-CONTRACT.md"


def test_certification_contract_matches_committed_bytes():
    working_copy = (ROOT / CONTRACT).read_bytes()
    assert b"\r" not in working_copy, "Certification contract requires LF line endings"
    committed = subprocess.check_output(
        ["git", "show", f"HEAD:{CONTRACT}"],
        cwd=ROOT,
    )
    assert working_copy == committed, "Certification contract must match its committed bytes"
