import pytest

from samsung_tv_root.qn90b import (
    Qn90bError,
    Qn90bRootEvidence,
    _uep_gate_is_valid,
    _uep_probe_words,
)


def test_qn90b_root_evidence_accepts_complete_root_identity() -> None:
    Qn90bRootEvidence(
        "uid_after=0\n"
        "euid_after=0\n"
        "gid_after=0\n"
        "egid_after=0\n"
        "exec_begin\n"
    ).validate()


def test_qn90b_root_evidence_rejects_incomplete_identity() -> None:
    with pytest.raises(Qn90bError, match="complete root identity"):
        Qn90bRootEvidence("uid_after=0\neuid_after=0\nexec_begin\n").validate()


def test_qn90b_root_evidence_requires_exact_identity_markers() -> None:
    output = (
        "uid_after=00\n"
        "euid_after=0\n"
        "gid_after=0\n"
        "egid_after=0\n"
        "exec_begin\n"
    )
    with pytest.raises(Qn90bError, match="uid_after=0"):
        Qn90bRootEvidence(output).validate()


def test_uep_gate_fingerprint_accepts_closed_and_open_flag() -> None:
    closed = _uep_probe_words(
        "read_words physical=0x808c26c0 page=0x808c2000 offset=0x6c0 words=4\n"
        "words word=0 c07bd300 00000001 00000000 000004e2\n"
    )
    assert _uep_gate_is_valid(closed)
    opened = list(closed)
    opened[1] = "00000000"
    assert _uep_gate_is_valid(opened)


def test_uep_gate_fingerprint_rejects_unrelated_page() -> None:
    assert not _uep_gate_is_valid(
        _uep_probe_words("words word=0 00000000 00000001 00000000 000004e2\n")
    )


def test_uep_gate_fingerprint_rejects_short_or_missing_dump() -> None:
    assert not _uep_gate_is_valid(_uep_probe_words("words word=0 c07bd300\n"))
    assert not _uep_gate_is_valid(_uep_probe_words("word mmap read failed errno=2\n"))


def test_uep_probe_words_selects_named_dump() -> None:
    output = (
        "words_before word=0 c07bd300 00000001 00000000 000004e2\n"
        "words_after word=0 c07bd300 00000000 00000000 000004e2\n"
    )
    assert _uep_probe_words(output, "words_after")[1] == "00000000"
    assert _uep_probe_words(output, "words_before")[1] == "00000001"
