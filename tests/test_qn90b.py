from pathlib import Path
from unittest.mock import Mock

import pytest

from samsung_tv_root.qn90b import (
    REMOTE_PROBE,
    Qn90bError,
    Qn90bRootEvidence,
    Qn90bRootExploit,
    _uep_gate_is_valid,
    _uep_probe_words,
)
from samsung_tv_root.sdb import CaptureResult


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
        "read_words physical=0x208c26c0 page=0x208c2000 offset=0x6c0 words=4\n"
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


@pytest.mark.parametrize(
    ("operation", "flag"),
    (
        ("read_uep_gate", "00000001"),
        ("read_uep_gate", "00000000"),
        ("disable_uep", "00000000"),
    ),
)
def test_uep_gate_reads_only_validated_address(monkeypatch, tmp_path, operation, flag) -> None:
    monkeypatch.setattr("samsung_tv_root.qn90b.find_sdb", lambda: Path("sdb"))
    exploit = Qn90bRootExploit("192.0.2.50", tmp_path)
    result = CaptureResult(f"words word=0 c07bd300 {flag} 00000000 000004e2\n", 0)
    capture = Mock(return_value=result)
    monkeypatch.setattr(exploit.sdb, "capture", capture)

    assert getattr(exploit, operation)() is result
    capture.assert_called_once_with(
        f"/usr/bin/dotnet {REMOTE_PROBE} rw 0x208c26c0 4", timeout=15.0
    )


@pytest.mark.parametrize("operation", ("read_uep_gate", "disable_uep"))
@pytest.mark.parametrize(
    "output",
    (
        "",
        "words word=0 c07bd300\n",
        "words word=0 00000000 00000001 00000000 000004e2\n",
        "words word=0 c07bd300 00000002 00000000 000004e2\n",
    ),
    ids=("missing", "short", "wrong-neighbour", "invalid-flag"),
)
def test_uep_gate_rejects_without_fallback_or_write(
    monkeypatch, tmp_path, operation, output
) -> None:
    monkeypatch.setattr("samsung_tv_root.qn90b.find_sdb", lambda: Path("sdb"))
    exploit = Qn90bRootExploit("192.0.2.50", tmp_path)
    capture = Mock(return_value=CaptureResult(output, 0))
    monkeypatch.setattr(exploit.sdb, "capture", capture)

    with pytest.raises(Qn90bError, match="at the validated physical address") as error:
        getattr(exploit, operation)()

    assert f"0x208c26c0: {output.strip() or 'no probe output'}" in str(error.value)
    capture.assert_called_once_with(
        f"/usr/bin/dotnet {REMOTE_PROBE} rw 0x208c26c0 4", timeout=15.0
    )


def test_uep_disable_writes_with_neighbour_checks(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("samsung_tv_root.qn90b.find_sdb", lambda: Path("sdb"))
    exploit = Qn90bRootExploit("192.0.2.50", tmp_path)
    read = CaptureResult("words word=0 c07bd300 00000001 00000000 000004e2\n", 0)
    write = CaptureResult(
        "words_before word=0 c07bd300 00000001 00000000 000004e2\n"
        "words_after word=0 c07bd300 00000000 00000000 000004e2\n",
        0,
    )
    capture = Mock(side_effect=[read, write])
    monkeypatch.setattr(exploit.sdb, "capture", capture)

    assert exploit.disable_uep() is write
    assert capture.call_count == 2
    capture.assert_called_with(
        f"/usr/bin/dotnet {REMOTE_PROBE} wwi 0x208c26c0 1 0x00000001 0x00000000 "
        "0:c07bd300,2:00000000,3:000004e2",
        timeout=15.0,
    )


def test_uep_disable_fails_closed_when_payload_refuses_neighbour(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr("samsung_tv_root.qn90b.find_sdb", lambda: Path("sdb"))
    exploit = Qn90bRootExploit("192.0.2.50", tmp_path)
    read = CaptureResult("words word=0 c07bd300 00000001 00000000 000004e2\n", 0)
    write = CaptureResult(
        "words_before word=0 00000000 00000001 00000000 00000000\n"
        "refusing write neighbour word=0 expected=0xc07bd300 actual=0x00000000\n",
        1,
    )
    capture = Mock(side_effect=[read, write])
    monkeypatch.setattr(exploit.sdb, "capture", capture)

    with pytest.raises(Qn90bError, match="guarded read-back"):
        exploit.disable_uep()


def test_uep_disable_fails_closed_on_unverified_read_back(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr("samsung_tv_root.qn90b.find_sdb", lambda: Path("sdb"))
    exploit = Qn90bRootExploit("192.0.2.50", tmp_path)
    read = CaptureResult("words word=0 c07bd300 00000001 00000000 000004e2\n", 0)
    write = CaptureResult(
        "words_before word=0 c07bd300 00000001 00000000 000004e2\n"
        "words_after word=0 c07bd300 00000000 00000000 000004f3\n",
        0,
    )
    capture = Mock(side_effect=[read, write])
    monkeypatch.setattr(exploit.sdb, "capture", capture)

    with pytest.raises(Qn90bError, match="guarded read-back"):
        exploit.disable_uep()
