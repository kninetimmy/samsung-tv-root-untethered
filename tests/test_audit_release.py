from pathlib import Path

import pytest

from tools import audit_release


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    (
        ("docs/assets/boot-agent-v4-on-tv.png", "reviewed", None),
        ("docs/assets/boot-agent-v4-on-tv.png", "changed", "review required"),
        ("docs/assets/boot-agent-v4-on-tv.png", "executable", "PE content"),
        ("docs/assets/other.png", "reviewed", "non-UTF-8"),
        ("docs/example.md", "private-address", "private IPv4"),
    ),
)
def test_audit_preserves_binary_and_address_checks(
    tmp_path, monkeypatch, name, content, expected
):
    image = Path(__file__).resolve().parents[1] / "docs/assets/boot-agent-v4-on-tv.png"
    data = image.read_bytes()
    if content == "changed":
        data += b"changed"
    elif content == "executable":
        data = b"MZ\x00\xff"
    elif content == "private-address":
        data = b"192." + b"168.1.1"
    candidate = tmp_path / name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(data)
    monkeypatch.setattr(audit_release, "ROOT", tmp_path)
    monkeypatch.setattr(audit_release, "candidate_files", lambda: (candidate,))

    failures = audit_release.audit()

    if expected is None:
        assert failures == []
    else:
        assert any(expected in failure for failure in failures)


def test_audit_allows_sealed_binaries_inside_the_packet_archive(
    tmp_path, monkeypatch
):
    candidate = tmp_path / "packets" / "r1" / "artifacts" / "uep-probe.elf"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"\x7fELF\x00\xff")
    monkeypatch.setattr(audit_release, "ROOT", tmp_path)
    monkeypatch.setattr(audit_release, "candidate_files", lambda: (candidate,))

    assert audit_release.audit() == []


def test_audit_still_reports_private_ips_inside_the_packet_archive(
    tmp_path, monkeypatch
):
    candidate = tmp_path / "packets" / "r1" / "GateAgent.cs"
    candidate.parent.mkdir(parents=True)
    candidate.write_text(
        'const string DevIp = "' + "192." + "168.50.247" + '";\n'
    )
    monkeypatch.setattr(audit_release, "ROOT", tmp_path)
    monkeypatch.setattr(audit_release, "candidate_files", lambda: (candidate,))

    failures = audit_release.audit()

    assert any("private IPv4" in failure for failure in failures)


def test_audit_still_rejects_binaries_outside_the_packet_archive(
    tmp_path, monkeypatch
):
    candidate = tmp_path / "tools" / "payload.dll"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"MZ\x00\xff")
    monkeypatch.setattr(audit_release, "ROOT", tmp_path)
    monkeypatch.setattr(audit_release, "candidate_files", lambda: (candidate,))

    failures = audit_release.audit()

    assert any("proprietary suffix" in failure for failure in failures)
    assert any("PE content" in failure for failure in failures)
