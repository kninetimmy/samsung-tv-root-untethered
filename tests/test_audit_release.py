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
