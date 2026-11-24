"""Private leaf creation and the native default-owner admission boundary."""

import json
import os
from pathlib import Path
import sys

import pytest

from tools import evidence_workspace as ew
from tools import run_storage_pilot as pilot
from tools import workspace_creation as creation
from tools import workspace_windows as win


def test_explicit_file_creation_is_private_exclusive_and_preserves_existing(tmp_path):
    root = tmp_path / "private"
    ew.make_private(root)
    path = root / "retained"
    with os.fdopen(ew.create_private_file(path), "wb") as file:
        assert not os.get_inheritable(file.fileno())
        file.write(b"retained evidence")
    ew.private(path)  # Includes actual current-user ownership on Windows.
    before = ew.snapshot(root)
    with pytest.raises(FileExistsError):
        ew.create_private_file(path)
    assert ew.snapshot(root) == before
    assert path.read_bytes() == b"retained evidence"


def test_control_and_evidence_files_use_explicit_private_creation(tmp_path):
    root = tmp_path / "private"
    ew.make_private(root)
    batch = ew.Batch(root, "owned", 1024**2)
    worker = batch.admit(10000)
    batch.write(worker, "retained", b"one")
    batch.write(worker, "retained", b"two", append=True)
    ew.private(batch.control)
    ew.private(batch.root / worker / "retained")
    assert (batch.root / worker / "retained").read_bytes() == b"onetwo"
    batch.finish(worker, success=True, reason="controlled creation verified")
    assert batch.report()["workers"][worker]["status"] == "complete"


@pytest.mark.skipif(os.name != "nt", reason="Windows actual default owner")
def test_existing_raw_control_is_never_ownership_normalized(tmp_path):
    root = tmp_path / "private"
    ew.make_private(root)
    ew.make_private(root / "existing")
    path = root / "existing/batch.json"
    path.write_bytes(b"preserve original bytes")
    before = ew.snapshot(root)
    token = creation.token_identity()
    if token["default_owner_sid"] != token["user_sid"]:
        with pytest.raises(ValueError, match="owner mismatch") as caught:
            ew.Batch(root, "existing", 1024**2)
        details = json.loads(str(caught.value).split("; security=", 1)[1])
        assert details["actual_owner_sid"] == token["default_owner_sid"]
        assert details["expected_user_sid"] == token["user_sid"]
    else:
        with pytest.raises(ew.WorkspaceError, match="invalid batch-control size"):
            ew.Batch(root, "existing", 1024**2)
        win.private_acl(path)
    assert ew.snapshot(root) == before
    assert path.read_bytes() == b"preserve original bytes"


@pytest.mark.skipif(os.name != "nt", reason="Windows native admission probe")
def test_native_token_state_selects_supported_or_refused_route(tmp_path, monkeypatch):
    root = tmp_path / "private"
    ew.make_private(root)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    batch = ew.Batch(root, "native", 20 * ew.GIB)
    token = creation.token_identity()
    assert token["user_sid"] == win.owner_sid()
    assert token["default_owner_sid"].startswith("S-")
    assert type(token["elevated"]) is bool
    monkeypatch.setattr(
        pilot,
        "run_command",
        lambda *a: pytest.fail("unsupported native child launched"),
    )
    if token["user_sid"] == token["default_owner_sid"]:
        worker = batch.admit(pilot.RESERVATION)
        pilot.check_creation_token(batch, worker)
        expected = "supported"  # Admission only; no external build is fabricated.
    else:
        with pytest.raises(ew.WorkspaceError, match="default owner differs"):
            pilot.execute_pilot(
                batch, checkout, Path(sys.executable), tmp_path / "cache"
            )
        state = batch.report()
        worker, slot = next(iter(state["workers"].items()))
        assert state["stop"] and slot["status"] == "incomplete"
        expected = "incomplete"
    evidence = json.loads((batch.root / worker / "creation-token.json").read_bytes())
    assert evidence["status"] == expected and evidence["token"] == token
