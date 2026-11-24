import json
import multiprocessing
import os
from pathlib import Path
import subprocess

import pytest

from tools import evidence_workspace as ew
from tools import workspace_windows as win


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "private"
    ew.make_private(root)
    return root


@pytest.mark.skipif(os.name != "nt", reason="Windows native owner/DACL evidence")
def test_windows_native_descendant_privacy_probe(tmp_path):
    # No Batch fixture: preserve the native rejection even when Batch cannot start.
    root = tmp_path / "native-private"
    try:
        win.make_private(root)
        child = root / "inherited-directory"
        child.mkdir()
        file = child / "inherited-file"
        file.write_bytes(b"private probe")
        for path in (root, child, file):
            win.private_acl(path)
    except (OSError, ValueError) as error:
        pytest.fail(f"native descendant privacy probe: {error}", pytrace=False)


def test_success_and_control_reserve(workspace):
    batch = ew.Batch(workspace, "test", 1024**2)
    worker = batch.admit(10000)
    batch.write(worker, "raw.stdout", b"retained")
    batch.finish(worker, success=True, reason="passed")
    state = batch.report()
    assert state["workers"][worker]["status"] == "complete"
    assert state["peak_bytes"] == ew.CONTROL_BYTES + 8
    assert batch.control.stat().st_size == ew.CONTROL_BYTES
    with pytest.raises(ew.WorkspaceError, match="differs"):
        ew.Batch(workspace, "test", 2 * 1024**2)


def test_tiny_budget_retains_incomplete_control(workspace):
    batch = ew.Batch(workspace, "tiny", ew.CONTROL_BYTES + 1)
    with pytest.raises(ew.WorkspaceError, match="capacity exhausted"):
        batch.admit(2)
    assert "capacity exhausted" in batch.report()["stop"]
    assert batch.control.exists()


def test_completed_reservation_cannot_be_reused_by_old_worker(workspace):
    batch = ew.Batch(workspace, "test", 1024**2)
    worker = batch.admit(10000)
    batch.write(worker, "raw.stdout", b"retained")
    batch.finish(worker, success=True, reason="passed")
    with pytest.raises(ew.WorkspaceError, match="after worker completion"):
        batch.write(worker, "raw.stdout", b"changed", append=True)
    assert (batch.root / worker / "raw.stdout").read_bytes() == b"retained"


def test_controlled_evidence_cannot_exceed_its_reservation(workspace):
    batch = ew.Batch(workspace, "test", 1024**2)
    worker = batch.admit(100)
    batch.write(worker, "raw.stdout", b"already retained")
    with pytest.raises(ew.WorkspaceError, match="reservation exhausted"):
        batch.write(worker, "raw.stdout", b"x" * 20, append=True)
    assert (batch.root / worker / "raw.stdout").read_bytes() == b"already retained"
    batch.finish(worker, success=False, reason="output exhausted")
    assert batch.report()["workers"][worker]["status"] == "incomplete"


def test_uncontrolled_overrun_latches_batch_and_retains_peak(workspace):
    batch = ew.Batch(workspace, "test", ew.CONTROL_BYTES + 100)
    worker = batch.admit(100)
    path = batch.root / worker / "build.output"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(b"x" * 101)
    with pytest.raises(ew.WorkspaceError, match="overrun"):
        batch.check()
    batch.finish(worker, success=True, reason="cannot claim success")
    state = batch.report()
    assert state["peak_bytes"] == ew.CONTROL_BYTES + 101
    assert state["workers"][worker]["status"] == "incomplete"
    with pytest.raises(ew.WorkspaceError, match="overrun"):
        batch.admit(1)
    assert path.exists()


def _synchronized_worker(workspace, barrier, results):
    batch = ew.Batch(Path(workspace), "shared", ew.CONTROL_BYTES + 10000)
    barrier.wait(timeout=20)
    try:
        worker = batch.admit(10000)
        results.put(("admitted", worker))
    except ew.WorkspaceError as error:
        results.put(("refused", str(error)))
    barrier.wait(timeout=20)


def test_two_synchronized_processes_share_one_budget(workspace):
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    workers = [
        context.Process(
            target=_synchronized_worker, args=(str(workspace), barrier, results)
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    outcomes = [results.get(timeout=30) for _ in workers]
    for worker in workers:
        worker.join(timeout=30)
        assert worker.exitcode == 0
    assert sorted(outcome[0] for outcome in outcomes) == ["admitted", "refused"]
    batch = ew.Batch(workspace, "shared", ew.CONTROL_BYTES + 10000)
    state = batch.report()
    assert len(state["workers"]) == 1
    assert next(iter(state["workers"].values()))["status"] == "incomplete"
    assert state["stop"]


def test_interruption_never_becomes_complete(workspace):
    batch = ew.Batch(workspace, "test", 1024**2)
    worker = batch.admit(10000)
    batch.write(worker, "raw.stdout", b"partial")
    reopened = ew.Batch(workspace, "test", 1024**2)
    assert reopened.report()["workers"][worker]["status"] == "incomplete"
    assert (batch.root / worker / "raw.stdout").read_bytes() == b"partial"


def test_invalid_control_is_incomplete_not_reinitialized(workspace):
    batch = ew.Batch(workspace, "test", 1024**2)
    data = b"{}" + b" " * (ew.CONTROL_BYTES - 2)
    batch.control.write_bytes(data)
    with pytest.raises(
        ew.WorkspaceError, match="invalid batch-control schema; incomplete"
    ):
        ew.Batch(workspace, "test", 1024**2)
    assert batch.control.read_bytes() == data


def test_short_control_write_cannot_report_success():
    class ShortWrite:
        def seek(self, offset):
            pass

        def write(self, data):
            return len(data) - 1

    with pytest.raises(
        ew.WorkspaceError, match="short batch-control write; incomplete"
    ):
        ew.Batch._save(ShortWrite(), {"status": "complete"})


def test_accounting_errors_fail_closed(workspace, monkeypatch):
    batch = ew.Batch(workspace, "test", 1024**2)
    worker = batch.admit(10000)
    monkeypatch.setattr(
        ew,
        "snapshot",
        lambda *a, **kw: (_ for _ in ()).throw(PermissionError("denied")),
    )
    with pytest.raises(PermissionError, match="denied"):
        batch.check()
    state = json.loads(batch.control.read_bytes())
    assert "accounting inspection failed" in state["stop"]
    assert state["workers"][worker]["status"] == "incomplete"


def test_hardlinks_are_refused(workspace):
    source = workspace / "one"
    source.write_bytes(b"x")
    os.link(source, workspace / "two")
    with pytest.raises(ew.WorkspaceError, match="hardlinked"):
        ew.snapshot(workspace)


def test_checkout_scratch_separates_preexisting_bytes(tmp_path):
    existing = tmp_path / "existing"
    existing.write_bytes(b"old")
    scratch = ew.CheckoutScratch(tmp_path)
    assert scratch.check() == 0
    (tmp_path / "new").write_bytes(b"new")
    assert scratch.check() == 3
    with pytest.raises(ew.WorkspaceError, match="checkout changed"):
        scratch.check(final=True)


def test_checkout_scratch_ceiling(tmp_path, monkeypatch):
    scratch = ew.CheckoutScratch(tmp_path)
    monkeypatch.setattr(
        ew, "snapshot", lambda root, **kw: {"new": (1, 2, 5 * ew.GIB + 1, 0)}
    )
    with pytest.raises(ew.WorkspaceError, match="exceeds 5 GiB"):
        scratch.check()


def test_checkout_empty_output_directory_is_not_success(tmp_path):
    scratch = ew.CheckoutScratch(tmp_path)
    (tmp_path / "obj").mkdir()
    assert scratch.check() == 0
    with pytest.raises(ew.WorkspaceError, match="checkout changed"):
        scratch.check(final=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL and path APIs")
def test_windows_private_creation_and_preexisting_refusal(tmp_path):
    path = tmp_path / "private"
    win.make_private(path)
    win.private_acl(path)
    child = path / "child"
    child.mkdir()
    win.private_acl(child)
    # An unrelated system directory does not qualify and is not rewritten.
    with pytest.raises(ValueError, match="private|access"):
        win.private_acl(Path(os.environ["SystemRoot"]))
    with pytest.raises(OSError):
        win.make_private(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction API")
def test_windows_junction_is_not_traversed(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    # Fixed script; paths are environment data, not command interpolation.
    command = "New-Item -ItemType Junction -Path $env:TEST_LINK -Target $env:TEST_TARGET | Out-Null"
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "TEST_LINK": str(junction), "TEST_TARGET": str(target)},
        check=True,
    )
    with pytest.raises(ew.WorkspaceError, match="redirected"):
        ew.snapshot(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="NTFS named stream API")
def test_windows_named_stream_refuses_incomplete_accounting(tmp_path):
    path = tmp_path / "ordinary"
    path.write_bytes(b"visible")
    Path(str(path) + ":hidden").write_bytes(b"unaccounted")
    with pytest.raises(ValueError, match="named data stream"):
        ew.snapshot(tmp_path)
