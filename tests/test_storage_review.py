"""Real Git/process regressions for the first storage-pilot review."""

import ctypes as c
from ctypes import wintypes as w
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import threading
import uuid

import pytest

from tools import evidence_workspace as ew
from tools import run_storage_pilot as pilot
from tools import workspace_windows as win
from tools.workspace_git import git_identity


def child_environment():
    return {
        key: os.environ[key]
        for key in ("SystemRoot", "TEMP", "TMP")
        if key in os.environ
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows rejection diagnostics")
@pytest.mark.parametrize("failure", ["owner", "null-dacl"])
def test_private_acl_rejection_distinguishes_native_metadata(
    tmp_path, monkeypatch, failure
):
    # Diagnostic-unit seams only; neither injection proves the GitHub cause.
    path = tmp_path / "private"
    win.make_private(path)
    actual_user = win.owner_sid()
    if failure == "owner":
        monkeypatch.setattr(win, "owner_sid", lambda: "S-1-5-18")
        reason = "owner mismatch"
    else:
        kernel, native = win.libraries()
        get_named = native.GetNamedSecurityInfoW

        def null_dacl(*args):
            result = get_named(*args)
            if result == 0:
                c.cast(args[5], c.POINTER(c.c_void_p))[0] = None
            return result

        class Security:
            GetNamedSecurityInfoW = staticmethod(null_dacl)

            def __getattr__(self, name):
                return getattr(native, name)

        monkeypatch.setattr(win, "libraries", lambda: (kernel, Security()))
        reason = "DACL is null"
    with pytest.raises(ValueError, match=reason) as caught:
        win.private_acl(path)
    details = json.loads(str(caught.value).split("; security=", 1)[1])
    assert details["actual_owner_sid"] == actual_user
    assert details["expected_user_sid"] == (
        "S-1-5-18" if failure == "owner" else actual_user
    )
    assert details["dacl"] == ("present" if failure == "owner" else "null")
    assert details["token_default_owner_sid"].startswith("S-")
    assert type(details["token_elevated"]) is bool
    if failure == "owner":
        assert {ace["sid"] for ace in details["aces"]} == {actual_user, "S-1-5-18"}
        assert all(
            ace["type"] == 0 and ace["mask"] == 0x1F01FF for ace in details["aces"]
        )
    else:
        assert details["aces"] == []


@pytest.fixture
def case(tmp_path):
    workspace = tmp_path / "workspace"
    ew.make_private(workspace)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    return ew.Batch(workspace, "review", 20 * ew.GIB), checkout


@pytest.mark.parametrize("inherited", [False, True])
def test_real_linked_worktree_identity_never_writes_git_admin(
    case, monkeypatch, inherited
):
    batch, root = case
    repo = root.parent / "repo"
    repo.mkdir()
    git_env = {
        **child_environment(),
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }

    def git(*args):
        return (
            subprocess.run(
                ["git", "-C", str(repo), *args],
                check=True,
                capture_output=True,
                env=git_env,
            )
            .stdout.decode()
            .strip()
        )

    git("init")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Storage fixture")
    for name in (
        *pilot.SOURCES,
        *(
            "tools/" + n
            for n in (
                "run_storage_pilot.py",
                "evidence_workspace.py",
                "workspace_windows.py",
                "workspace_git.py",
                "workspace_acl_diagnostics.py",
                "workspace_creation.py",
            )
        ),
    ):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
    git("add", ".")
    git("commit", "-m", "Create fixture")
    git("worktree", "add", "--detach", str(root))
    admin = Path(
        subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--absolute-git-dir"], env=git_env
        )
        .decode()
        .strip()
    )
    index = admin / "index"
    # Invalidate cached stat data without changing tracked content.
    source = root / pilot.SOURCES[1]
    info = source.stat()
    os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns + 10_000_000_000))
    before = ew.snapshot(admin, directories=True)
    common_before = ew.snapshot(repo / ".git", directories=True)
    index_before = index.read_bytes()
    canary = root.parent / "inherited-git-trace"
    if inherited:
        monkeypatch.setenv("GIT_TRACE", str(canary))
        monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "untrusted-monitor")
    # This is the read-only Git primitive, not the guarded .NET pilot route.
    worker = batch.admit(pilot.RESERVATION)
    directory = batch.root / worker
    for name in ("home", "temp"):
        ew.make_private(directory / name)
    head, dirty = git_identity(
        batch,
        worker,
        root,
        pilot.environment(directory, Path(sys.executable).resolve(strict=True)),
        ew.CheckoutScratch(root),
        pilot.run_command,
    )
    assert not canary.exists(), "inherited Git tracing wrote outside the workspace"
    assert index.read_bytes() == index_before, "Git refreshed the linked-worktree index"
    assert ew.snapshot(admin, directories=True) == before
    assert ew.snapshot(repo / ".git", directories=True) == common_before
    assert head == git("rev-parse", "HEAD")
    assert dirty == ""


def test_detected_stop_between_evidence_and_launch_prevents_real_process(
    case, monkeypatch
):
    batch, root = case
    first = batch.admit(1024 * 1024)
    second = batch.admit(100)
    ready, stopped = threading.Event(), threading.Event()
    errors = []

    def overrun():
        try:
            assert ready.wait(10)
            with os.fdopen(
                ew.create_private_file(batch.root / second / "tool-output"), "wb"
            ) as output:
                output.write(b"x" * 101)
            with pytest.raises(ew.WorkspaceError, match="overrun"):
                ew.Batch(batch.root.parent, "review", batch.budget).check()
        except BaseException as error:
            errors.append(error)
        finally:
            stopped.set()

    original = batch.write

    def write(*args, **kwargs):
        original(*args, **kwargs)
        if args[1] == "next.stderr":
            ready.set()
            assert stopped.wait(10)

    monkeypatch.setattr(batch, "write", write)
    popen = subprocess.Popen

    def real_creation(*args, **kwargs):
        process = popen(*args, **kwargs)
        process.wait(timeout=10)
        assert not json.loads(batch.control.read_bytes())["stop"], (
            "real process launched after persisted batch stop"
        )
        return process

    monkeypatch.setattr(pilot.subprocess, "Popen", real_creation)
    if hasattr(win.ProcessJob, "spawn"):
        native = win.ProcessJob.spawn

        def native_creation(self, *args, **kwargs):
            process = native(self, *args, **kwargs)
            process.wait(timeout=10)
            assert not json.loads(batch.control.read_bytes())["stop"], (
                "native process launched after persisted batch stop"
            )
            return process

        monkeypatch.setattr(win.ProcessJob, "spawn", native_creation)
    other = threading.Thread(target=overrun)
    other.start()
    marker = batch.root / first / "launched"
    try:
        with pytest.raises(ew.WorkspaceError, match="overrun"):
            pilot.run_command(
                batch,
                first,
                "next",
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "from pathlib import Path; Path('launched').touch()",
                ],
                child_environment(),
                ew.CheckoutScratch(root),
            )
    finally:
        ready.set()
        other.join(15)
    assert not errors
    assert not other.is_alive()
    # Even entering the real Popen path is forbidden after a persisted stop.
    assert not marker.exists()
    assert "overrun" in batch.report()["stop"]


def test_final_write_scan_raises_and_preserves_detected_stop(case, monkeypatch):
    batch, _ = case
    first, second = batch.admit(10000), batch.admit(100)
    refresh = batch._refresh
    calls = 0

    def concurrent_output(state):
        nonlocal calls
        calls += 1
        if calls == 2:
            with os.fdopen(
                ew.create_private_file(batch.root / second / "tool-output"), "wb"
            ) as output:
                output.write(b"x" * 101)
        return refresh(state)

    monkeypatch.setattr(batch, "_refresh", concurrent_output)
    with pytest.raises(ew.WorkspaceError, match="overrun"):
        batch.write(first, "retained", b"evidence")
    assert (batch.root / first / "retained").read_bytes() == b"evidence"
    assert "overrun" in json.loads(batch.control.read_bytes())["stop"]


def _interrupted_launcher(workspace, checkout, created, release, pids, event_name):
    # Pause immediately after real process creation returns, before the caller
    # can do any post-creation containment. No fake process replaces this path.
    if hasattr(win.ProcessJob, "spawn"):
        original = win.ProcessJob.spawn

        def spawn(self, *args, **kwargs):
            process = original(self, *args, **kwargs)
            pids.put(process.pid)
            created.set()
            assert release.wait(20)
            return process

        win.ProcessJob.spawn = spawn
    else:
        original = pilot.subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            pids.put(process.pid)
            created.set()
            assert release.wait(20)
            return process

        pilot.subprocess.Popen = spawn
    batch = ew.Batch(Path(workspace), "tree", 20 * ew.GIB)
    worker = batch.admit(1024 * 1024)
    grandchild = "import threading; threading.Event().wait()"
    child = (
        "import ctypes as c, subprocess, sys; from pathlib import Path; "
        f"p=subprocess.Popen([sys.executable,'-B','-c',{grandchild!r}]); "
        f"sys.path.insert(0,{str(pilot.ROOT)!r}); "
        "from tools.evidence_workspace import create_private_file; import os; "
        "fd=create_private_file(Path('grandchild.pid')); "
        "os.write(fd,str(p.pid).encode()); os.close(fd); "
        "k=c.WinDLL('kernel32',use_last_error=True); "
        "k.OpenEventW.argtypes=[c.c_uint32,c.c_int,c.c_wchar_p]; "
        "k.OpenEventW.restype=c.c_void_p; k.SetEvent.argtypes=[c.c_void_p]; "
        f"assert k.SetEvent(k.OpenEventW(2,False,{event_name!r})); "
        "import threading; threading.Event().wait()"
    )
    pilot.run_command(
        batch,
        worker,
        "tree",
        [sys.executable, "-B", "-c", child],
        child_environment(),
        ew.CheckoutScratch(Path(checkout)),
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows atomic job containment")
def test_real_process_tree_dies_if_launcher_killed_at_creation_return(case):
    batch, root = case
    kernel, _ = win.libraries()
    kernel.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    kernel.CreateEventW.restype = w.HANDLE
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    name = "Local\\samtv-tree-" + uuid.uuid4().hex
    event = kernel.CreateEventW(None, True, False, name)
    win.checked(event)
    context = multiprocessing.get_context("spawn")
    created, release, pids = context.Event(), context.Event(), context.Queue()
    launcher = context.Process(
        target=_interrupted_launcher,
        args=(str(batch.root.parent), str(root), created, release, pids, name),
    )
    handles = []
    try:
        launcher.start()
        assert created.wait(15), "launcher did not reach native creation return"
        child_pid = pids.get(timeout=5)
        child = kernel.OpenProcess(0x100001, False, child_pid)
        win.checked(child)
        handles.append(child)
        assert kernel.WaitForSingleObject(event, 15000) == 0, "descendant not ready"
        tree = batch.root.parent / "tree"
        grandchild_pid = int(next(tree.glob("*/grandchild.pid")).read_text())
        grandchild = kernel.OpenProcess(0x100001, False, grandchild_pid)
        win.checked(grandchild)
        handles.append(grandchild)
        launcher.kill()
        launcher.join(10)
        assert not launcher.is_alive()
        assert [kernel.WaitForSingleObject(h, 5000) for h in handles] == [0, 0], (
            "child/descendant survived launcher termination at creation return"
        )
        state = ew.Batch(batch.root.parent, "tree", 20 * ew.GIB).report()
        assert all(s["status"] == "incomplete" for s in state["workers"].values())
    finally:
        if launcher.is_alive():
            launcher.kill()
            launcher.join(10)
        # Only handles opened for these exact test-owned processes are killed.
        for handle in reversed(handles):
            if kernel.WaitForSingleObject(handle, 0) != 0:
                kernel.TerminateProcess(handle, 1)
                kernel.WaitForSingleObject(handle, 5000)
            kernel.CloseHandle(handle)
        kernel.CloseHandle(event)
        pids.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows job-list creation failure")
def test_invalid_job_refuses_native_creation_without_uncontained_fallback(case):
    _, root = case
    marker = root / "must-not-launch"
    job = win.ProcessJob()
    job.close()
    with pytest.raises(OSError):
        job.spawn(
            [
                sys.executable,
                "-B",
                "-c",
                "from pathlib import Path; Path('must-not-launch').touch()",
            ],
            cwd=root,
            env=child_environment(),
        )
    assert not marker.exists()
