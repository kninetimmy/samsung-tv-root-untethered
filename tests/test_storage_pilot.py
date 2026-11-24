import json
import os
from pathlib import Path
import sys

import pytest

from tools import evidence_workspace as ew
from tools import run_storage_pilot as pilot


@pytest.fixture
def setup(tmp_path, monkeypatch):
    workspace = tmp_path / "private"
    ew.make_private(workspace)
    root = tmp_path / "checkout"
    root.mkdir()
    for name in pilot.SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
    for name in (
        "evidence_workspace.py",
        "run_storage_pilot.py",
        "workspace_windows.py",
    ):
        (root / "tools" / name).write_bytes(name.encode())
    dotnet = tmp_path / "dotnet"
    dotnet.write_bytes(b"installed SDK")

    # Fake Git identity; fixed-runner tests replace .NET at run_command.
    class Git:
        stdout = b"a" * 40

    monkeypatch.setattr(pilot.subprocess, "run", lambda *a, **kw: Git())
    return ew.Batch(workspace, "test", 20 * ew.GIB), root, dotnet, tmp_path / "cache"


def fake_run(batch, worker, label, command, env, scratch):
    batch.check()
    scratch.check()
    if label == "sdk-version":
        return b"10.0.115"
    if label == "selftest":
        assert command[-1] == str(batch.root / worker / "out/PowerGateSelfTest.dll")
        return b'{"passed":27,"real_native_calls":0}'
    if label == "restore":
        assert "--source" in command
        assert command[command.index("--source") + 1] == str(
            batch.root / worker / "feed"
        )
    if label == "build":
        assert "--no-restore" in command
        assert "--disable-build-servers" in command
        assert "-p:AppendTargetFrameworkToOutputPath=false" in command
        batch.write(worker, "out/PowerGateSelfTest.dll", b"fake test assembly")
    batch.write(worker, label + ".stdout", b"raw retained")
    batch.write(worker, label + ".stderr", b"")
    return b""


def test_success_preserves_sources_and_routes_all_output(setup, monkeypatch):
    batch, root, dotnet, cache = setup
    before = ew.snapshot(root)
    monkeypatch.setattr(pilot, "run_command", fake_run)
    monkeypatch.setattr(pilot, "cached_references", lambda *args: None)
    worker = pilot.execute_pilot(batch, root, dotnet, cache)
    result = json.loads((batch.root / worker / "result.json").read_bytes())
    assert result["status"] == "selftest-passed"
    assert result["selftest"]["real_native_calls"] == 0
    assert result["checkout_scratch_peak_bytes"] == 0
    assert ew.snapshot(root) == before
    assert batch.report()["workers"][worker]["status"] == "complete"
    for name in pilot.SOURCES:
        assert (root / name).read_bytes() == (
            batch.root / worker / "source" / name
        ).read_bytes()


@pytest.mark.parametrize(
    "failure", ["build", "interrupted", "missing-cache", "scratch"]
)
def test_failures_retain_incomplete_evidence(setup, monkeypatch, failure):
    batch, root, dotnet, cache = setup

    def command(*args):
        label = args[2]
        if label == "build":
            if failure == "interrupted":
                raise KeyboardInterrupt("interrupted")
            if failure == "scratch":
                (root / "new-output").write_bytes(b"unwanted")
            else:
                raise ew.WorkspaceError("build failed")
        return fake_run(*args)

    monkeypatch.setattr(pilot, "run_command", command)
    if failure != "missing-cache":
        monkeypatch.setattr(pilot, "cached_references", lambda *args: None)
    with pytest.raises((ew.WorkspaceError, OSError, KeyboardInterrupt)):
        pilot.execute_pilot(batch, root, dotnet, cache)
    state = batch.report()
    worker, slot = next(iter(state["workers"].items()))
    assert state["stop"]
    assert slot["status"] == "incomplete"
    assert (batch.root / worker / "identity.json").exists()
    assert not (batch.root / worker / "result.json").exists()


@pytest.mark.parametrize(
    "result",
    [
        {"passed": 27, "real_native_calls": 1},
        {"passed": True, "real_native_calls": False},
    ],
)
def test_native_call_report_must_be_explicit_zero(setup, monkeypatch, result):
    batch, root, dotnet, cache = setup

    def command(*args):
        output = fake_run(*args)
        return json.dumps(result).encode() if args[2] == "selftest" else output

    monkeypatch.setattr(pilot, "run_command", command)
    monkeypatch.setattr(pilot, "cached_references", lambda *args: None)
    with pytest.raises(ew.WorkspaceError, match="zero real native calls"):
        pilot.execute_pilot(batch, root, dotnet, cache)
    assert all(
        slot["status"] == "incomplete" for slot in batch.report()["workers"].values()
    )


@pytest.mark.parametrize("workspace", ["", "C:/not-allowed", "E:/missing-workspace"])
def test_refuses_invalid_workspace_before_build(workspace, monkeypatch):
    calls = []
    monkeypatch.setattr(pilot, "execute_pilot", lambda *args: calls.append(args))
    assert (
        pilot.main(["--workspace", workspace, "--batch", "test", "--budget-gib", "20"])
        == 2
    )
    assert not calls


@pytest.mark.skipif(os.name != "nt", reason="Windows workspace trust boundary")
@pytest.mark.parametrize("failure", ["redirected", "privacy", "inside-checkout"])
def test_workspace_checks_fail_closed(tmp_path, monkeypatch, failure):
    def physical(path):
        if failure == "redirected":
            raise ValueError("redirected")

    def private(path):
        if failure == "privacy":
            raise ValueError("non-private")

    monkeypatch.setattr(ew.windows, "physical_path", physical)
    monkeypatch.setattr(ew, "private", private)
    with pytest.raises((ValueError, ew.WorkspaceError)):
        ew.validate_workspace(
            str(tmp_path),
            tmp_path if failure == "inside-checkout" else Path("C:/other"),
        )


def test_environment_ignores_inherited_sources_and_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("RestoreSources", "https://invalid.example")
    monkeypatch.setenv("MSBuildSDKsPath", "untrusted")
    env = pilot.environment(tmp_path, Path("C:/installed/dotnet.exe"))
    assert "RestoreSources" not in env
    assert "MSBuildSDKsPath" not in env
    for key in (
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "NUGET_PACKAGES",
        "NUGET_HTTP_CACHE_PATH",
        "NUGET_SCRATCH",
        "DOTNET_CLI_HOME",
    ):
        assert Path(env[key]).is_relative_to(tmp_path)


def test_environment_keeps_windows_installation_locations(tmp_path, monkeypatch):
    # NuGet's Windows shared-config lookup requires ProgramFiles(x86).
    monkeypatch.setenv("ProgramFiles(x86)", "C:/installed-x86")
    env = pilot.environment(tmp_path, Path("C:/installed/dotnet.exe"))
    assert env["ProgramFiles(x86)"] == "C:/installed-x86"


@pytest.mark.parametrize("exit_code", [0, 3])
def test_real_process_raw_capture_and_failure(setup, exit_code):
    batch, root, _, _ = setup
    worker = batch.admit(pilot.RESERVATION)
    scratch = ew.CheckoutScratch(root)
    env = {key: os.environ[key] for key in ("SystemRoot",) if key in os.environ}
    command = [
        sys.executable,
        "-B",
        "-c",
        f"import sys; sys.stdout.buffer.write(bytes([0,255,10])); sys.stderr.buffer.write(b'raw error'); sys.exit({exit_code})",
    ]
    if exit_code:
        with pytest.raises(ew.WorkspaceError, match="exit 3"):
            pilot.run_command(batch, worker, "capture", command, env, scratch)
    else:
        assert pilot.run_command(
            batch, worker, "capture", command, env, scratch
        ) == bytes([0, 255, 10])
    assert (batch.root / worker / "capture.stdout").read_bytes() == bytes([0, 255, 10])
    assert (batch.root / worker / "capture.stderr").read_bytes() == b"raw error"


def test_real_process_output_exhaustion_retains_partial_evidence(setup):
    batch, root, _, _ = setup
    worker = batch.admit(128 * 1024)
    env = {key: os.environ[key] for key in ("SystemRoot",) if key in os.environ}
    command = [
        sys.executable,
        "-B",
        "-c",
        "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024))",
    ]
    with pytest.raises(
        ew.WorkspaceError, match="reservation exhausted|could not be retained"
    ):
        pilot.run_command(
            batch, worker, "exhaust", command, env, ew.CheckoutScratch(root)
        )
    state = batch.report()
    assert state["stop"] == "controlled evidence reservation exhausted"
    assert (batch.root / worker / "exhaust.stdout").stat().st_size > 0
    assert state["workers"][worker]["evidence_bytes"] <= 32 * 1024
