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
        "workspace_git.py",
        "workspace_acl_diagnostics.py",
        "workspace_creation.py",
    ):
        (root / "tools" / name).write_bytes(name.encode())
    dotnet = tmp_path / "dotnet"
    dotnet.write_bytes(b"installed SDK")

    # Real linked-worktree Git regressions live in test_storage_review.py.
    monkeypatch.setattr(pilot, "git_identity", lambda *a: ("a" * 40, ""))
    # These tests fake .NET and exercise the supported-token route, not elevated builds.
    monkeypatch.setattr(
        pilot,
        "token_identity",
        lambda: {
            "user_sid": "S-1-5-21-1",
            "default_owner_sid": "S-1-5-21-1",
            "elevated": False,
        },
    )
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


def test_restore_and_build_disable_automatic_response_files(setup, monkeypatch):
    batch, root, dotnet, cache = setup
    checked = []

    def command(*args):
        if args[2] in {"restore", "build"}:
            assert "-noAutoResponse" in args[3]
            checked.append(args[2])
        return fake_run(*args)

    monkeypatch.setattr(pilot, "run_command", command)
    monkeypatch.setattr(pilot, "cached_references", lambda *a: None)
    pilot.execute_pilot(batch, root, dotnet, cache)
    assert checked == ["restore", "build"]


@pytest.mark.parametrize("label", ["restore", "build"])
def test_fixed_command_disables_ancestor_package_props(setup, monkeypatch, label):
    batch, root, dotnet, cache = setup
    commands = {}

    def command(*args):
        commands[args[2]] = args[3]
        return fake_run(*args)

    monkeypatch.setattr(pilot, "run_command", command)
    monkeypatch.setattr(pilot, "cached_references", lambda *a: None)
    pilot.execute_pilot(batch, root, dotnet, cache)
    assert "-p:ImportDirectoryPackagesProps=false" in commands[label]


@pytest.mark.parametrize("component", [";tag=one", ",tag=one", "%20", "@(tag)"])
def test_cli_refuses_msbuild_workspace_ancestor_before_batch(
    tmp_path, monkeypatch, capsys, component
):
    ancestor = tmp_path / component
    ew.make_private(ancestor)
    workspace = ancestor / "selected workspace"
    ew.make_private(workspace)
    # Native workspace checks are covered separately; exercise the CLI boundary.
    monkeypatch.setattr(pilot, "validate_workspace", lambda *a: workspace)

    def forbidden(*args):
        pytest.fail("unsafe MSBuild path reached batch creation")

    monkeypatch.setattr(pilot, "Batch", forbidden)
    assert (
        pilot.main(
            ["--workspace", str(workspace), "--batch", "test", "--budget-gib", "20"]
        )
        == 2
    )
    assert "unsupported MSBuild path syntax" in capsys.readouterr().err
    assert not list(workspace.iterdir())


@pytest.mark.parametrize("component", [";tag=one", ",tag=one", "%20", "@(tag)"])
@pytest.mark.parametrize("location", ["workspace", "cache"])
def test_execute_refuses_msbuild_paths_before_children(
    setup, monkeypatch, component, location
):
    batch, root, dotnet, cache = setup
    if location == "workspace":
        ancestor = batch.root.parent / component
        ew.make_private(ancestor)
        workspace = ancestor / "selected workspace"
        ew.make_private(workspace)
        batch = ew.Batch(workspace, "test", 20 * ew.GIB)
    else:
        cache = cache / component / "packages"

    def forbidden(*args):
        pytest.fail("unsafe MSBuild path launched a child")

    monkeypatch.setattr(pilot, "git_identity", forbidden)
    monkeypatch.setattr(pilot, "run_command", forbidden)
    with pytest.raises(ew.WorkspaceError, match="unsupported MSBuild path syntax"):
        pilot.execute_pilot(batch, root, dotnet, cache)
    assert batch.report()["workers"] == {}


@pytest.mark.parametrize("character", "%$@'();?,*")
def test_msbuild_reserved_path_characters_are_explicitly_unsupported(character):
    with pytest.raises(ew.WorkspaceError, match="unsupported MSBuild path syntax"):
        pilot.validate_msbuild_path(Path("cache") / character / "packages")


def test_msbuild_paths_keep_spaces_and_equals(setup, monkeypatch):
    batch, root, dotnet, cache = setup
    workspace = batch.root.parent / "selected space=one"
    ew.make_private(workspace)
    batch = ew.Batch(workspace, "test", 20 * ew.GIB)
    cache = cache / "cached space=one"
    checked = []

    def command(*args):
        if args[2] in {"restore", "build"}:
            directory = batch.root / args[1]
            assert f"-p:BaseIntermediateOutputPath={directory / 'obj'}/" in args[3]
            assert f"-p:MSBuildProjectExtensionsPath={directory / 'obj'}/" in args[3]
            assert f"-p:OutputPath={directory / 'out'}/" in args[3]
            assert f"-p:NetCoreTargetingPackRoot={cache}" in args[3]
            checked.append(args[2])
        return fake_run(*args)

    monkeypatch.setattr(pilot, "run_command", command)
    monkeypatch.setattr(pilot, "cached_references", lambda *a: None)
    pilot.execute_pilot(batch, root, dotnet, cache)
    assert checked == ["restore", "build"]


@pytest.mark.skipif(os.name != "nt", reason="Windows default-owner admission")
@pytest.mark.parametrize("failure", ["mismatch", "unreadable", "unknown"])
def test_cli_refuses_default_owner_before_any_child_and_retains_evidence(
    setup, monkeypatch, failure, capsys
):
    batch, root, dotnet, _ = setup
    calls = []

    def token():
        if failure == "unreadable":
            raise PermissionError("token query denied")
        return {
            "user_sid": "S-1-5-21-1",
            "default_owner_sid": "S-1-5-32-544" if failure == "mismatch" else None,
            "elevated": True,
        }

    def command(*args):
        calls.append(args[2])
        return fake_run(*args)

    monkeypatch.setattr(pilot, "ROOT", root)
    monkeypatch.setattr(pilot, "token_identity", token)
    monkeypatch.setattr(pilot, "validate_workspace", lambda *a: batch.root.parent)
    monkeypatch.setattr(pilot.shutil, "which", lambda *a: str(dotnet))
    monkeypatch.setattr(pilot, "run_command", command)
    monkeypatch.setattr(pilot, "cached_references", lambda *a: None)
    monkeypatch.setattr(
        pilot, "git_identity", lambda *a: calls.append("git-identity") or ("a" * 40, "")
    )
    assert (
        pilot.main(
            [
                "--workspace",
                str(batch.root.parent),
                "--batch",
                "test",
                "--budget-gib",
                "20",
            ]
        )
        == 2
    )
    assert not calls
    assert "incomplete" in capsys.readouterr().err
    state = batch.report()
    worker, slot = next(iter(state["workers"].items()))
    assert state["stop"] and slot["status"] == "incomplete"
    evidence = json.loads((batch.root / worker / "creation-token.json").read_bytes())
    assert evidence["status"] == "incomplete"
    assert not (batch.root / worker / "result.json").exists()
    assert not (batch.root / worker / "commands.jsonl").exists()


@pytest.mark.parametrize("elevated", [False, True])
def test_success_preserves_sources_and_routes_all_output(setup, monkeypatch, elevated):
    batch, root, dotnet, cache = setup
    before = ew.snapshot(root)
    monkeypatch.setattr(
        pilot,
        "token_identity",
        lambda: {
            "user_sid": "S-1-5-21-1",
            "default_owner_sid": "S-1-5-21-1",
            "elevated": elevated,
        },
    )
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


@pytest.mark.parametrize("workspace", ["", "C:/not-allowed"])
def test_refuses_invalid_workspace_before_build(workspace, monkeypatch):
    calls = []
    monkeypatch.setattr(pilot, "execute_pilot", lambda *args: calls.append(args))
    assert (
        pilot.main(["--workspace", workspace, "--batch", "test", "--budget-gib", "20"])
        == 2
    )
    assert not calls


@pytest.mark.skipif(os.name != "nt", reason="Windows workspace trust boundary")
def test_missing_workspace_refused_before_batch(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing-workspace"
    assert not missing.exists()
    inspected = []

    def physical(path):
        # Model an admitted volume; inspect a real test-owned missing directory.
        assert path == missing
        inspected.append(path)
        path.lstat()

    def forbidden(*args):
        pytest.fail("missing workspace reached batch creation or a build")

    monkeypatch.setattr(ew.windows, "physical_path", physical)
    monkeypatch.setattr(pilot, "Batch", forbidden)
    monkeypatch.setattr(pilot, "execute_pilot", forbidden)
    assert (
        pilot.main(
            ["--workspace", str(missing), "--batch", "test", "--budget-gib", "20"]
        )
        == 2
    )
    result = json.loads(capsys.readouterr().err)
    assert result["status"] == "incomplete" and result["batch"] is None
    assert repr(str(missing)) in result["reason"]
    assert "[WinError 2]" in result["reason"]
    assert inspected == [missing]
    assert not missing.exists()


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
