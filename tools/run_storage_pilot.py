"""Build and run ONLY the host PowerGateSelfTest, offline in a private E: batch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from xml.sax.saxutils import quoteattr

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.evidence_workspace import (
    Batch,
    CheckoutScratch,
    GIB,
    WorkspaceError,
    make_private,
    ordinary,
    snapshot,
    validate_workspace,
)
from tools.workspace_windows import ProcessJob
from tools.workspace_git import git_identity
from tools.workspace_creation import token_identity

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "tools/reboot-helper/selftest/PowerGateSelfTest.csproj"
SOURCES = (
    PROJECT,
    "tools/reboot-helper/selftest/PowerGateSelfTest.cs",
    "tools/reboot-helper/LinuxRebootHelper.cs",
    "tools/reboot-helper/snapshot.sh",
)
RESERVATION = GIB


def digest(path):
    ordinary(path)
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def source_identity(root):
    return {name: digest(root / name) for name in SOURCES}


def environment(worker, dotnet):
    # No inherited package sources, proxy, MSBuild overrides, or user-profile output.
    env = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "ProgramFiles(x86)")
        if key in os.environ
    }
    env.update(
        {
            "PATH": str(dotnet.parent)
            + os.pathsep
            + str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"),
            "DOTNET_ROOT": str(dotnet.parent),
            "DOTNET_CLI_HOME": str(worker / "home"),
            "USERPROFILE": str(worker / "home"),
            "HOME": str(worker / "home"),
            "APPDATA": str(worker / "home"),
            "LOCALAPPDATA": str(worker / "home"),
            "TEMP": str(worker / "temp"),
            "TMP": str(worker / "temp"),
            "TMPDIR": str(worker / "temp"),
            "NUGET_PACKAGES": str(worker / "packages"),
            "NUGET_HTTP_CACHE_PATH": str(worker / "http"),
            "NUGET_PLUGINS_CACHE_PATH": str(worker / "plugins"),
            "NUGET_SCRATCH": str(worker / "temp"),
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
            "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "false",
            "DOTNET_BUNDLE_EXTRACT_BASE_DIR": str(worker / "temp"),
            "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
            "DOTNET_CLI_USE_MSBUILD_SERVER": "0",
            "MSBUILDDISABLENODEREUSE": "1",
            "MSBuildEnableWorkloadResolver": "false",
            "DOTNET_MULTILEVEL_LOOKUP": "0",
            "DOTNET_EnableDiagnostics": "0",
            "COMPlus_EnableDiagnostics": "0",
            "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_UI_LANGUAGE": "en-US",
            "NUGET_XMLDOC_MODE": "skip",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def run_command(batch, worker, label, command, env, scratch):
    directory = batch.root / worker
    batch.check()
    scratch.check()
    batch.write(
        worker,
        "commands.jsonl",
        (
            json.dumps(
                {
                    "label": label,
                    "argv": command,
                    "cwd": str(directory),
                    "environment": env,
                }
            )
            + "\n"
        ).encode(),
        append=True,
    )
    for stream in ("stdout", "stderr"):
        batch.write(worker, f"{label}.{stream}", b"")
    process = None
    job = None
    threads = []
    errors = []

    def capture(pipe, name):
        try:
            with pipe:
                while chunk := pipe.read(16384):
                    batch.write(worker, f"{label}.{name}", chunk, append=True)
        except BaseException as error:
            errors.append(error)

    try:
        with batch.launch():
            scratch.check()
            if os.name == "nt":
                job = ProcessJob()
                process = job.spawn(command, cwd=directory, env=env)
            else:
                process = subprocess.Popen(
                    command,
                    cwd=directory,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
        for name in ("stdout", "stderr"):
            thread = threading.Thread(
                target=capture, args=(getattr(process, name), name)
            )
            threads.append(thread)
            thread.start()
        while True:
            batch.check()
            scratch.check()
            if errors:
                raise WorkspaceError(f"raw output could not be retained: {errors[0]}")
            try:
                code = process.wait(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        try:
            if job:
                job.close()
        finally:
            if process:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                for thread in threads:
                    thread.join()
                for pipe in (process.stdout, process.stderr):
                    pipe.close()
    if errors:
        raise WorkspaceError(f"raw output could not be retained: {errors[0]}")
    batch.check()
    scratch.check()
    batch.write(
        worker,
        "commands.jsonl",
        (json.dumps({"label": label, "exit_code": code}) + "\n").encode(),
        append=True,
    )
    if code:
        raise WorkspaceError(
            f"{label} failed with exit {code}; cached prerequisites may be missing; no download attempted"
        )
    return (directory / f"{label}.stdout").read_bytes()


def cached_references(batch, worker, cache):
    """Use an extracted reference pack read-only; never unpack/download packages."""
    pack = cache / "microsoft.netcore.app.ref/6.0.36"
    names = ["data/FrameworkList.xml", "ref/net6.0/System.Runtime.dll"]
    try:
        hashes = {name: digest(pack / name) for name in names}
    except OSError as error:
        raise WorkspaceError(
            "cached net6.0 reference pack 6.0.36 unavailable; no download attempted"
        ) from error
    batch.write(
        worker,
        "cached-references.json",
        json.dumps({"root": str(pack), "sha256": hashes}).encode(),
    )


def check_creation_token(batch, worker):
    if os.name != "nt":
        return  # Only direct primitive tests run outside the Windows CLI.
    token, reason = {}, None
    try:
        token = token_identity()
        if not isinstance(token, dict) or not all(
            isinstance(token.get(key), str) and token[key].startswith("S-")
            for key in ("user_sid", "default_owner_sid")
        ):
            raise ValueError("unknown token ownership")
        if token["user_sid"] != token["default_owner_sid"]:
            reason = "external pilot commands refused: token default owner differs from token user"
    except (OSError, ValueError) as error:
        reason = f"token ownership inspection failed: {error}"
    batch.write(
        worker,
        "creation-token.json",
        json.dumps(
            {
                "status": "incomplete" if reason else "supported",
                "token": token,
                "reason": reason,
            }
        ).encode(),
    )
    if reason:
        raise WorkspaceError(reason)


def execute_pilot(batch, root, dotnet, cache):
    scratch = CheckoutScratch(root)
    worker = batch.admit(RESERVATION)
    directory = batch.root / worker
    success = False
    reason = "worker interrupted; no complete result"
    try:
        check_creation_token(batch, worker)
        identity = source_identity(root)
        for name in (
            "home",
            "temp",
            "packages",
            "http",
            "plugins",
            "feed",
            "source",
            "out",
            "obj",
        ):
            make_private(directory / name)
        # Preserve the project-relative layout, not arbitrary repo inputs or packet data.
        for subdir in ("tools", "tools/reboot-helper", "tools/reboot-helper/selftest"):
            make_private(directory / "source" / subdir)
        for name in SOURCES:
            batch.write(worker, "source/" + name, (root / name).read_bytes())
        env = environment(directory, dotnet)
        head, dirty = git_identity(batch, worker, root, env, scratch, run_command)
        batch.write(
            worker,
            "identity.json",
            json.dumps(
                {
                    "head": head,
                    "git_status": dirty,
                    "sources_sha256": identity,
                    "python": sys.executable,
                    "python_version": sys.version,
                    "dotnet": str(dotnet),
                    "dotnet_sha256": digest(dotnet),
                    "runner_sha256": {
                        name: digest(root / "tools" / name)
                        for name in (
                            "evidence_workspace.py",
                            "workspace_windows.py",
                            "run_storage_pilot.py",
                            "workspace_git.py",
                            "workspace_acl_diagnostics.py",
                            "workspace_creation.py",
                        )
                    },
                },
                indent=2,
            ).encode(),
        )
        version = (
            run_command(
                batch, worker, "sdk-version", [str(dotnet), "--version"], env, scratch
            )
            .decode()
            .strip()
        )
        batch.write(
            worker,
            "global.json",
            json.dumps(
                {
                    "sdk": {
                        "version": version,
                        "rollForward": "disable",
                        "allowPrerelease": False,
                    }
                }
            ).encode(),
        )
        for label, option in (
            ("toolchain", "--list-sdks"),
            ("runtimes", "--list-runtimes"),
        ):
            run_command(batch, worker, label, [str(dotnet), option], env, scratch)
        cached_references(batch, worker, cache)
        batch.write(
            worker,
            "NuGet.Config",
            (
                '<configuration><packageSources><clear/><add key="offline" value='
                + quoteattr(str(directory / "feed"))
                + "/></packageSources><disabledPackageSources><clear/></disabledPackageSources>"
                + "<auditSources><clear/></auditSources></configuration>"
            ).encode(),
        )
        project = str(directory / "source" / PROJECT)
        properties = [
            f"-p:BaseIntermediateOutputPath={directory / 'obj'}/",
            f"-p:MSBuildProjectExtensionsPath={directory / 'obj'}/",
            f"-p:OutputPath={directory / 'out'}/",
            f"-p:NetCoreTargetingPackRoot={cache}",
            "-p:EnableTargetingPackDownload=false",
            "-p:EnableRuntimePackDownload=false",
            "-p:NuGetAudit=false",
            "-p:UseSharedCompilation=false",
            "-p:ImportDirectoryBuildProps=false",
            "-p:ImportDirectoryBuildTargets=false",
            "-p:EnableNETAnalyzers=false",
            "-p:CheckEolTargetFramework=false",
            "-p:TargetLatestRuntimePatch=false",
            "-p:AppendTargetFrameworkToOutputPath=false",
        ]
        run_command(
            batch,
            worker,
            "restore",
            [
                str(dotnet),
                "restore",
                project,
                "--configfile",
                str(directory / "NuGet.Config"),
                "--source",
                str(directory / "feed"),
                "--disable-parallel",
                *properties,
            ],
            env,
            scratch,
        )
        run_command(
            batch,
            worker,
            "build",
            [
                str(dotnet),
                "build",
                project,
                "--no-restore",
                "--disable-build-servers",
                "--configuration",
                "Release",
                "-nodeReuse:false",
                *properties,
            ],
            env,
            scratch,
        )
        assembly = directory / "out/PowerGateSelfTest.dll"
        ordinary(assembly)
        output = run_command(
            batch, worker, "selftest", [str(dotnet), str(assembly)], env, scratch
        )
        result = json.loads(output)
        if (
            result.get("real_native_calls") != 0
            or type(result.get("real_native_calls")) is not int
            or type(result.get("passed")) is not int
            or result["passed"] <= 0
        ):
            raise WorkspaceError(
                "self-test did not report passes and zero real native calls"
            )
        if source_identity(root) != identity:
            raise WorkspaceError("original self-test source bytes changed")
        scratch.check(final=True)
        files = snapshot(directory, privacy=True)
        batch.write(
            worker,
            "result.json",
            json.dumps(
                {
                    "status": "selftest-passed",
                    "head": head,
                    "selftest": result,
                    "checkout_scratch_peak_bytes": scratch.peak,
                    "files": {
                        name: {"bytes": value[2], "sha256": digest(directory / name)}
                        for name, value in files.items()
                    },
                },
                indent=2,
            ).encode(),
        )
        success, reason = (
            True,
            "offline PowerGateSelfTest passed; zero real native calls reported",
        )
    except BaseException as error:
        reason = f"{type(error).__name__}: {error}"
        raise
    finally:
        batch.finish(worker, success=success, reason=reason)
    return worker


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--budget-gib", required=True, type=int)
    args = parser.parse_args(argv)
    batch = None
    try:
        workspace = validate_workspace(args.workspace, ROOT)
        batch = Batch(workspace, args.batch, args.budget_gib * GIB)
        dotnet = shutil.which("dotnet")
        if not dotnet:
            raise WorkspaceError(
                "installed dotnet SDK unavailable; no download attempted"
            )
        worker = execute_pilot(
            batch, ROOT, Path(dotnet).resolve(), Path.home() / ".nuget/packages"
        )
        state = batch.report()
        if state["stop"] or any(
            w["status"] != "complete" for w in state["workers"].values()
        ):
            raise WorkspaceError("batch has incomplete workers; see batch.json")
        print(
            json.dumps(
                {
                    "status": "complete",
                    "worker": str(batch.root / worker),
                    "observed_peak_bytes": state["peak_bytes"],
                    "budget_bytes": state["budget"],
                }
            )
        )
        return 0
    except (
        OSError,
        ValueError,
        WorkspaceError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ) as error:
        if batch:
            try:
                with batch.transaction() as state:
                    state["stop"] = state["stop"] or str(error)[:1000]
            except (OSError, ValueError, WorkspaceError) as metadata_error:
                print(
                    f"batch-control update failed; incomplete: {metadata_error}",
                    file=sys.stderr,
                )
        print(
            json.dumps(
                {
                    "status": "incomplete",
                    "reason": str(error),
                    "batch": str(batch.root) if batch else None,
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
