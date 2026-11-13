"""Unchanged qualified staging/cleanup methods; no power or live entrypoint."""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r23-pycache-')

import asyncio
import re
from pathlib import Path, PurePosixPath
from shlex import quote
from packet import *
from sdk import prepare_upload, shell_argument
TAR = PKG + ".tar.gz"
RUNTIME_ALIAS = "/usr/share/dotnet.tizen/netcoreapp"
RUNTIME_FILES = ("libcoreclr.so", "System.Private.CoreLib.dll")
def clean_materials(directory):
    require(
        directory.resolve(strict=True) == directory
        and directory.parent == HERE / "execution",
        "local cleanup containment",
    )
    files = list(directory.iterdir())
    for p in files:
        require(
            p.name in MATERIALS
            and p.is_file()
            and p.resolve(strict=True) == p
            and p.stat().st_nlink == 1,
            "unexpected local credential directory contents",
        )
    for p in files:
        p.unlink()
    directory.rmdir()


class Trial:
    def __init__(self, sdk, save):
        self.sdk, self.save = sdk, save
        self.owned_sdk = self.disconnected = False
        self.claim_attempted = self.launch_attempted = False
        self.stage_id = self.control_hash = self.manifest_hash = None
        self.server = self.connection = self.process = None
        self.agent_pid = 0
        self.launcher_pid = 0
        self.materials = None
        self.cleanup_pending = []
        self.close_errors = []
        self.baseline_passed = False
        self.protected = None
        self.initial_runtime = None


    async def read(self, label, command):
        self.save("sdk-request", name=label, command=command)
        code, output = await self.sdk.capture(command)
        self.save("sdk", name=label, command=command, exit=code)
        require(code == 0, label + " refused or failed")
        return output


    async def runtime_path(self, label, command):
        self.save("sdk-request", name=label, command=command)
        code, output = await self.sdk.capture(command, preserve_output=True)
        # readlink emits one terminating newline. Keep any other whitespace as evidence.
        value = output.removesuffix("\n")
        self.save("runtime-path", name=label, command=command, exit=code, output=value)
        require(code == 0, label + " refused or failed")
        target = PurePosixPath(value)
        require(
            target.is_absolute()
            and str(target) == value
            and ".." not in target.parts
            and re.fullmatch(r"/[A-Za-z0-9_./+-]+", value)
            and not value.startswith("//"),
            label + " returned a noncanonical path",
        )
        return target


    async def check_runtime(self):
        resolve = "readlink -f " + RUNTIME_ALIAS
        active = await self.runtime_path("runtime", resolve)
        require(
            active.name == "3.1.3"
            and (
                active.is_relative_to("/usr/share/dotnet.tizen")
                or active.parent
                == PurePosixPath("/usr/share/dotnet/shared/Microsoft.NETCore.App")
            ),
            "unexpected TV .NET runtime version or system location",
        )
        require(
            self.initial_runtime in (None, active),
            "runtime location changed since preflight",
        )
        for name in RUNTIME_FILES:
            # Only packet literals enter the command. The TV's returned paths stay data.
            file = RUNTIME_ALIAS + "/" + name
            command = f'f={file}; test -f "$f" && test -r "$f" && readlink -f "$f"'
            resolved = await self.runtime_path("runtime-" + name, command)
            require(
                active in resolved.parents,
                name + " resolves outside the active runtime",
            )
        require(
            await self.runtime_path("runtime-recheck", resolve) == active,
            "runtime changed during file checks",
        )
        self.initial_runtime = active
        self.save(
            "runtime-verified",
            path=str(active),
            version="3.1.3",
            readable_files=list(RUNTIME_FILES),
        )


    async def metadata(self, path):
        self.save("lstat-request", path=path)
        code, value = await self.sdk.capture(
            "LC_ALL=C stat -c '%F:%u:%g:%a:%s:%d:%i' " + quote(path)
        )
        if (
            code == 1
            and value.endswith("No such file or directory")
            and path in value
            and "\n" not in value
        ):
            return None
        require(
            code == 0 and re.fullmatch(r"[a-z ]+:\d+:\d+:[0-7]+:\d+:\d+:\d+", value),
            "unknown metadata: " + path,
        )
        return value


    async def proof(self):
        found = False
        found_evidence_directory = False
        for path in (PROOF, EV, EV + "/selfroot-proof.txt"):
            if path.startswith(EV + "/") and not found_evidence_directory:
                continue
            info = await self.metadata(path)
            if path == EV:
                found_evidence_directory = bool(info and info.startswith("directory:"))
            if info:
                found = found or path != EV
                self.save("preexisting-evidence", path=path, metadata=info)
                if (
                    path != EV
                    and info.split(":")[0] in ("regular file", "regular empty file")
                    and int(info.split(":")[4]) <= 65536
                ):
                    # Recheck the exact lstat receipt in the same SDK command. Keep the archived contents local.
                    cmd = f'p={quote(path)}; test ! -L "$p" && test "$(stat -c \'%d:%i:%s\' "$p")" = '
                    fields = info.split(":")
                    cmd += (
                        quote(":".join([fields[5], fields[6], fields[4]]))
                        + ' && base64 "$p"'
                    )
                    data = await self.read("archive-automatic-proof", cmd)
                    self.save("automatic-proof-base64", path=path, data=data)
        return found


    async def stage(self, assets):
        for name, source in assets.items():
            # Validate every complete upload before creating a TV directory.
            prepare_upload(source, STAGE + "/" + name, "9" * 20 + ":" + "9" * 20)
        require(
            await self.read("sdk-root", "readlink -f " + ROOT) == CANON,
            "SDK root redirected",
        )
        require(
            await self.read("on-demand", "readlink -f " + DEMAND)
            == CANON + "/on-demand"
            and (await self.metadata(DEMAND) or "").startswith("directory:"),
            "on-demand parent missing or redirected",
        )
        for path in (STAGE, DEMAND + "/" + TAR, DEMAND + "/" + TAR + ".signature"):
            require(await self.metadata(path) is None, "staging collision")
        self.control_hash, self.manifest_hash = (
            digest(assets["stage.sh"]),
            digest(assets["files.sha256"]),
        )
        self.claim_attempted = True
        cmd = f"cd -P {ROOT} && test \"$PWD\" = {CANON} && umask 077 && mkdir -m 700 -- {PKG} && stat -c '%d:%i' {PKG}"
        value = await self.read("exclusive-claim", cmd)
        require(
            re.fullmatch(r"[0-9]+:[0-9]+", value),
            "unknown result of exclusive staging claim",
        )
        self.stage_id = value
        self.save("stage-owned", path=STAGE, identity=value)
        for name, source in assets.items():
            target = STAGE + "/" + name
            await self.check_stage()
            require(
                await self.metadata(target) is None,
                "upload destination exists: " + name,
            )
            self.save("upload-request", path=target)
            await self.sdk.push(source, target, stage_id=self.stage_id)
            require(
                (await self.read("upload-hash", "sha256sum " + target))
                == digest(source) + "  " + target,
                "upload verification: " + name,
            )
        await self.control("publish")


    async def check_stage(self):
        actual = await self.metadata(STAGE)
        require(
            actual is not None
            and actual.startswith("directory:901:")
            and actual.split(":")[3] == "700"
            and ":".join(actual.split(":")[-2:]) == self.stage_id,
            "owned staging directory changed",
        )
        require(
            await self.read("canonical-stage", "readlink -f " + STAGE)
            == CANON + "/" + PKG,
            "canonical staging path changed",
        )


    def control_command(self, action):
        require(
            action in ("launch", "publish", "clean")
            and re.fullmatch(r"\d+:\d+", self.stage_id or "")
            and re.fullmatch(r"[a-f0-9]{64}", self.manifest_hash or "")
            and type(self.agent_pid) is int
            and self.agent_pid >= 0,
            "invalid control arguments",
        )
        return f"set -o pipefail;cd -P {STAGE} && cat stage.sh | /bin/bash -s -- {action} {self.stage_id} {self.manifest_hash} {self.agent_pid}"


    async def control(self, action):
        await self.check_stage()
        script = STAGE + "/stage.sh"
        info = await self.metadata(script)
        require(
            info
            and info.startswith("regular file:901:")
            and await self.read("control-links", "stat -c %h " + script) == "1",
            "control script is not the owned file",
        )
        require(
            await self.read("control-hash", "sha256sum " + script)
            == self.control_hash + "  " + script,
            "control script drift",
        )
        cmd = self.control_command(action)
        if action == "launch":
            self.launch_attempted = True
            self.save("launch-requested", command=cmd)
            self.process = await self.sdk.process(shell_argument(cmd))
        else:
            await self.read("stage-" + action, cmd)


    async def cleanup_stage(self):
        if not self.stage_id:
            require(not self.claim_attempted, "staging claim receipt missing")
            return
        await self.current()
        if self.launch_attempted:
            require(
                self.agent_pid > 1,
                "authenticated root identity unknown; retain staging",
            )
            await self.check_stage()
            marker = STAGE + "/started/pid"
            info = await self.metadata(marker)
            require(
                info
                and info.startswith("regular file:901:")
                and await self.read("launcher-receipt-links", "stat -c %h " + marker)
                == "1",
                "unowned launcher receipt",
            )
            record = await self.read("post-close-launcher-identity", "cat " + marker)
            match = re.fullmatch(r"([1-9]\d*) (\d+:\d+)", record)
            require(match and int(match[1]) > 1, "invalid launcher identity")
            self.launcher_pid = int(match[1])
            for _ in range(5):
                if (
                    await self.metadata("/proc/" + str(self.agent_pid)) is None
                    and await self.metadata("/proc/" + str(self.launcher_pid)) is None
                ):
                    break
                await asyncio.sleep(0.5)
            else:
                raise Stop(
                    "trial processes still present or PID reused; retain staging"
                )
            self.save(
                "process-absence-verified",
                agent=self.agent_pid,
                launcher=self.launcher_pid,
            )
        await self.check_stage()
        names = (
            await self.read(
                "cleanup-inventory",
                f"find {STAGE} -mindepth 1 -maxdepth 1 -printf '%f\\n'",
            )
        ).splitlines()
        self.save("staging-inventory", names=names)
        if (
            set(names) <= {"files.sha256", "stage.sh"}
            and len(names) < 2
            and not self.launch_attempted
        ):
            # Bootstrap may have stopped before the sealed cleanup script was available.
            for name in names:
                p = STAGE + "/" + name
                checksum = (
                    self.manifest_hash if name == "files.sha256" else self.control_hash
                )
                info = await self.metadata(p)
                require(
                    info
                    and info.startswith("regular file:901:")
                    and await self.read("bootstrap-links", "stat -c %h " + p) == "1"
                    and await self.read("bootstrap-hash", "sha256sum " + p)
                    == checksum + "  " + p,
                    "bootstrap artifact changed",
                )
            for name in names:
                await self.read("bootstrap-unlink", "unlink " + STAGE + "/" + name)
            await self.read("bootstrap-rmdir", "rmdir -- " + STAGE)
        else:
            await self.control("clean")
        for path in (STAGE, DEMAND + "/" + TAR, DEMAND + "/" + TAR + ".signature"):
            require(await self.metadata(path) is None, "cleanup unverified: " + path)
        self.save("staging-absence-verified")


    async def finish(self):
        async def step(name, func):
            try:
                await func()
                self.save("closeout", name=name, verified=True)
                return True
            except Exception as error:
                self.close_errors.append(name)
                self.save(
                    "closeout", name=name, verified=False, error=type(error).__name__
                )
                return False

        if self.connection is not None:
            await step("authenticated-root-close", lambda: self.connection.shutdown(6))
        if self.server is not None:
            await step("desktop-callback-close", self.server.close)
        if self.process is not None:

            async def wait_local():
                try:
                    await asyncio.wait_for(self.process.wait(), 8)
                except TimeoutError as error:
                    if self.process.returncode is None:
                        self.process.kill()
                        await self.process.wait()
                    raise Stop("desktop launcher wait expired") from error

            await step("desktop-launch-client-exit", wait_local)
        available = self.owned_sdk
        if self.owned_sdk and self.disconnected:
            available = await step("one-target-sdk-reconnect", self.sdk.connect)
        if self.claim_attempted:
            cleaned = available and await step("owned-remote-files", self.cleanup_stage)
            if not cleaned:
                self.cleanup_pending += [
                    STAGE,
                    DEMAND + "/" + TAR,
                    DEMAND + "/" + TAR + ".signature",
                ]
        if available and self.baseline_passed:
            await step("post-session-baseline", self.baseline)
        if self.owned_sdk:
            await step("ordinary-sdk-close", self.sdk.disconnect)
        if self.materials is not None:
            try:
                clean_materials(self.materials)
            except Exception as error:
                self.cleanup_pending.append(str(self.materials))
                self.close_errors.append("local-credentials")
                self.save(
                    "local-credential-cleanup-pending", error=type(error).__name__
                )
