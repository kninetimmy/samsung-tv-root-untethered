"""Short SDK bootstrap; a complete reviewed script is sent after the one-use grant."""

import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r22-pycache-')

import asyncio
import base64
import hashlib
import re
import secrets
import subprocess
import time
from pathlib import Path, PurePosixPath
from shlex import quote

import packet as prior
import bootstrap_sdk as sdk

HERE = Path(__file__).resolve().parent
DEADLINE = 15
MAX_REPLY = 131072
MAX_SCRIPT = 70000
MAX_WIRE = 423
MAX_UPLOAD = 48000
UPLOAD_NAMES = {
    "manager.dll",
    "manager.dll.gz",
    "manager.dll.a",
    "manager.dll.b",
    "SamsungTvRootAgent.dll.gz",
    "SamsungTvRootAgent.dll.a",
    "SamsungTvRootAgent.dll.b",
    "FdetProbe.dll",
    "FdetProbe.dll.gz",
    "FdetProbe.dll.a",
    "FdetProbe.dll.b",
    "FdetProbe.runtimeconfig.json",
    "LinuxRebootHelper.dll",
    "LinuxRebootHelper.runtimeconfig.json",
    "linux-power.conf",
    "files.sha256",
    "stage.sh",
    "SamsungTvArchiveRoot.dll",
    "SamsungTvRootAgent.dll",
    "SamsungTvArchiveRoot.runtimeconfig.json",
    "SamsungTvRootAgent.runtimeconfig.json",
    "public.pem",
    "passwd",
    "root-agent.token",
    "launcher.log",
    # v5.19 install set: the module and the two manager files are staged by the
    # gate session, so the reviewed channel contract must name them (r9 B1).
    "manager.runtimeconfig.json",
    "UepGateHost.dll",
    "UepGateHost.runtimeconfig.json",
    "boot.sh",
    "module.json",
    prior.PKG + ".tar.gz",
    prior.PKG + ".tar.gz.signature",
}


def stage_gzip_command(name, plain_digest, plain_size, stage_id):
    """TV-side decompress of a staged .gz asset into the plain name.

    Mirrors prepare_upload's reviewed staging discipline: containment against
    the owned stage identity, exclusive write, digest + size receipts, and
    the .gz variant removed before any publish check can see it.
    """
    gz = name + ".gz"
    return (
        "set -o pipefail\n"
        + f'cd -P {quote(prior.STAGE)} && test "$PWD" = {quote(prior.CANON + "/" + prior.PKG)}'
        + f' && test "$(stat -c %d:%i:%u:%a .)" = {stage_id}:901:700 || exit 71\n'
        + "umask 077 || exit 72\n"
        + f'report=$( {{ gzip -dc -- {quote(gz)} | /usr/bin/dd of={quote(name)} conv=excl oflag=nofollow status=noxfer; }} 2>&1)\n'
        + 'result=$?\nif test "$result" != 0; then printf "%s\\n" "$report"; exit "$result"; fi\n'
        + f'test ! -L {quote(name)} && test -f {quote(name)}\n'
        + f'test "$(stat -c %s {quote(name)})" = {int(plain_size)}\n'
        + f'test "$(sha256sum {quote(name)})" = \'{plain_digest}  {name}\'\n'
        + f'unlink -- {quote(gz)}\n'
        + f'test ! -e {quote(gz)} && test ! -L {quote(gz)}\n'
        + f'sha256sum {quote(name)}'
    )


def stage_cat_command(name, parts, plain_digest, plain_size, stage_id):
    """Chunked assembly fallback: two staged part files, one assembled write.

    The pre-check rejects an existing or linked plain name (the conv=excl
    semantics), `cat` introduces no extra dd flag requirements, both parts
    stay inside every reviewed bound, and the final digest receipt binds the
    whole assembled file before the parts are unlinked.
    """
    part_names = " ".join(quote(part) for part in parts)
    part_absent = "\n".join(f"test ! -e {quote(part)}" for part in parts)
    part_unlink = "\n".join(
        f"unlink -- {quote(part)}\n"
        + f"test ! -e {quote(part)} && test ! -L {quote(part)}"
        for part in parts
    )
    return (
        "set -o pipefail\n"
        + f'cd -P {quote(prior.STAGE)} && test "$PWD" = {quote(prior.CANON + "/" + prior.PKG)}'
        + f' && test "$(stat -c %d:%i:%u:%a .)" = {stage_id}:901:700 || exit 71\n'
        + "umask 077 || exit 72\n"
        + f'test ! -L {quote(name)} || exit 73\n'
        + part_absent + "\n"
        + f'report=$( {{ cat -- {part_names} | /usr/bin/dd of={quote(name)} conv=excl oflag=nofollow status=noxfer; }} 2>&1)\n'
        + 'result=$?\nif test "$result" != 0; then printf "%s\\n" "$report"; exit "$result"; fi\n'
        + f'test ! -L {quote(name)} && test -f {quote(name)}\n'
        + f'test "$(stat -c %s {quote(name)})" = {int(plain_size)}\n'
        + f'test "$(sha256sum {quote(name)})" = \'{plain_digest}  {name}\'\n'
        + part_unlink + "\n"
        + f'sha256sum {quote(name)}'
    )


def prepare_upload(source, target, stage_id):
    source, remote = Path(source), PurePosixPath(target)
    prior.require(
        str(remote) == target
        and str(remote.parent) == prior.STAGE
        and remote.name in UPLOAD_NAMES
        and re.fullmatch(r"[0-9]{1,20}:[1-9][0-9]{0,19}", stage_id),
        "Upload target or creation receipt is outside this packet",
    )
    prior.require(
        source.resolve(strict=True) == source.absolute()
        and source.is_file()
        and source.stat().st_nlink == 1
        and source.stat().st_size <= MAX_UPLOAD,
        "Upload source missing, redirected, linked or oversized",
    )
    with source.open("rb") as stream:
        data = stream.read(MAX_UPLOAD + 1)
    prior.require(len(data) <= MAX_UPLOAD, "Upload source grew beyond limit")
    encoded = base64.b64encode(data).decode("ascii")
    command = (
        "set -o pipefail\n"
        + f'cd -P {quote(prior.STAGE)} && test "$PWD" = {quote(prior.CANON + "/" + prior.PKG)}'
        + f' && test "$(stat -c %d:%i:%u:%a .)" = {stage_id}:901:700 || exit 71\n'
        + "umask 077 || exit 72\n"
        + f"report=$( {{ printf %s {quote(encoded)} | base64 -d | /usr/bin/dd of={quote(remote.name)} conv=excl oflag=nofollow status=noxfer; }} 2>&1)\n"
        + 'result=$?\nif test "$result" != 0; then printf "%s\\n" "$report"; exit "$result"; fi\n'
        + f"test ! -L {quote(remote.name)} && test -f {quote(remote.name)} && sha256sum {quote(remote.name)}"
    )
    script_payload(command, "0" * 16)
    return command, hashlib.sha256(data).hexdigest() + "  " + remote.name


def make_wire(label, command, port, nonce):
    if not re.fullmatch(r"[0-9a-f]{16}", nonce) or not 1 <= port <= 65535:
        raise ValueError("Invalid callback framing")
    script_payload(command, nonce)
    arg = sdk.shell_argument(
        f"exec 3<>/dev/tcp/{sdk.PC}/{port}||exit;n={payload_tag(command, nonce)};echo $n >&3;"
        'read -rt5 c<&3&&h=$(printf %s "$c"|sha256sum)&&[ "${h%% *}" = "$n" ]&&'
        'printf %s "$c"|base64 -d|bash >&3 2>&3'
    )
    if len(arg) > MAX_WIRE:
        raise ValueError("Bootstrap exceeds the demonstrated short-control size")
    return arg


def script_payload(command, nonce):
    if not isinstance(command, str) or not command or "\x00" in command:
        raise ValueError("Invalid reviewed command")
    script = (
        "(\n"
        + command
        + "\n) </dev/null\nr=$?\n"
        + "printf '\\n[exit:"
        + nonce
        + ':%d]\\n\' "$r"\nexit\n'
    ).encode("ascii", "strict")
    if len(script) > MAX_SCRIPT:
        raise ValueError("Reviewed script exceeds limit")
    return base64.b64encode(script) + b"\n"


def payload_tag(command, nonce):
    return hashlib.sha256(
        script_payload(command, nonce).removesuffix(b"\n")
    ).hexdigest()


class TracedSDK(sdk.DirectSDK):
    def __init__(self, log):
        super().__init__()
        self.log = log

    async def spawn(self, arg):
        return await asyncio.create_subprocess_exec(
            str(prior.SDB),
            "-s",
            self.client.serial,
            "shell",
            arg,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    async def request(
        self, label, command, *, preserve_output=False, record_command=True, partial_evidence=False
    ):
        prior.require(not partial_evidence or label == 'denial-evidence', 'unreviewed partial-evidence request')
        state = dict(prefix=bytearray(), observed=0, accepted=False, trailer=False,
                     request_id=secrets.token_hex(8))
        try:
            return await self._request(label, command, preserve_output=preserve_output,
                                       record_command=record_command, evidence=state if partial_evidence else None)
        except BaseException as error:
            # _request has completed teardown before this boundary. A trailer alone is not success.
            if partial_evidence and state['accepted']:
                prefix = bytes(state['prefix'])
                try:
                    self.log('sdk-reply-incomplete', request='denial-evidence', request_id=state['request_id'],
                        transport_complete=False, capture_complete=False, usable_as_kernel_authority=False,
                        reason='reply-limit' if state['observed'] > MAX_REPLY else type(error).__name__ + ': ' + str(error),
                        prefix_limit_bytes=MAX_REPLY, retained_bytes=len(prefix),
                        observed_bytes_at_least=state['observed'], truncated=state['observed'] > len(prefix),
                        raw_prefix_encoding='base64', raw_prefix_b64=base64.b64encode(prefix).decode('ascii'),
                        prefix_sha256=hashlib.sha256(prefix).hexdigest(), exit_trailer_seen=state['trailer'])
                except BaseException as storage_error:
                    raise BaseExceptionGroup('denial transport failure: ' + type(error).__name__ + ': ' + str(error)
                                             + '; receipt persistence failure: ' + str(storage_error),
                                             [error, storage_error]) from None
            raise

    async def _request(
        self, label, command, *, preserve_output=False, record_command=True, evidence=None
    ):
        started = time.monotonic()
        nonce = secrets.token_hex(8)
        done = asyncio.get_running_loop().create_future()
        handlers, writers, jobs = set(), set(), []
        closing = False
        accepted = False
        result = None
        proc = server = None
        phases = {}
        counts = {"stdout": 0, "stderr": 0}
        prefixes = {"stdout": bytearray(), "stderr": bytearray()}

        def mark(event, **data):
            ms = round((time.monotonic() - started) * 1000, 1)
            phases[event] = ms
            self.log(event, request=label, ms=ms, **data)

        async def receive(reader, writer):
            nonlocal accepted, result
            try:
                peer = writer.get_extra_info("peername")
                if not peer or peer[0] != sdk.TV:
                    if "wrong-peer" not in phases:
                        mark("wrong-peer")
                    return
                mark("callback-arrived")
                if (
                    await reader.readline()
                    != (payload_tag(command, nonce) + "\n").encode()
                ):
                    mark("tag-rejected")
                    return
                if accepted:
                    mark("duplicate-denied")
                    return
                accepted = True
                if evidence is not None:
                    evidence['accepted'] = True
                mark("tag-verified")
                # Latch before sending. A lost grant never permits another connection to execute.
                mark("command-release-recorded")
                payload = script_payload(command, nonce)
                writer.write(payload)
                await writer.drain()
                mark("command-release-sent", script_wire_bytes=len(payload))
                data = bytearray()
                while chunk := await reader.read(4096):
                    if evidence is not None:
                        evidence['observed'] += len(chunk)
                        evidence['prefix'].extend(chunk[:max(0, MAX_REPLY - len(evidence['prefix']))])
                    if result is not None:
                        raise ValueError("data after exit trailer")
                    if not data:
                        mark("first-tv-bytes")
                    if len(data) + len(chunk) > MAX_REPLY:
                        raise ValueError("kernel-capture-transport-bound" if evidence is not None else "TV reply exceeds limit")
                    data.extend(chunk)
                    trailer = re.search(
                        rb"\n\[exit:" + nonce.encode("ascii") + rb":(\d{1,3})\]\n\Z",
                        data,
                    )
                    if trailer:
                        if evidence is not None:
                            evidence['trailer'] = True
                        code = int(trailer[1])
                        if code > 255:
                            raise ValueError("invalid shell exit")
                        output = data[: trailer.start()].decode("utf-8", "strict")
                        result = code, output
                        mark(
                            "tv-exit-trailer",
                            exit_code=code,
                            output=output.replace(nonce, "[tag]").replace(
                                payload_tag(command, nonce), "[payload-tag]"
                            ),
                        )
                mark("callback-eof")
                if result is None:
                    raise ValueError("EOF without an exit trailer")
                if not done.done():
                    done.set_result(result)
            except (ValueError, OSError) as error:
                mark("callback-error", reason=type(error).__name__ + ": " + str(error))
                if not done.done():
                    done.set_exception(error)
            finally:
                writer.close()
                writers.discard(writer)

        def accept(reader, writer):
            if closing or len(handlers) >= 4:
                writer.close()
                return
            writers.add(writer)
            task = asyncio.create_task(receive(reader, writer))
            handlers.add(task)
            task.add_done_callback(handlers.discard)

        async def drain(name, stream):
            while chunk := await stream.read(4096):
                counts[name] += len(chunk)
                prefixes[name].extend(chunk[: max(0, 2048 - len(prefixes[name]))])

        async def watch_exit():
            status = await proc.wait()
            mark("desktop-sdb-exit", returncode=status)
            return status

        self.log(
            "request",
            request=label,
            command=command if record_command else "[file bytes omitted]",
            deadline_seconds=DEADLINE,
        )
        stop_unverified = False
        try:
            async with asyncio.timeout(DEADLINE):
                server = await asyncio.start_server(accept, sdk.PC, 0, limit=256)
                port = server.sockets[0].getsockname()[1]
                argument = make_wire(label, command, port, nonce)
                mark(
                    "listening",
                    port=port,
                    wire_bytes=len(argument),
                    wire_sha256=hashlib.sha256(argument.encode("ascii")).hexdigest(),
                )
                proc = await self.spawn(argument)
                mark("desktop-sdb-started", pid=proc.pid)
                jobs.extend(
                    asyncio.create_task(drain(k, getattr(proc, k))) for k in counts
                )
                exited = asyncio.create_task(watch_exit())
                jobs.append(exited)
                reply, status = await asyncio.gather(done, exited)
                if status not in (0, 1) or "callback-error" in phases:
                    raise RuntimeError("invalid desktop exit or ambiguous callback")
                mark("request-complete")
                code, output = reply
                return code, output if preserve_output else output.strip()
        except TimeoutError:
            mark(
                "request-timeout",
                observed=list(phases),
                os_returncode=proc.returncode if proc else None,
            )
            raise
        finally:
            closing = True
            if server is not None:
                server.close()
            for handler in list(handlers):
                handler.cancel()
            # wait_closed() can wait for active peers. Close our ends before waiting.
            for writer in list(writers):
                writer.close()
            if handlers:
                await asyncio.gather(*list(handlers), return_exceptions=True)
            if server is not None:
                try:
                    await asyncio.wait_for(server.wait_closed(), 2)
                except TimeoutError:
                    mark("desktop-listener-close-unverified")
                    stop_unverified = True
            if proc is not None and proc.returncode is None:
                mark("desktop-client-stop-requested")
                try:
                    proc.kill()  # Only the one local SDB CLI child.
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), 2)
                except TimeoutError:
                    mark("desktop-client-stop-unverified")
                    stop_unverified = True
            if jobs:
                _, pending = await asyncio.wait(jobs, timeout=0.5)
                for job in pending:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
            # Ordinary logs never retain echoed wire arguments, tags or environment values.
            # The opt-in private denial receipt alone retains byte-exact response framing,
            # including its single-use nonce; never desktop/bootstrap or rejected-peer bytes.
            hints = {
                k: [
                    hint
                    for hint in (
                        "permission denied",
                        "offline",
                        "not found",
                        "failed",
                        "error",
                        "closed",
                    )
                    if hint.encode() in prefixes[k].lower()
                ]
                for k in counts
            }
            self.log(
                "transport-close",
                request=label,
                output_bytes=counts,
                diagnostic_categories=hints,
                final_local_code=proc.returncode if proc else None,
            )
            if done.done() and not done.cancelled():
                done.exception()
            if stop_unverified:
                raise RuntimeError("Desktop transport closure not verified")


shell_argument = sdk.shell_argument


def wire(command, port, nonce):
    return make_wire("qualification", command, port, nonce)


class DirectSDK(TracedSDK):
    async def push(self, source, target, *, stage_id):
        command, expected = prepare_upload(source, target, stage_id)
        self.log(
            "stream-upload",
            name=PurePosixPath(target).name,
            bytes=Path(source).stat().st_size,
        )
        code, output = await self.request(
            "context-file-upload", command, record_command=False
        )
        prior.require(code == 0, "Stream upload failed with shell exit " + str(code))
        prior.require(output == expected, "Stream upload hash/receipt mismatch")

    async def capture(self, command, *, preserve_output=False, evidence_label=None):
        prior.require(evidence_label in (None, 'denial-evidence'), 'unreviewed evidence label')
        return await self.request(
            evidence_label or "context-sdk", command, preserve_output=preserve_output,
            partial_evidence=evidence_label is not None
        )

    async def process(self, argument):
        prior.require(
            len(argument.encode("ascii")) <= MAX_WIRE,
            "Root launch exceeds short-wire limit",
        )
        self.log(
            "raw-launch-wire",
            wire_bytes=len(argument),
            wire_sha256=hashlib.sha256(argument.encode("ascii")).hexdigest(),
        )
        return await super().process(argument)
