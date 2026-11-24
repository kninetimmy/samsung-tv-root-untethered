"""Private workspace validation and a shared, retained batch byte ledger."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import threading
import uuid

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import workspace_windows as windows

GIB = 1024**3
CONTROL_BYTES = 65536
_THREAD_LOCK = threading.RLock()


class WorkspaceError(RuntimeError):
    pass


def ordinary(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise WorkspaceError(f"redirected path: {path}")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise WorkspaceError(f"not an ordinary file/directory: {path}")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise WorkspaceError(f"hardlinked file: {path}")
    if os.name == "nt":
        windows.no_named_streams(path)
    return info


def private(path: Path):
    if os.name == "nt":
        windows.private_acl(path)
    else:
        info = ordinary(path)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkspaceError(f"non-private workspace: {path}")


def make_private(path: Path):
    if os.name == "nt":
        windows.make_private(path)
    else:
        path.mkdir(mode=0o700)
    private(path)


def create_private_file(path: Path):
    """Create one exclusive read/write file in an inspected private parent."""
    ordinary(path.parent)
    private(path.parent)
    if os.name == "nt":
        from tools.workspace_creation import create_file

        fd = create_file(path)
    else:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        ordinary(path)
        private(path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def validate_workspace(raw: str, checkout: Path) -> Path:
    if not raw or os.name != "nt":
        raise WorkspaceError(
            "an explicit physical private E: workspace on Windows is required"
        )
    path = Path(raw)
    if ".." in path.parts:
        raise WorkspaceError("parent traversal is not allowed")
    windows.physical_path(path)
    if path.is_relative_to(checkout.resolve()):
        raise WorkspaceError("workspace is inside the checkout")
    private(path)
    return path


def snapshot(
    root: Path, *, privacy=False, directories=False
) -> dict[str, tuple[int, int, int, int]]:
    """No skipped paths/errors, link following, or implicit recursive globbing."""
    result = {}

    def visit(path):
        info = ordinary(path)
        if privacy:
            private(path)
        if stat.S_ISDIR(info.st_mode):
            if directories:
                result[path.relative_to(root).as_posix() + "/"] = (
                    info.st_dev,
                    info.st_ino,
                    0,
                    info.st_mtime_ns,
                )
            with os.scandir(path) as entries:
                for entry in entries:
                    visit(Path(entry.path))
        else:
            result[path.relative_to(root).as_posix()] = (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            )

    visit(root)
    return result


class CheckoutScratch:
    def __init__(self, root: Path):
        self.root = root
        self.before = snapshot(root, directories=True)
        self.peak = 0

    def check(self, *, final=False):
        now = snapshot(self.root, directories=True)
        generated = sum(
            max(0, value[2] - self.before.get(name, (0, 0, 0, 0))[2])
            if value[:2] == self.before.get(name, (0, 0, 0, 0))[:2]
            else value[2]
            for name, value in now.items()
        )
        self.peak = max(self.peak, generated)
        if generated > 5 * GIB:
            raise WorkspaceError(f"checkout scratch exceeds 5 GiB: {generated} bytes")
        if final and now != self.before:
            raise WorkspaceError("checkout changed during pilot; no complete result")
        return generated


@contextmanager
def locked(file):
    with _THREAD_LOCK:
        file.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            file.seek(0)
            if os.name == "nt":
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file, fcntl.LOCK_UN)


class Batch:
    """All cooperating processes share one fixed-size, OS-locked ledger."""

    def __init__(self, workspace: Path, name: str, budget: int):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
            raise WorkspaceError("batch must be 1-64 lowercase letters/digits/hyphens")
        if budget < CONTROL_BYTES:
            raise WorkspaceError("budget cannot reserve batch-control capacity")
        private(workspace)
        self.root = workspace / name
        try:
            make_private(self.root)
        except FileExistsError:
            ordinary(self.root)
            private(self.root)
        self.budget = budget
        self.control = self.root / "batch.json"
        try:
            fd = create_private_file(self.control)
        except FileExistsError:
            ordinary(self.control)
            private(self.control)
            fd = os.open(self.control, os.O_RDWR)
        with os.fdopen(fd, "r+b", buffering=0) as file, locked(file):
            ordinary(self.control)
            private(self.control)
            file.seek(0)
            content = file.read(CONTROL_BYTES + 1)
            if not content:
                if list(self.root.iterdir()) != [self.control]:
                    raise WorkspaceError("uninitialized batch contains unknown output")
                # Physical preallocation: no truncate-only/sparse metadata reserve.
                file.seek(0)
                if file.write(b" " * CONTROL_BYTES) != CONTROL_BYTES:
                    raise WorkspaceError(
                        "batch-control preallocation failed; incomplete"
                    )
                os.fsync(file.fileno())
                self._save(
                    file,
                    {
                        "version": 1,
                        "budget": budget,
                        "stop": None,
                        "peak_bytes": CONTROL_BYTES,
                        "workers": {},
                    },
                )
        with self.transaction() as state:
            if state["budget"] != budget:
                raise WorkspaceError(
                    "batch budget differs from the existing aggregate budget"
                )

    @staticmethod
    def _save(file, state):
        data = json.dumps(state, sort_keys=True).encode()
        if len(data) > CONTROL_BYTES:
            raise WorkspaceError("batch-control capacity exhausted; incomplete")
        file.seek(0)
        if file.write(data.ljust(CONTROL_BYTES, b" ")) != CONTROL_BYTES:
            raise WorkspaceError("short batch-control write; incomplete")
        os.fsync(file.fileno())

    @staticmethod
    def _validate(state):
        try:
            valid = (
                isinstance(state, dict)
                and set(state) == {"version", "budget", "stop", "peak_bytes", "workers"}
                and type(state["version"]) is int
                and state["version"] == 1
                and type(state["budget"]) is int
                and state["budget"] >= CONTROL_BYTES
                and type(state["peak_bytes"]) is int
                and state["peak_bytes"] >= CONTROL_BYTES
                and (state["stop"] is None or isinstance(state["stop"], str))
                and isinstance(state["workers"], dict)
                and len(state["workers"]) <= 64
            )
            if not valid:
                raise ValueError("invalid batch fields")
            for name, slot in state["workers"].items():
                valid = (
                    re.fullmatch(r"[0-9a-f]{32}", name)
                    and set(slot)
                    == {
                        "reservation",
                        "used",
                        "status",
                        "reason",
                        "evidence_limit",
                        "evidence_bytes",
                    }
                    and all(
                        type(slot[key]) is int and slot[key] >= 0
                        for key in (
                            "reservation",
                            "used",
                            "evidence_limit",
                            "evidence_bytes",
                        )
                    )
                    and slot["reservation"] > 0
                    and slot["evidence_bytes"]
                    <= slot["evidence_limit"]
                    <= slot["reservation"]
                    and slot["status"] in {"complete", "incomplete"}
                    and isinstance(slot["reason"], str)
                )
                if not valid:
                    raise ValueError("invalid worker fields")
        except (ValueError, TypeError, KeyError) as error:
            raise WorkspaceError("invalid batch-control schema; incomplete") from error

    @contextmanager
    def transaction(self):
        ordinary(self.control)
        private(self.control)
        with self.control.open("r+b", buffering=0) as file, locked(file):
            data = file.read(CONTROL_BYTES + 1)
            if len(data) != CONTROL_BYTES:
                raise WorkspaceError("invalid batch-control size; incomplete")
            state = json.loads(data)
            self._validate(state)
            try:
                yield state
            except BaseException as error:
                state["stop"] = (
                    state["stop"] or f"{type(error).__name__}: {error}"[:1000]
                )
                raise
            finally:
                self._save(file, state)

    def _refresh(self, state):
        try:
            for ancestor in self.root.parents:
                ordinary(ancestor)
            files = snapshot(self.root, privacy=True)
            used = sum(value[2] for value in files.values())
            state["peak_bytes"] = max(state["peak_bytes"], used)
            if any(
                p != "batch.json" and p.split("/")[0] not in state["workers"]
                for p in files
            ):
                raise WorkspaceError("unknown output outside registered workers")
            for name, worker in state["workers"].items():
                worker["used"] = sum(
                    v[2] for p, v in files.items() if p.startswith(name + "/")
                )
                if worker["used"] > worker["reservation"]:
                    state["stop"] = f"worker output overrun: {name}"
            if used > state["budget"]:
                state["stop"] = f"aggregate output overrun: {used} bytes"
            return used
        except (OSError, ValueError, WorkspaceError) as error:
            state["stop"] = f"accounting inspection failed: {error}"[:1000]
            raise

    def admit(self, reservation: int) -> str:
        with self.transaction() as state:
            used = self._refresh(state)
            committed = used + sum(
                max(0, worker["reservation"] - worker["used"])
                for worker in state["workers"].values()
                if worker["status"] == "incomplete"
            )
            if state["stop"]:
                raise WorkspaceError(state["stop"])
            if (
                reservation <= 0
                or committed + reservation > state["budget"]
                or shutil.disk_usage(self.root).free < committed + reservation
            ):
                state["stop"] = "worker admission refused: aggregate capacity exhausted"
                raise WorkspaceError(state["stop"])
            if len(state["workers"]) >= 64:
                state["stop"] = (
                    "worker admission refused: 64 retained worker slots exhausted"
                )
                raise WorkspaceError(state["stop"])
            name = uuid.uuid4().hex
            state["workers"][name] = {
                "reservation": reservation,
                "used": 0,
                "status": "incomplete",
                "evidence_limit": min(reservation // 4, 32 * 1024**2),
                "evidence_bytes": 0,
                "reason": "worker active or interrupted; no success recorded",
            }
            make_private(self.root / name)
            return name

    def check(self):
        with self.launch():
            pass

    @contextmanager
    def launch(self):
        """Serialize a final stop check and process creation with every stop writer."""
        with self.transaction() as state:
            self._refresh(state)
            if state["stop"]:
                raise WorkspaceError(state["stop"])
            yield

    def write(self, worker: str, relative: str, data: bytes, *, append=False):
        target = self.root / worker / relative
        if (
            not target.is_relative_to(self.root / worker)
            or Path(relative).drive
            or ".." in Path(relative).parts
            or ":" in relative
        ):
            raise WorkspaceError("evidence path escaped worker")
        with self.transaction() as state:
            used = self._refresh(state)
            slot = state["workers"][worker]
            if state["stop"]:
                raise WorkspaceError(state["stop"])
            if slot["status"] != "incomplete":
                raise WorkspaceError("cannot write evidence after worker completion")
            if (
                slot["evidence_bytes"] + len(data) > slot["evidence_limit"]
                or slot["used"] + len(data) > slot["reservation"]
                or used + len(data) > state["budget"]
            ):
                state["stop"] = "controlled evidence reservation exhausted"
                raise WorkspaceError(state["stop"])
            # Worker-owned files only; never overwrite retained evidence.
            existing = append and target.exists()
            if existing:
                ordinary(target)
                private(target)
            slot["evidence_bytes"] += len(data)
            fd = (
                os.open(target, os.O_WRONLY | os.O_APPEND)
                if existing
                else create_private_file(target)
            )
            with os.fdopen(fd, "ab" if append else "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            self._refresh(state)
            if state["stop"]:
                raise WorkspaceError(state["stop"])

    def finish(self, worker: str, *, success: bool, reason: str):
        with self.transaction() as state:
            try:
                self._refresh(state)
            finally:
                slot = state["workers"][worker]
                slot["status"] = (
                    "complete" if success and not state["stop"] else "incomplete"
                )
                slot["reason"] = reason[:256]
                if slot["status"] != "complete":
                    state["stop"] = state["stop"] or reason[:1000]

    def report(self):
        with self.transaction() as state:
            self._refresh(state)
            return json.loads(json.dumps(state))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--create",
        required=True,
        help="explicitly provision ONE new private E: directory",
    )
    args = parser.parse_args()
    try:
        path = Path(args.create)
        if os.name != "nt" or path.exists() or ".." in path.parts:
            raise WorkspaceError("creation requires a new physical E: directory")
        windows.physical_path(path.parent)
        if path.is_relative_to(Path(__file__).resolve().parents[1]):
            raise WorkspaceError("workspace is inside the checkout")
        # Validate the leaf too before creating it, without rewriting existing ACLs.
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", path.name):
            raise WorkspaceError("unsafe new workspace directory name")
        make_private(path)
        validate_workspace(str(path), Path(__file__).resolve().parents[1])
        print(f"created private workspace: {path}")
        return 0
    except (OSError, ValueError, WorkspaceError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
