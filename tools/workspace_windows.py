"""Windows platform checks; no packet imports or host-policy changes."""

from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from pathlib import Path, PureWindowsPath
import re
import os
import subprocess


def libraries():
    kernel = c.WinDLL("kernel32", use_last_error=True)
    security = c.WinDLL("advapi32", use_last_error=True)
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.LocalFree.restype = c.c_void_p
    return kernel, security


def checked(ok):
    if not ok:
        raise c.WinError(c.get_last_error())


def owner_sid():
    kernel, security = libraries()
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    token = w.HANDLE()
    checked(security.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)))
    try:
        length = w.DWORD()
        security.GetTokenInformation.argtypes = [
            w.HANDLE,
            w.DWORD,
            c.c_void_p,
            w.DWORD,
            c.POINTER(w.DWORD),
        ]
        security.GetTokenInformation(token, 1, None, 0, c.byref(length))
        buffer = c.create_string_buffer(length.value)
        checked(security.GetTokenInformation(token, 1, buffer, length, c.byref(length)))
        return sid_text(c.c_void_p.from_buffer(buffer))
    finally:
        kernel.CloseHandle(token)


def sid_text(sid):
    kernel, security = libraries()
    text = w.LPWSTR()
    security.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    checked(security.ConvertSidToStringSidW(sid, c.byref(text)))
    try:
        return text.value
    finally:
        kernel.LocalFree(text)


def physical_path(path: Path):
    """Check all ancestors, including DOS-device and volume redirection."""
    raw = str(path)
    parts = PureWindowsPath(raw)
    if parts.drive.upper() != "E:" or not parts.is_absolute():
        raise ValueError("workspace must be an explicit absolute physical E: path")
    for part in parts.parts[1:]:
        base = part.split(".")[0].upper()
        if (
            part in {".", ".."}
            or part.endswith((".", " "))
            or any(ch in part for ch in ':*?<>|"')
            or base in {"CON", "PRN", "AUX", "NUL"}
            or base in {f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(10)}
        ):
            raise ValueError("unsafe workspace path component")
    kernel, _ = libraries()
    kernel.GetDriveTypeW.argtypes = [w.LPCWSTR]
    if kernel.GetDriveTypeW("E:\\") != 3:
        raise ValueError("E: is not an available fixed drive")
    target = c.create_unicode_buffer(32768)
    kernel.QueryDosDeviceW.argtypes = [w.LPCWSTR, w.LPWSTR, w.DWORD]
    checked(kernel.QueryDosDeviceW("E:", target, len(target)))
    if not re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", target.value):
        raise ValueError("E: is redirected rather than a physical volume")
    for ancestor in [*reversed(path.parents), path]:
        info = ancestor.lstat()
        if info.st_file_attributes & 0x400:
            raise ValueError(f"redirected path: {ancestor}")
        if not ancestor.is_dir():
            raise ValueError(f"not a directory: {ancestor}")
    if str(path.resolve(strict=True)).casefold() != raw.casefold():
        raise ValueError("workspace resolves to a different physical path")


def no_named_streams(path: Path):
    """A hidden NTFS data stream would make byte accounting incomplete."""
    kernel, _ = libraries()

    class Stream(c.Structure):
        _fields_ = [("size", c.c_int64), ("name", w.WCHAR * 296)]

    kernel.FindFirstStreamW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(Stream), w.DWORD]
    kernel.FindFirstStreamW.restype = w.HANDLE
    kernel.FindNextStreamW.argtypes = [w.HANDLE, c.POINTER(Stream)]
    kernel.FindClose.argtypes = [w.HANDLE]
    stream = Stream()
    handle = kernel.FindFirstStreamW(str(path), 0, c.byref(stream), 0)
    if handle == c.c_void_p(-1).value:
        if c.get_last_error() == 38:  # ERROR_HANDLE_EOF: no streams on a directory
            return
        raise c.WinError(c.get_last_error())
    try:
        while True:
            if stream.name != "::$DATA":
                raise ValueError(f"named data stream prevents accounting: {path}")
            if not kernel.FindNextStreamW(handle, c.byref(stream)):
                if c.get_last_error() != 38:
                    raise c.WinError(c.get_last_error())
                break
    finally:
        kernel.FindClose(handle)


def private_acl(path: Path):
    kernel, security = libraries()
    security.GetNamedSecurityInfoW.argtypes = [
        w.LPWSTR,
        w.DWORD,
        w.DWORD,
        c.POINTER(c.c_void_p),
        c.c_void_p,
        c.POINTER(c.c_void_p),
        c.c_void_p,
        c.POINTER(c.c_void_p),
    ]
    owner, acl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
    result = security.GetNamedSecurityInfoW(
        str(path), 1, 5, c.byref(owner), None, c.byref(acl), None, c.byref(descriptor)
    )
    if result:
        raise c.WinError(result)
    try:
        current = owner_sid()
        actual = sid_text(owner) if owner else None

        def reject(reason):
            from tools.workspace_acl_diagnostics import private_acl_error

            return private_acl_error(path, reason, current, actual, acl)

        if actual != current:
            raise reject("workspace owner is not private (owner mismatch)")
        if not acl:
            raise reject("workspace DACL is null (not private)")
        # ACL header: revision, reserved, size, ACE count, reserved.
        count = c.c_ushort.from_address(acl.value + 4).value
        security.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        allowed = set()
        for index in range(count):
            ace = c.c_void_p()
            checked(security.GetAce(acl, index, c.byref(ace)))
            kind = c.c_ubyte.from_address(ace.value).value
            flags = c.c_ubyte.from_address(ace.value + 1).value
            mask = c.c_uint32.from_address(ace.value + 4).value
            principal = sid_text(c.c_void_p(ace.value + 8)) if kind == 0 else None
            if (
                principal not in {current, "S-1-5-18"}
                or flags & 8  # Inherit-only grants do not protect this object.
                or mask != 0x1F01FF
            ):
                raise reject("non-private workspace ACL")
            allowed.add(principal)
        if allowed != {current, "S-1-5-18"}:
            raise reject("missing owner/SYSTEM access")
    finally:
        kernel.LocalFree(descriptor)


def make_private(path: Path):
    """Create exactly one new directory with its private ACL at creation."""
    from tools.workspace_creation import private_attributes

    kernel, _ = libraries()
    kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, c.c_void_p]
    with private_attributes() as attributes:
        checked(kernel.CreateDirectoryW(str(path), c.byref(attributes)))
    private_acl(path)


class ProcessJob:
    """Atomically contain children at creation; kill them when the owner exits."""

    def __init__(self):
        kernel, _ = libraries()
        self.kernel = kernel
        kernel.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        kernel.CreateJobObjectW.restype = w.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            w.HANDLE,
            w.DWORD,
            c.c_void_p,
            w.DWORD,
        ]
        kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = kernel.CreateJobObjectW(None, None)
        checked(self.handle)

        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION; documented ABI layout.
        class Basic(c.Structure):
            _fields_ = [
                ("process_time", c.c_int64),
                ("job_time", c.c_int64),
                ("flags", w.DWORD),
                ("min_ws", c.c_size_t),
                ("max_ws", c.c_size_t),
                ("active", w.DWORD),
                ("affinity", c.c_size_t),
                ("priority", w.DWORD),
                ("scheduling", w.DWORD),
            ]

        class Extended(c.Structure):
            _fields_ = [
                ("basic", Basic),
                ("io", c.c_uint64 * 6),
                ("process_memory", c.c_size_t),
                ("job_memory", c.c_size_t),
                ("peak_process", c.c_size_t),
                ("peak_job", c.c_size_t),
            ]

        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            checked(
                kernel.SetInformationJobObject(
                    self.handle, 9, c.byref(limits), c.sizeof(limits)
                )
            )
        except BaseException:
            self.close()
            raise

    def spawn(self, command, *, cwd, env):
        """CreateProcessW + PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+)."""
        import msvcrt

        kernel = self.kernel

        class Startup(c.Structure):
            _fields_ = [
                ("cb", w.DWORD),
                ("reserved", w.LPWSTR),
                ("desktop", w.LPWSTR),
                ("title", w.LPWSTR),
                ("x", w.DWORD),
                ("y", w.DWORD),
                ("xsize", w.DWORD),
                ("ysize", w.DWORD),
                ("xchars", w.DWORD),
                ("ychars", w.DWORD),
                ("fill", w.DWORD),
                ("flags", w.DWORD),
                ("show", w.WORD),
                ("reserved_size", w.WORD),
                ("reserved_data", c.c_void_p),
                ("stdin", w.HANDLE),
                ("stdout", w.HANDLE),
                ("stderr", w.HANDLE),
            ]

        class ExtendedStartup(c.Structure):
            _fields_ = [("startup", Startup), ("attributes", c.c_void_p)]

        class ProcessInfo(c.Structure):
            _fields_ = [
                ("process", w.HANDLE),
                ("thread", w.HANDLE),
                ("pid", w.DWORD),
                ("tid", w.DWORD),
            ]

        kernel.InitializeProcThreadAttributeList.argtypes = [
            c.c_void_p,
            w.DWORD,
            w.DWORD,
            c.POINTER(c.c_size_t),
        ]
        kernel.UpdateProcThreadAttribute.argtypes = [
            c.c_void_p,
            w.DWORD,
            c.c_size_t,
            c.c_void_p,
            c.c_size_t,
            c.c_void_p,
            c.c_void_p,
        ]
        kernel.DeleteProcThreadAttributeList.argtypes = [c.c_void_p]
        kernel.CreateProcessW.argtypes = [
            w.LPCWSTR,
            w.LPWSTR,
            c.c_void_p,
            c.c_void_p,
            w.BOOL,
            w.DWORD,
            c.c_void_p,
            w.LPCWSTR,
            c.POINTER(ExtendedStartup),
            c.POINTER(ProcessInfo),
        ]
        size = c.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 2, 0, c.byref(size))
        if not size.value:
            raise c.WinError(c.get_last_error())
        attributes = c.create_string_buffer(size.value)
        checked(
            kernel.InitializeProcThreadAttributeList(attributes, 2, 0, c.byref(size))
        )
        fds = []
        info = ProcessInfo()
        try:
            stdin = os.open(os.devnull, os.O_RDONLY)
            fds.append(stdin)
            out_read, out_write = os.pipe()
            fds.extend((out_read, out_write))
            err_read, err_write = os.pipe()
            fds.extend((err_read, err_write))
            handles = (w.HANDLE * 3)(
                *(msvcrt.get_osfhandle(fd) for fd in (stdin, out_write, err_write))
            )
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            jobs = (w.HANDLE * 1)(self.handle)
            # HANDLE_LIST limits inheritance; the non-inheritable job handle
            # must remain owned solely by the pilot for KILL_ON_JOB_CLOSE.
            checked(
                kernel.UpdateProcThreadAttribute(
                    attributes, 0, 0x20002, handles, c.sizeof(handles), None, None
                )
            )
            checked(
                kernel.UpdateProcThreadAttribute(
                    attributes, 0, 0x2000D, jobs, c.sizeof(jobs), None, None
                )
            )
            startup = ExtendedStartup()
            startup.startup.cb = c.sizeof(startup)
            startup.startup.flags = 0x100  # STARTF_USESTDHANDLES
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = (
                handles
            )
            startup.attributes = c.addressof(attributes)
            if any("\0" in key + value or "=" in key for key, value in env.items()):
                raise ValueError("invalid child environment")
            block = c.create_unicode_buffer(
                "\0".join(f"{key}={env[key]}" for key in sorted(env, key=str.casefold))
                + "\0\0"
            )
            checked(
                kernel.CreateProcessW(
                    str(command[0]),
                    c.create_unicode_buffer(subprocess.list2cmdline(command)),
                    None,
                    None,
                    True,
                    0x80000 | 0x400,  # extended startup + Unicode env
                    block,
                    str(cwd),
                    c.byref(startup),
                    c.byref(info),
                )
            )
            process = JobProcess(kernel, info.process, info.pid)
            process.stdout = os.fdopen(out_read, "rb")
            fds.remove(out_read)
            process.stderr = os.fdopen(err_read, "rb")
            fds.remove(err_read)
            info.process = None
            return process
        finally:
            kernel.DeleteProcThreadAttributeList(attributes)
            for fd in fds:
                os.close(fd)
            if info.thread:
                kernel.CloseHandle(info.thread)
            if info.process:
                kernel.CloseHandle(info.process)

    def close(self):
        if self.handle:
            try:
                checked(self.kernel.TerminateJobObject(self.handle, 1))
            finally:
                self.kernel.CloseHandle(self.handle)
                self.handle = None


class JobProcess:
    """The small wait/kill/pipe surface used by the fixed runner."""

    def __init__(self, kernel, handle, pid):
        self.kernel, self.handle, self.pid = kernel, handle, pid
        self.returncode = None
        kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        status = self.kernel.WaitForSingleObject(
            self.handle, 0xFFFFFFFF if timeout is None else max(0, int(timeout * 1000))
        )
        if status == 258:
            raise subprocess.TimeoutExpired(str(self.pid), timeout)
        if status != 0:
            raise c.WinError(c.get_last_error())
        code = w.DWORD()
        checked(self.kernel.GetExitCodeProcess(self.handle, c.byref(code)))
        self.returncode = code.value
        self.kernel.CloseHandle(self.handle)
        self.handle = None
        return self.returncode

    def poll(self):
        try:
            return self.wait(timeout=0)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.poll() is None:
            checked(self.kernel.TerminateProcess(self.handle, 1))
