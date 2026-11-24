"""Windows platform checks; no packet imports or host-policy changes."""

from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from pathlib import Path, PureWindowsPath
import re


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
        if sid_text(owner) != current or not acl:
            raise ValueError(f"workspace owner or DACL is not private: {path}")
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
                raise ValueError(f"non-private workspace ACL: {path}")
            allowed.add(principal)
        if allowed != {current, "S-1-5-18"}:
            raise ValueError(f"missing owner/SYSTEM access: {path}")
    finally:
        kernel.LocalFree(descriptor)


def make_private(path: Path):
    """Create exactly one new directory with its private ACL at creation."""
    kernel, security = libraries()
    descriptor = c.c_void_p()
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        c.POINTER(c.c_void_p),
        c.c_void_p,
    ]
    sid = owner_sid()
    checked(
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)",
            1,
            c.byref(descriptor),
            None,
        )
    )

    class Attributes(c.Structure):
        _fields_ = [
            ("length", w.DWORD),
            ("descriptor", c.c_void_p),
            ("inherit", w.BOOL),
        ]

    attributes = Attributes(c.sizeof(Attributes), descriptor, False)
    kernel.CreateDirectoryW.argtypes = [w.LPCWSTR, c.POINTER(Attributes)]
    try:
        checked(kernel.CreateDirectoryW(str(path), c.byref(attributes)))
    finally:
        kernel.LocalFree(descriptor)
    private_acl(path)


class ProcessJob:
    """Kill the build's descendants too, including when the pilot is killed."""

    def __init__(self, process):
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
        kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
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
            checked(
                kernel.AssignProcessToJobObject(self.handle, w.HANDLE(process._handle))
            )
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)
            self.kernel.CloseHandle(self.handle)
            self.handle = None
