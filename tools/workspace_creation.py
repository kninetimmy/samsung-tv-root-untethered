"""Explicit Windows creation security and read-only process-token identity."""

from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import os

from tools import workspace_windows as win


@contextmanager
def private_attributes():
    kernel, security = win.libraries()
    descriptor = c.c_void_p()
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        c.POINTER(c.c_void_p),
        c.c_void_p,
    ]
    sid = win.owner_sid()
    win.checked(
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

    try:
        yield Attributes(c.sizeof(Attributes), descriptor, False)
    finally:
        kernel.LocalFree(descriptor)


def create_file(path):
    """CREATE_NEW, explicit owner/DACL, non-inheritable handle; never rewrite."""
    import msvcrt

    kernel, _ = win.libraries()
    kernel.CreateFileW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        c.c_void_p,
        w.DWORD,
        w.DWORD,
        w.HANDLE,
    ]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    with private_attributes() as attributes:
        # Sharing permits cooperating ledger handles; CREATE_NEW never reopens.
        handle = kernel.CreateFileW(
            str(path), 0xC0000000, 3, c.byref(attributes), 1, 0x80, None
        )
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return fd


def token_identity():
    """TOKEN_QUERY only: user, default owner and elevation; no token changes."""
    kernel, security = win.libraries()
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    security.GetTokenInformation.argtypes = [
        w.HANDLE,
        w.DWORD,
        c.c_void_p,
        w.DWORD,
        c.POINTER(w.DWORD),
    ]
    token = w.HANDLE()
    win.checked(
        security.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token))
    )
    try:

        def information(kind):
            length = w.DWORD()
            security.GetTokenInformation(token, kind, None, 0, c.byref(length))
            if not 0 < length.value <= 4096:
                raise ValueError("token identity exceeds size bound")
            buffer = c.create_string_buffer(length.value)
            win.checked(
                security.GetTokenInformation(
                    token, kind, buffer, length, c.byref(length)
                )
            )
            return buffer

        user, owner = information(1), information(4)
        return {
            "user_sid": win.sid_text(c.c_void_p.from_buffer(user)),
            "default_owner_sid": win.sid_text(c.c_void_p.from_buffer(owner)),
            "elevated": bool(w.DWORD.from_buffer(information(20)).value),
        }
    finally:
        kernel.CloseHandle(token)
