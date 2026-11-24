"""Bounded native metadata attached only to an existing privacy rejection."""

import ctypes as c
from ctypes import wintypes as w
import json

from tools import workspace_windows as win


def private_acl_error(path, reason, current, actual, acl):
    kernel, security = win.libraries()
    details = {
        "expected_user_sid": current,
        "actual_owner_sid": actual,
        "dacl": "present" if acl else "null",
        "ace_count": c.c_ushort.from_address(acl.value + 4).value if acl else 0,
        "aces": [],
    }
    security.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
    for index in range(min(details["ace_count"], 16)):
        ace = c.c_void_p()
        try:
            win.checked(security.GetAce(acl, index, c.byref(ace)))
            kind = c.c_ubyte.from_address(ace.value).value
            details["aces"].append(
                {
                    "type": kind,
                    "flags": c.c_ubyte.from_address(ace.value + 1).value,
                    "mask": c.c_uint32.from_address(ace.value + 4).value,
                    # Other layouts are already refused by private_acl, not guessed.
                    "sid": win.sid_text(c.c_void_p(ace.value + 8))
                    if kind in {0, 1}
                    else None,
                }
            )
        except OSError as error:
            details["ace_metadata_error"] = str(error)[:256]
            break
    details["aces_truncated"] = details["ace_count"] > len(details["aces"])
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
    try:
        win.checked(
            security.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token))
        )

        def information(kind):
            length = w.DWORD()
            security.GetTokenInformation(token, kind, None, 0, c.byref(length))
            if not 0 < length.value <= 4096:
                raise ValueError("token metadata exceeds diagnostic size bound")
            buffer = c.create_string_buffer(length.value)
            win.checked(
                security.GetTokenInformation(
                    token, kind, buffer, length, c.byref(length)
                )
            )
            return buffer

        owner = information(4)  # TokenOwner, not TokenUser
        details["token_default_owner_sid"] = win.sid_text(c.c_void_p.from_buffer(owner))
        details["token_elevated"] = bool(w.DWORD.from_buffer(information(20)).value)
    except (OSError, ValueError) as error:
        details["token_metadata_error"] = str(error)[:256]
    finally:
        if token:
            kernel.CloseHandle(token)
    return ValueError(f"{reason}: {str(path)[:512]}; security={json.dumps(details)}")
