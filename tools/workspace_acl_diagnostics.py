"""Bounded native metadata attached only to an existing privacy rejection."""

import ctypes as c
from ctypes import wintypes as w
import json

from tools import workspace_windows as win
from tools.workspace_creation import token_identity


def private_acl_error(path, reason, current, actual, acl):
    _, security = win.libraries()
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
    try:
        token = token_identity()
        details["token_default_owner_sid"] = token["default_owner_sid"]
        details["token_elevated"] = token["elevated"]
    except (OSError, ValueError) as error:
        details["token_metadata_error"] = str(error)[:256]
    return ValueError(f"{reason}: {str(path)[:512]}; security={json.dumps(details)}")
