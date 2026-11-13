# Archived sealed packets

Immutable record of every UEP deployment packet that has been superseded.
Working packets stay in `.memhub/prep`, which is gitignored and machine-local;
a packet is copied here once its successor is sealed, so the live set is always
the current packet plus its immediate predecessor (the port tooling reads the
predecessor as a sibling directory).

## What is archived

Each directory holds `seal.json` plus exactly the files it names, so the packet
can be re-verified with the packet controller: `sha256(seal.json)` is the seal
digest recorded in that packet's commit message. Sealed build outputs
(`artifacts/*.dll`, `artifacts/*.elf`, `build/*.dll`) are included, because the
seal covers them. `.gitattributes` marks this tree `-text` so checkout cannot
rewrite the bytes to CRLF.

The release audit (`tools/audit_release.py`) treats this tree as a record rather
than a release artifact: its binary rules are scoped away from `packets/`, while
every text rule (private IPv4, private key, personal path, fleet hostname) still
applies. That is why the addresses below had to be sanitized before archiving.

## Sanitization

The developer-mode LAN address the TV trusts was replaced with
`000.000.00.000` in the files below, one occurrence each. Their current bytes
therefore no longer match `seal.json`; every other file in the tree does.
The original digests are preserved here so the pre-sanitization bytes can still
be identified against any surviving copy.

| Packet | File | Original sha256 |
| --- | --- | --- |
| qn90b-uep-l4-deploy-20261108-r1 | `BridgeRepairAgent.cs` | `a77bade786490860d46b8ec4cf2493c37bda87494739992874ac0d6c6f76fa6c` |
| qn90b-uep-l4-deploy-20261109-r2 | `BridgeRepairAgent.cs` | `fcce9501ac870e6009aeeda5859093a60c107a8a30caf6d8ca118037a27b052e` |
| qn90b-uep-l4-deploy-20261109-r3 | `BridgeRepairAgent.cs` | `fcce9501ac870e6009aeeda5859093a60c107a8a30caf6d8ca118037a27b052e` |
| qn90b-uep-l4-deploy-20261109-r4 | `BridgeRepairAgent.cs` | `fcce9501ac870e6009aeeda5859093a60c107a8a30caf6d8ca118037a27b052e` |
| qn90b-uep-l4-deploy-20261109-r5 | `BridgeRepairAgent.cs` | `fcce9501ac870e6009aeeda5859093a60c107a8a30caf6d8ca118037a27b052e` |
| qn90b-uep-l4-deploy-20261109-r6 | `BridgeRepairAgent.cs` | `fcce9501ac870e6009aeeda5859093a60c107a8a30caf6d8ca118037a27b052e` |
| qn90b-uep-l4-deploy-20261109-r7 | `BridgeRepairAgent.cs` | `7a142e1010d582fcc60fd59f5ab671283fba6403da4c931d81cd6c73cdb43f4a` |
| qn90b-uep-l4-deploy-20261109-r8 | `BridgeRepairAgent.cs` | `7a142e1010d582fcc60fd59f5ab671283fba6403da4c931d81cd6c73cdb43f4a` |
| qn90b-uep-l4-deploy-20261109-r9 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261110-r10 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261111-r11 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261112-r12 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261113-r13 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261114-r14 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261115-r15 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261116-r16 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261117-r17 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261118-r18 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261119-r19 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261120-r20 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261121-r21 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261122-r22 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261123-r23 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |
| qn90b-uep-l4-deploy-20261124-r24 | `UepGateAgent.cs` | `870178c94344d6f910a888fa2fa1a44396abf348e24ba3594c6bb28e472c4bb3` |

Archived packets: 24 (1,510 files). r27 is sealed but was reviewed not fit, so
it is not a usable fallback: the operational live pair is r26 plus its
predecessor r25, and r27 is retained only as the port source for its successor.
Every older packet is archived here.

_Last updated 2026-11-13._

