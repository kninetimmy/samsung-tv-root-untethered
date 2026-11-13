# Historical evidence, not a new TV observation

r15 seal SHA-256: `18d14375d0576fc52e0ba15647c2aebf2f8de1c6e13788d8b11c3d19f89c7e2e`.
Its permanent STOP and consumed attempt are never copied or replayed.
`r15-evidence-digests.json` pins the full sealed set and the named runtime evidence.

1-based r15 `receipts.jsonl` citations:
- 5173: gate-remove exit=0, GATE_CONFIG_REMOVED_COMPLETE / GATE_ABSENT.
- 6406: boot 299d6f3f-c014-43e5-a487-59c47c833f6f; config absent;
  manager 449cf034 / runtimeconfig ed69fdc8; module/backup present; bridge active;
  proof 90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29.
- 6506: exact absent-config module boot receipt and module exit=0.
- 6452: automatic proof bytes extracted to anchored-proof.txt; SHA-256 exactly
  90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29.
  Host tests use these historical bytes and the real SHA-256, not a substituted hash.
- 6524: enforcing fingerprint c07bd300 00000001 00000000 000004e2.
- 6585: bash reported Operation not permitted, while the wrapper falsely said
  native_exit=0. QN90B_UEP_NATIVE_PROBE_OK was absent.
- 6586: stage failed solely at the expected-permission-denial assertion.

Authoritative post-STOP measurement: sibling `qn90b-uep-denial-errno-20261110`;
measurement.json and dmesg_grep.txt are carried byte-identically. The raw fields
have trailing `|`; its `boot_is_stopped_boot: false` is therefore not a new
boot observation and is not used as authority. The raw boot text matches the
full anchored boot before that transport delimiter; r16 must re-certify live.

The kernel names the denier and canonical vdfs path:
`[   95.244381] [Verification fail] file /opt/usr/home/owner/share/tmp/sdk_tools/denial-fd9fa25930776ce9/uep-probe.elf is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)`.

**Known-open observation:** "The r8 baseline produced EACCES for the same UEP
signature check while boot 299d6f3f produced EPERM. The difference is unresolved;
neither result is canonicalised, and the r8 result is not claimed to be wrong."

The denial ELF is inert under UEP, not a running hazard. Its remaining staging
tree is preserved pending the separate optional task46 step. No receipt or
measurement naming that path is deleted by either r16 step.
