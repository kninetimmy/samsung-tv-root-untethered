# External Q70T / NIKEM research

> **External research:** These are newly written summaries of findings reported
> by other owners, not results reproduced by this fork or an installation guide.
> They add context for older TVs without adding a supported CLI target, payload,
> root method or boot procedure. Start with the [quick start](../../QUICKSTART.md)
> for this project's tooling.

## Provenance and scope

Credit: **cfloinc**, [samsung-q70t-tizen-root][source], reviewed at revision
[`4969e20320f3129119b0f5ef7308c9db9d2fd4f7`][revision]. Links below are pinned
to that revision so later upstream edits do not silently change this summary's
evidence. Upstream code and documentation are copyright (c) 2026 cfloinc,
licensed under the [MIT License][license]. Its [notice and credits][notice]
identify the earlier work and independent contributors behind the findings;
this consolidation does not claim those discoveries as this fork's work.

No upstream source files, prose passages, scripts, firmware, binaries, keys or
assets are copied here. Any future import of their code or substantial text
must retain the applicable copyright and MIT permission notice; external work
does not become Unlicensed merely because it is referenced by this project.

The main reported device is **QN65Q70TAFXZA**, 2020 NIKEM / ARMv7, Tizen 6.0,
Linux 4.1.10, firmware **T-NKMAKUC-2743.0**. Its [target record][target]
reports an exFAT USB kernel root route and raw-block boot persistence. Those
results are separate from our QN90B, QN90F and U8000 evidence. The repository
also preserves [independent Q90T firmware-container checks][q90t]; downloaded
firmware verification is not proof that the same firmware is installed on a TV.

## Capability boundaries on older TVs

The [capability investigation][capabilities] found runtime directories and
managed launchers on the Q70T, but no `/usr/bin/dotnet` host. Processes launched
through the managed app path had no effective capabilities, including after
app-context and certificate experiments. A runtime's presence alone therefore
does not establish the capability-bearing execution needed by archive-root.

For another model, inspect the actual host, effective capabilities and launch
context. Keep this negative result tied to the inspected Q70T firmware; do not
infer that every older Samsung TV lacks an archive-root path.

## Firmware layout and TEE decryption

The [MSDU11 container analysis][container] corrects a concrete extraction error
on T-NKMAKUC-2743.0: its encrypted TOC is **3984 bytes** starting at `0xFC`, so
section ciphertext begins at **`0x108C`**. Assuming a 3844-byte TOC moves the
section base to `0x1000`, shifting ciphertext by `0x8C` and making valid-key
decryptions appear broken. The source's layout checker tests block alignment;
section lengths, container closure and plaintext CRC/content checks provide
further evidence. These offsets are a firmware-specific example, not defaults
for our tools or other MSD containers.

The [TEE study][tee] reports firmware decryption from an ordinary managed app,
using the device's SWU trusted application and its legacy ABI. It validates
plaintext against section metadata rather than treating plausible output as
success. This is useful independent evidence for a TV-mediated decryption
workflow, not a claim that the same calls work on every model.

This project already has [SWU and TEEC research](AES_EXTRACTION.md), including
legacy/modern ABI handling. Its firmware-decrypt client currently selects the
modern profile; this note does not add Q70T compatibility or duplicate the
upstream client. A future port must establish the exact ABI, command contract
and output checks on its target.

## UEP remains a separate boundary

The [UEP investigation][uep] reports that root identity alone does not permit
unsigned native execution. Copying a signed executable to a new inode did not
preserve executability. Script content passed to an already signed shell
behaved differently from loading an unsigned script file.

The source distinguishes observations from unresolved controls around inode,
path and mount behavior. Preserve those limits when citing it: a successful
script invocation is not proof of a universal UEP bypass. Its kernel patch
addresses, loop-device exploit and boot integration remain build-specific
research, not a replacement for our existing boot-root route.

## Debloat durability and diagnostics

The [debloat study][debloat] distinguishes vendor-provided condition markers,
user package deactivation and temporary `/run/systemd/system` masks. On that
device, ordinary disable/mask operations did not provide the expected durable
result; runtime masks needed a boot-time reapply. Services could also reactivate
through other dependencies. Its inventory is not an approved removal list for
our TVs, whose modules must be checked independently for dependencies and
recovery behavior.

The [debug-channel notes][debug] also document session-owned background jobs,
one-way socket failures and process matching that can kill the script running
it. The transferable lesson is to verify resulting device state through an
independent channel and use exact process ownership rather than broad command-
line matching. The source's raw shell servers are not imported into our
authenticated management tooling.

## Home routing differs by generation

On the documented Q70T build, the [target record][target] reports Home routing
through `db/first_screen/type`; `db/appfw/home_appid` and `startup_appid` were
absent. A launcher was reached with Home from another app. That is a Home-button
result, not evidence of reliable cold-start behavior or QN90B compatibility.

For a future launcher, query the exact TV's existing operation and preferences,
preserve a baseline and recovery route, and assess Home and startup separately.
Do not copy another generation's keys or overwrite the existing boot-root
configuration from this research note. Launcher development remains a separate
project; this change supplies reference material only.

[source]: https://github.com/cfloinc/samsung-q70t-tizen-root
[revision]: https://github.com/cfloinc/samsung-q70t-tizen-root/commit/4969e20320f3129119b0f5ef7308c9db9d2fd4f7
[license]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/LICENSE
[notice]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/NOTICE.md
[target]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/targets/q70t-nikem-2020.md
[q90t]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/q90t-nkmakuc-2743.0-verification.md
[capabilities]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/07-capabilities-and-zones.md
[container]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/02-firmware-container.md
[tee]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/03-tee-decrypt.md
[uep]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/06-uep.md
[debloat]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/09-debloat.md
[debug]: https://github.com/cfloinc/samsung-q70t-tizen-root/blob/4969e20320f3129119b0f5ef7308c9db9d2fd4f7/docs/methodology/10-debug-channels.md
