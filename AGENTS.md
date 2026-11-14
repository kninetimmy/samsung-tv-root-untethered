# Samsung TV root

Samsung TV root tooling. Use standalone Codex; Orch is disabled.

## Session continuity

Memhub at `.memhub/project.sqlite` is the source of truth.
Start with `.memhub/rendered/PROJECT.md`; use `memhub recall` for details
and `memhub arch show` for build/test commands.
Generated memory stays local and ignored by Git.

## Packet workstreams

Packet authoring is split across disjoint workstreams with one integrator and
one cold reviewer; the main session runs the seal. See
`docs/PACKET-WORKSTREAM-PROTOCOL.md`.
