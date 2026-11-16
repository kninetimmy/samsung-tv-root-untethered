# Samsung TV root

Samsung TV root tooling. Use standalone Codex; Orch is disabled.

## Writing style

Plain language is the default for everything written to the owner: chat
answers, handoffs, STATUS and review prose. Short sentences, no unexplained
jargon, no piled-up acronyms. Keep a technical term when it is the precise
one or when plain wording would lose meaning, and define it the first time
it appears. Lead with the outcome; put hashes, paths and counts after the
sentence that says what they mean. Code, identifiers and evidence files are
exempt.

## Session continuity

Memhub at `.memhub/project.sqlite` is the source of truth.
Start with `.memhub/rendered/PROJECT.md`; use `memhub recall` for details
and `memhub arch show` for build/test commands.
Generated memory stays local and ignored by Git.

## Packet workstreams

Packet authoring is split across disjoint workstreams with one integrator and
one cold reviewer; the main session runs the seal. See
`docs/PACKET-WORKSTREAM-PROTOCOL.md`.
