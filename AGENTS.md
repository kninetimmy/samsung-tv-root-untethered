# Samsung TV root

Samsung TV root tooling. Use standalone Codex; Orch is disabled.

## Session continuity

Memhub at `.memhub/project.sqlite` is the source of truth.
Start with `.memhub/rendered/PROJECT.md`; use `memhub recall` for details
and `memhub arch show` for build/test commands.
Generated memory stays local and ignored by Git.
