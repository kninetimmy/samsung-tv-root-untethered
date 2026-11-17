# Packet workstream protocol

Applies to every certification packet authored under `.memhub/prep/` in this
repository. It exists because one agent holding a whole packet compacts, drifts,
and dies at the session socket boundary; a packet is larger than one context.

Owner: Kninetimmy. Change this file only by pull request.

## Roles and model pins

| Role | Model (current pin) | Owns |
|---|---|---|
| WS-A core and interface | `openai/gpt-6.1-sol#xhigh` | `INTERFACES.md`, recorder and runtime core |
| WS-B scope and gating | `openai/gpt-6.1-sol#xhigh` | boundary derivation, packet gating hooks |
| WS-C consumers | `openai/gpt-6.1-sol#xhigh` | expected-code consumer migration |
| WS-D integrations | `openai/gpt-6.1-sol#xhigh` | call sites, bindings, integration controls |
| WS-E supervisor and adapters | `openai/gpt-6.1-sol#xhigh` | outcome decoding, protocol adapters, probes |
| Integrator | `openai/gpt-6.1-sol#xhigh` | merge, targeted suites, seal command list |
| Seal runner | main session | the ordered long-running seal |
| Cold reviewer | `openai/gpt-6-astra#high` | independent read-only review |

Pins are per-repository and current as of 2026-11-14. The owner updates them;
agents do not substitute models.

## Schedule

1. API and proof-model freeze: WS-A, with input from WS-B and the supervisor
   owner, before any authoring.
2. Parallel authoring: WS-B through WS-E. Targeted results are checkpoints, not
   credit for the final frozen generation.
3. Integration and preflight: one integrator reconciles every owner's changes,
   producers, authoritative inputs, provenance and source membership.
4. Source and input freeze: the integrator records one complete generation
   manifest and stops every input writer.
5. Frozen proof cohort: assigned execution leaders run disjoint obligations on
   the integrator's schedule, with private outputs.
6. Publication and verification: canonical owners publish whole documents on
   one coordinated schedule. The integrator checks coverage and gate results
   against the frozen generation.
7. Seal: main session, after green integration.
8. Review: one cold reviewer.

Execution may run in parallel. During a frozen cohort nobody changes inputs,
and canonical documents are published only on the coordinated schedule.

## API and proof-model freeze

WS-A publishes `.memhub/prep/<packet>/INTERFACES.md` before any other agent
starts, with input from WS-B and the supervisor owner. It contains:

- exact signatures and semantics for every shared helper (recorder, `expect`,
  shared terminal handler, supervisor decode);
- the call-site binding, observation, outcome and artifact schemas, including
  the evidence and outcome record keys;
- the file-ownership table for this packet: one owner per source path, per
  producer and per canonical output;
- runtime roots, the test/runtime boundary and the coverage-key rules;
- the analyzer rules the proof depends on, required annotations, conservative
  fallback behavior and known unsupported forms;
- approved generated-code origins and their source and identity checks;
- what proof is required for repeated actions, nested graphs, late actions,
  native actions and the exact process and artifact channels;
- representative acceptance and refusal controls;
- stub-level import or compile proof, with its limitations stated.

The proof-model freeze says how compliance will be shown. It does not claim
that any pending implementation passes.

No other workstream starts until the interface owner reports it frozen. A later
shared change goes to WS-A, which records it as a versioned amendment in
`INTERFACES.md`. The affected owner implements it, dependent workstreams
acknowledge it, and the integrator reconciles it before the source freeze.

A freeze records approvals that already exist. It grants no new process,
import, device or certification policy.

## Workstream rules

- One owner per file. Never edit a file owned by another workstream; send a
  request instead.
- Do not run the full seal flow. Targeted tests and assigned frozen-cohort
  obligations only, with private outputs.
- Do not write `seal.json`, `STATUS.md` or the final manifest.
- Do not change the contract. Contract amendments are a separate owner-approved
  documentation change.
- Do not commit to git, contact the device, or touch sealed predecessors.
- Leave the packet importable at every checkpoint. If an intermediate state is
  broken, say exactly what is broken in the handoff.

## Checkpoints and handoff

Each workstream writes `workstreams/WS-X.md` at the end of every milestone and
before stopping or handing off:

- Status: in progress / blocked / done
- Files changed
- What executes now, with the command and its result
- What remains
- Open interface questions
- Exact resume instructions

A handoff from a frozen cohort also records:

- the generation and phase identity, and a reference to the complete input map;
- the assigned obligation keys and their exact predeclared expectations;
- the exact commands, working directory, interpreter and environment;
- private output locations and the hashes of the raw artifacts;
- planned, attempted, target-reached, matched, refused and unreached results;
- verifier issues verbatim, and start and end integrity receipts;
- remaining omissions, the exact resume command and the sole canonical
  publisher.

The current checkpoint is the resume authority. Earlier checkpoints are
history. Never present an older green count as credit for the current
generation.

A socket death is recovered by a fresh agent reading this file, not by replaying
the conversation.

## Structural test/runtime boundary

Test supervision, child execution and test-only loading live outside the
runtime import closure derived from source. Shared protocol and decoder modules
may be runtime dependencies, but they must not import, lazily load or re-export
test code. The dependency runs one way.

WS-B proves the boundary from the declared runtime roots, including resolved
dynamic imports. An unknown import refuses. A direct or aliased import of a
test execution module defeats its exclusion. Uncalled-function arguments in the
same module, name exemptions and annotation-only claims do not replace the
boundary.

Excluded test code is still inventoried, sealed and source-pinned.

The boundary proves supervisor exclusion. It does not waive runtime callback
analysis, unresolved imports, outside-attempt accounting or the global consumer
and reporter obligations. Those stay separate.

## Source and input freeze

The second freeze pins the finished bytes before the final proof cohort.

Before the freeze:

- The integrator has a current handoff from every owner.
- Every known change to source or pinned-input bytes that a later proof or seal
  step needs is finished. This includes supervisor instrumentation, process
  containment, producer and fixture repairs, annotations, catalog and anchor
  repairs, provenance constants and source-membership declarations. Only
  designated outputs, such as the final manifest and seal records, may wait.
- Each of those edits is made by the file's owner, on request. The integrator
  coordinates and verifies; it does not edit files it does not own.
- Provenance constants are re-pinned last. A source digest can only be
  re-pinned once the sources it covers have stopped changing: freeze those
  sources, then write the constant, then start the cohort.
- Representative proof controls pass with the final producer, exporter and
  verifier. Compile or import success is not enough.
- Owners derive and publish whole binding, admission and scope inputs in
  dependency order, with unique keys and zero drift.

At the freeze, the integrator:

- freezes producer and controller code, templates, expectations, schemas,
  executable and build inputs, and the complete effective source universe;
- records the complete path set and hashes, the obligation ledger, the commands
  and the private output assignments;
- classifies every path as an immutable input or a designated output. An output
  that becomes a later phase's input gets an explicit phase receipt; it never
  changes source bytes;
- stops every input writer, keeps read-only protection in place and rechecks
  the hashes throughout.

Per-run payloads are generated only by frozen producers from predeclared
parameters. Do not tune declarations after seeing results.

On drift, stop launching, keep the evidence and refuse the cohort. Do not
bypass locks, re-pin old executions or quietly pick a newer snapshot.

Reopening the freeze needs owner coordination, an impact report and a fresh run
of every proof whose input set changed. A supervisor change invalidates every
proof pinned to that generation.

## Frozen proof shards and publication

The integrator may assign disjoint obligation keys to execution leaders. This
delegates execution only. It grants no edit or policy authority; model pins and
approvals still apply. Each shard:

- uses the same frozen inputs;
- writes to fresh private run, subject, build and cache namespaces;
- saves raw outcomes before asserting anything;
- keeps attempted, target-reached and accepted separate;
- checks paths and hashes at start and end;
- keeps every failed, refused, interrupted and unreached obligation.

Run shards at the same time only after private-output behavior and the disk and
memory budget have been checked. Otherwise run them one after another inside
the same freeze.

The obligation ledger is derived once, with the approved key scheme. Duplicate
candidates are merged and target sets interned without losing aliases, role
alternatives or source witnesses. Exact obligations stay separate from
conservative alias debt. Conservative candidates are neither turned into extra
execution obligations nor silently dropped.

Raw evidence is kept once per execution. Canonical documents do not embed it
twice where the schema allows a reference. A new reference form needs a WS-A
amendment, contained-path and digest checks and complete raw revalidation.
Compression and references never count as attestation.

Only the assigned canonical owner publishes each whole document. The integrator
schedules publication after execution closes and the integrity receipts match.
Shards do not publish.

Nothing is backfilled from an older generation. A missing obligation stays
explicitly missing. An exit code, a producer flag or an empty issue list alone
is not acceptance.

## Integration

One integrator serves each generation. It reads every handoff, reconciles
interface drift and runs the targeted suites. It may return a question to a
workstream session; it does not re-derive that workstream's code. Execution
leaders return shard receipts to it, not separate freezes.

Coordination is not edit permission. Every file keeps its owner, and the
integrator sends requests like any other role.

The integrator produces:

- the consolidated diff summary;
- the generation manifest and the complete coverage ledger;
- publication receipts and the remaining gate issues;
- the ordered seal command list, with working directory and environment;
- confirmation that no later seal step needs a change to a frozen source or
  input;
- a list of unresolved risks.

## Seal

The main session runs the ordered seal flow detached and unbuffered, with no
tool timeout, and reports the exact result. No agent seals. The seal runs only
after the integrator reports the targeted suites green.

The source freeze stays in force through the seal. The seal must not repair
source, annotations, fixtures, provenance constants or membership declarations.
If it finds such a repair is needed, the seal stops and goes back to an
explicit unfreeze. The final manifest and seal records are designated outputs;
producing them must not change any frozen proof input.

## Review

The cold reviewer is a different model from every authoring agent, receives the
sealed packet and the contract only, and scores against the contract. It does
not edit, seal, or accept a major as closed.

## Anti-patterns

- One agent authoring the whole packet.
- Two agents editing the same file.
- A workstream running the seal.
- An author reviewing its own packet.
- A handoff that says "done" without the command and its output.
- Freezing signatures while the proof model is still unresolved.
- Running final proofs while any source or authoritative-input writer is still
  active.
- Refining whole-program precision to avoid a structural test/runtime boundary.
- Execution shards publishing competing canonical documents.
- Reusing old executions after their pinned inputs changed.
- Deferring source-changing provenance or membership work until after the final
  proofs.
