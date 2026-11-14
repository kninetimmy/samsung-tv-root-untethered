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

1. Interface freeze: WS-A only.
2. Parallel workstreams: WS-B through WS-E.
3. Integration: one integrator.
4. Seal: main session.
5. Review: one cold reviewer.

## Interface freeze

WS-A publishes `.memhub/prep/<packet>/INTERFACES.md` before any other agent
starts. It contains:

- exact signatures and semantics for every shared helper (recorder, `expect`,
  shared terminal handler, supervisor decode);
- the call-site binding schema and the evidence and outcome record keys;
- the file-ownership table for this packet, one owner per path;
- stub-level import or compile proof.

No other workstream starts until the interface owner reports it frozen. If a
workstream later needs an interface change, it asks the interface owner, who
updates `INTERFACES.md` and records the change; the integrator reconciles.

## Workstream rules

- One owner per file. Never edit a file owned by another workstream; send a
  request instead.
- Do not run the full seal flow. Targeted tests only, with private outputs.
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

A socket death is recovered by a fresh agent reading this file, not by replaying
the conversation.

## Integration

The integrator reads every handoff, reconciles interface drift and runs the
targeted suites. It may return a question to a workstream session; it does not
re-derive that workstream's code. It produces:

- the consolidated diff summary;
- the ordered seal command list, with working directory and environment;
- a list of unresolved risks.

## Seal

The main session runs the ordered seal flow detached and unbuffered, with no
tool timeout, and reports the exact result. No agent seals. The seal runs only
after the integrator reports the targeted suites green.

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
