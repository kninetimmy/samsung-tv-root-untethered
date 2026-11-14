# Certification harness contract

Status: revision 3, accepted by the owner on 2026-11-13 and recorded in memhub.
Revision 2 narrowed the boundary inventory to the attempt path (section 2.0) and
unified terminal escrows (section 2.5). Revision 3 adds lifecycle reachability,
the `(handler, call-site binding)` model and per-caller integration controls.
The identity rules, C1-C8, runtime protocol, evidence and trust boundary are
unchanged. Binding on r29 and every later packet that claims the L4 denial
certification.

This document replaces the r28 `PLAN.md` fit criterion (a') and its clauses
(i)-(v), which it amends. It does not modify the accepted denial certification
contract (kernel-record completeness; architecture section "Denial
certification contract (accepted 2026-11-11)"); those obligations remain
separate and unchanged.

Each packet from r29 carries `CONTRACT.md`, byte-identical to this file, listed
in the seal manifest with its digest pinned in `PLAN.md` and evidence. A
reviewer scores the packet against that sealed copy, never against this tree.

## 1. The claim

Certification claims that the sealed bytes, executing as written on a trusted
host, either carry a declared identity or refuse, and that every pass is backed
by complete evidence. It does not claim author honesty, host integrity, or
robustness against a deliberately hostile channel (section 5).

A mechanism earns credit only by executing. Prose, names, comments and
self-attestation are never evidence and never gate.

## 2. Boundary sites

### 2.0 Scope: the attempt path

Certification is a claim about one live attempt: the entry point that reads the
kernel bracket, executes once and records the outcome, plus the tidy path when
the packet runs it. The boundary inventory proves that path.

- `ATTEMPT_ENTRIES` is a closed, sealed list of entry points (`certify.main`
  and `tidy.main` when present). The inventory covers exactly the boundary
  sites in scope by the rule below.
- Scope includes executable module initialization, entrypoint preambles,
  constructors, callback registrations and terminal accounting needed to run
  `ATTEMPT_ENTRIES`. Resolve calls conservatively across aliases, inheritance
  and callbacks. An unresolved target includes every compatible target in the
  closed universe, or refuses the gate. An allowlist entry does not exempt that
  module's reachable packet-owned code. Moving code or introducing indirection
  cannot remove it from scope without an executable exclusion proof.
- A site outside the attempt path is not a certification boundary. It must be
  exactly one of:
  (a) a consumer that asserts a predeclared type/code through the matcher
      (`failure.expect`);
  (b) a catch that propagates without recording;
  (c) a call to the shared terminal handler of section 2.5 with its own
      source-bound call-site binding; or
  (d) a host-test reporter that requires an already-recorded root and produces a
      nonpassing supervised result, never a certification outcome.
  A site that records an uncoded failure and continues makes the gate refuse.
- An uncoded escape from any child, in scope or not, is EVIDENCE_FAILURE or
  HARNESS_ERROR, never a pass (section 3).

The claim given up is that every catch in test scaffolding is a certification
boundary. That scaffolding remains covered by expected-code consumers, the four
outcome kinds and the mutation oracle.

### 2.1 Classes

Every enumerated site is exactly one class:

- **escrow**: a handler that admits an uncoded foreign child beneath a failure
  the operation itself constructed. It must name the declared code and the
  construction site that owns it.
- **observer**: a terminal or hook adapter whose handler is itself the
  boundary. A production handler may not be classified as an observer.

### 2.2 Gating fields

The gate reads only:

| field | escrow | observer | source |
|---|---|---|---|
| `id` | required | required | AST |
| `file`, `function`, `line` | required | required | AST |
| `handler_sha256` | required | required | AST dump |
| `source_sha256` | required | required | file bytes |
| `families` | exact MRO names | exact MRO names | AST + resolution |
| `declared_code` | one catalog code | - | row |
| `code_owner` | `file:function:line` | - | row |
| `root_code_required` | - | `true` | row |
| `control` | executed control id | executed control id | suite |

A shared-handler invocation is not a second boundary row. It is a call-site
binding row carrying caller, declared code, callback bindings and control id;
identity and C4 checks apply to the pair `(handler, binding)`.

Non-gating fields - `justification`, `permanent_control` as text,
`cannot_match`, `disposition`, `audit_complete`, `independently_reviewed` -
may remain in the file for humans. The gate must not read them, and a review
may not cite them as proof. C5 enforces this.

### 2.3 Identity rules

1. No capture site may assign a declared code to a foreign exception.
   `native_site` is a family assertion, not an identity assigner.
2. An escrow root must be an exception object the packet recorded itself
   (registry identity). A catalog-valued attribute, first argument, message or
   type is not sufficient.
3. An escrow's `declared_code` must equal the code constructed at
   `code_owner`. For a shared-handler binding, the code is the source-bound
   constant in the binding, and the handler construction is checked once.
4. No type-wide or function-wide fallback may change identity.
5. Catalog membership alone establishes neither a refusal nor a correct
   identity; section 3.1 defines the outcome kinds.

### 2.4 Controls

Each control executes the site's own handler path. A shared hook-path or
matcher test does not substitute for exercising the site.

- **C1 identity**: the escaped or persisted root carries `declared_code`
  (escrow) or a catalog code the packet recorded (observer), never `None`.
- **C2 admission**: an admitted foreign child stays `reason_code: None` and is
  bound to `boundary == site.id`; the site does not stamp identity.
- **C3 refusal matchers**: every declared-refusal matcher rejects the admitted
  child.
- **C4 exactness**: any one of deleting the row, widening `families` by one
  name, changing the row's `declared_code`, or substituting another valid
  catalog code at `code_owner` makes the gate refuse.
- **C5 prose inertness**: replacing every non-gating string with arbitrary
  junk leaves gate output byte-identical. This is a non-interference check
  only; it is not behavioral proof.
- **C6 unlisted site**: an unlisted capture that yields an uncoded escape is
  refused at runtime, never passed.
- **C7 preservation**: forwarding preserves every previously recorded coded
  node in both the escaped and the persisted graph.
- **C8 consumers**: every consumer that can accept a failure is exercised with
  an uncoded, matching-text failure and must refuse it.

Any identity loss, unintended success, incorrect refusal, or evidence loss is
a finding regardless of which control caught it. C3 and C6 are examples of the
failure class, not its definition.

### 2.5 Terminal escrows

Terminal and cleanup handlers share one packet-owned handler instead of
repeating the escrow pattern. The handler preserves an already-recorded original
graph unchanged. Only foreign, unrecorded nodes remain null-coded.

The shared handler has one implementation boundary. Each invocation
additionally has a source-bound call-site binding containing its caller,
declared code, callback bindings and control ID. Identity and C4 checks apply to
`(handler, call-site binding)`; caller codes may not be accepted through an
unbounded dynamic declaration.

Shared-core controls prove traversal, admission, accumulation and forwarding
once. Each caller's integration control executes its actual callback path and
verifies required order, execution of every mandatory cleanup action,
primary-plus-secondary preservation, persisted/escaped graph agreement, and
required durable evidence. Exercise both primary failure and callback failure.
Callback omission or reordering must fail the relevant control. No other catch
may own a terminal aggregate.

## 3. Runtime protocol

### 3.1 Outcome kinds

Every child execution decodes to exactly one:

- **PASS**: an explicit completion marker.
- **DECLARED_REFUSAL**: root recorded by the packet, catalog category `stop`,
  and the refusal matcher accepts it.
- **HARNESS_ERROR**: catalog categories `assert`, `protocol` or `raise`, or a
  recorder or adaptation failure.
- **EVIDENCE_FAILURE**: missing, malformed, contradictory or unavailable
  terminal evidence; timeout; abnormal termination; failure during graph
  traversal.

There is no fifth kind. Missing evidence is never a pass, and neither a zero
exit nor a nonzero exit is by itself a verdict.

### 3.2 Coverage

The recorder is authoritative at construction, admission, persistence,
forwarding and terminal adaptation, not only at interpreter escape.

A supervisor decodes every child: it requires either an explicit completion
marker or a validated failure outcome. Any other terminal state is
EVIDENCE_FAILURE.

Thread, asyncio, `atexit` and destructor paths either propagate into failure
accounting under a permanent control or are prohibited by an executable
constraint.

Each protocol has an explicit adapter: Python child, managed child (exit 86)
and native denial (exit 77). OS status, protocol status and certification
verdict are distinct and are never conflated.

### 3.3 Negative controls and STOP

A negative control runs an isolated child that fails as designed; the parent
asserts that exact decoded outcome and retains the raw graph. No fixture is
exempt from runtime enforcement.

Offline failures never write a live STOP. Only a consumed live stage may
produce STOP; host-test failures stay host-test failures.

### 3.4 Static authoring gate

The AST gate is an accident lint. It blocks the seal on known accident forms
(raise outside the recorder, `require` without a declared reason, encoding
drift), and passing it proves nothing about semantics. A missed spelling
pattern is not a finding unless a runtime outcome it enables is not refused.

The mutation oracle keeps its standard: a kill requires the exact predeclared
type and a declared non-null code. Display text and nonzero status are not
kills.

## 4. Evidence

Evidence is authoritative only if it is byte-bound: the sealed manifest names
every member, the supervisor decodes evidence produced during the run, and
verification covers the interval from seal to use. Accidental corruption,
truncation, overwrite and provenance mismatch are in scope. Deliberate
replacement of the trusted baseline is out of scope (section 5).

## 5. Trust boundary

**In scope**: behavior of the sealed bytes executing as written on a trusted
host - false passes, lost identities, refusals that are not refusals,
over-trust reachable through ordinary operation, evidence provenance and
integrity, and accidental corruption.

**Out of scope**, recorded as a residual note and never scored as blocker,
major or minor:

- deliberate replacement of the interpreter, CLR, SDK, frozen observer, oracle
  channel or evidence baseline;
- forging the private result channel from outside the process;
- dishonest prose, timestamps or review claims;
- a mutation subject that targets the private oracle channel instead of
  exhibiting a behavioral regression.

Findings are admissible when they are reproducible against unmodified sealed
bytes (copies and synthetic inputs are fine) and trace to the certification
claim: a pass that should refuse, an identity that is lost, or a refusal that
is not one.

A contradiction between code and prose is not a finding. A missing executed
control is.

Any reproducible violation of an accepted invariant is corrected or the
invariant is amended by explicit owner approval. The absence of a control that
detects it is not a defense.

## 6. Review

- **Blocker**: a false certification (a pass with incomplete or contradictory
  evidence) or a lost refusal that a live attempt would accept.
- **Major**: an accepted invariant of this contract is violated or unproven at
  a site that can reach the certification path.
- **Minor**: imprecision, or a defect confined to a retired path with no
  certification effect.

Reviewers score only admissible findings. Out-of-scope items are noted as
residuals. The author cannot dismiss a finding by asserting intent, and the
reviewer cannot expand scope by asserting a hostile harness.

## 7. r29 obligations

r29 must:

1. Delete boundary identity stamping and implement sections 2-3.
2. Derive the attempt-path inventory and reachability evidence (section 2.0);
   no site carries forward by copy. Convert every out-of-scope catch to a
   consumer, a propagation, a shared-handler call or a host-test reporter.
3. Unify terminal escrows on the shared handler (section 2.5), with a
   source-bound call-site binding and an integration control that exercises the
   actual callback path for every caller.
4. Implement C1-C8 for in-scope sites and the four outcome kinds, with
   per-protocol adapters. C8 applies to every consumer and reporter, not only
   to in-scope sites.
5. Close the r28 majors: static-gate evasion is replaced by a runtime
   acceptance control, `native_site` stamping, forwarding context loss, and the
   `str(error)` consumer check. Fold in the `stage_common` boot-polling minor.
6. Fold in task 69 only if it touches `r21_checks.py`.
7. Seal `CONTRACT.md` through the actual manifest and bind it to this approved
   text.
8. Pass independent review by a different model before any readiness probe.

Approval of this document settles scope only. It is not a fitness verdict, not
authorization for a readiness probe, and not authorization to arm or touch the
device.
