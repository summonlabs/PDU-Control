# PDU Control

Vendor-neutral lifecycle and safe control semantics for power distribution units
and branch circuits.

**The core question.** Given authoritative permission and current evidence, what
PDU or branch-circuit state transition may be attempted, under which limits and
interlocks, and how do we prove whether the requested effect actually occurred
without confusing acknowledgement with physical state?

PDU Control answers that question and nothing else. It adjudicates control. It
does not decide who may control, how much power a facility has, or which load
should be shed.

## Systems boundary

**This runtime owns**

* stable PDU and branch-circuit identities, with device generation separated from
  state revision;
* branch lifecycle (provisioned, active, maintenance, degraded, isolated,
  faulted, retired) with an explicit transition table;
* commanded state and observed state as separate values, and a third, verified
  state established only from fresh evidence;
* exact-integer limit metadata with provenance, enforced with checked
  arithmetic;
* telemetry observations with source, sequence, clock domain, quality, freshness,
  and explicit unknown;
* permission and interlock references issued by the layer that owns them;
* operation attempts: desired transition, preconditions, adapter command,
  acknowledgement, observed effect, verified effect, failure, cancellation,
  supersession, and the idempotency that makes a retry safe;
* durable, integrity-checked persistence of all of the above, with crash and
  rollback semantics;
* one narrow vendor adapter interface.

**This runtime does not own** facility-wide Power Control Plane policy, power
topology, feed authority, UPS or generator control, power-capacity derivation,
load-shedding policy, or the energy ledger. It consumes permissions, interlocks,
and capacity limits from those systems as references, and it never reproduces
their policy engines. It never derives a limit; it enforces the limit it was
given, and reports that the limit is unknown when it was not given one.

## The rule this library exists to enforce

An acknowledgement is not an effect. A command object is not physical actuation.
Telemetry is not authority. A value that was recovered from disk is not current
evidence. Zero is not unknown, and "unsupported" is not "unavailable".

Every one of those statements is a separate, testable state in this library:

| concept | where it lives | what it means |
|---|---|---|
| permission | `PermissionGrant` | an epoch-scoped, generation-scoped, expiring reference from the owning authority |
| authorisation | `ActuationAuthorization` | proof, constructed only by the engine, that every precondition was validated |
| command | `AdapterCommand` | what was handed to an adapter; not an effect |
| acknowledgement | `AdapterOutcome` | what the adapter said; not an effect |
| observation | `TelemetryObservation` | what a source reported, with quality and freshness |
| verified effect | `VerifiedEffect` | what a *fresh* observation established after a command |

## Architecture

    include/pdu_control/    the public API (13 headers)
    src/                    the implementation
    src/detail/             the codec, CRC, file, path, process, store, and
                            serialization layers
    tools/pdu_cli.cpp       the pdu-control administration tool
    examples/               five runnable scenarios
    bench/                  the completed-operation benchmark
    tests/                  the proof-obligation suite
    downstream/consumer/    an out-of-tree find_package consumer
    docs/artifact-format.md the durable byte format

The public surface is strongly typed: identities, generations, epochs,
incarnations, revisions, ticks, sequences, and attempt ordinals are distinct
types, and none of them is a generic integer. The engine is a pimpl, so the
header stays stable and the mutable state stays private.

### Lifecycle

Seven states, twenty-three declared transitions, no others. `active` and
`degraded` permit control; `maintenance` permits it only with an explicit,
scoped, expiring maintenance override; `provisioned`, `isolated`, `faulted`,
and `retired` refuse it. `retired` is terminal. Every transition names a class
(commission, service, recovery, administrative, fault) and the class decides which
permission action the caller must hold — the action is never inferred from the
state names.

A branch on a PDU whose lifecycle forbids control is refused even when the branch
itself is active.

### Deterministic validation precedence

The primary code returned for an invalid request is a function of the request and
the current state, in this order:

1. request shape — `invalid_argument`, `out_of_range`, `overflow`
2. idempotent replay — the retained result, or `idempotency_conflict`
3. identity resolution — `not_found`, `duplicate_identity`
4. identity binding — `identity_mismatch`
5. lifecycle gate — `lifecycle_forbidden`, `transition_invalid`
6. unresolved attempt — `attempt_unresolved`
7. device generations — `generation_mismatch`
8. state revision — `revision_mismatch`
9. authority epoch — `permission_stale`
10. permission — `permission_missing`, `permission_stale`, `permission_denied`
11. interlock — `interlock_open`, `interlock_unknown`
12. limits — `limit_invalid`, `limit_exceeded`
13. adapter — `adapter_refused`, `adapter_unavailable`, `adapter_fault`,
    `adapter_fenced`

Step 2 deliberately precedes steps 7 and 8: a retry of an already accepted
attempt returns the prior accepted result rather than being refused because the
branch moved on in the meantime. A retry that repeats the same request under the
same key replays; the same key with a different request is a conflict.

The trace of every check is returned with the decision, so a refusal always names
the precondition that produced it.

### Authority, generations, and fencing

Every mutation states the authority it was planned against and refuses stale
authority rather than merging it:

* **device generation** — a PDU generation and a branch generation, independent
  of each other, both required on every request;
* **state revision** — bumped by every accepted mutation; required for lifecycle
  and limit changes, optional but honoured for control commands;
* **authority epoch** — adopted explicitly, monotonic; adopting an older epoch is
  refused, because that would silently re-authorize withdrawn grants;
* **store generation** — the monotonic fence of the durable publication;
* **incarnation** — allocated on every successful open, so a writer that was
  thought to be dead can be told apart from its successor;
* **attempt id, observation id, adapter sequence, audit sequence** — four
  independent ordinals, never interchangeable.

Interlocks fail closed. A protected obligation that is open blocks control; one
that cannot be established at all blocks control as unknown; a protected
obligation that was required but never declared blocks control as unknown. A
report from another epoch is not current, and an out-of-order report is refused
rather than allowed to walk the obligation backwards.

Limits are enforced with checked integer arithmetic in exact fixed units. A
negative or inverted limit is `limit_invalid`. A projected load against an
unknown limit is refused: missing evidence is never permission.

### Acknowledgement, effect, and idempotency

An attempt is a durable record. It is written, and published, **before** the
command leaves for the adapter. That record is the durable command-attempt
boundary: a process that dies immediately after dispatch leaves behind a record
that says a command may have reached the branch, and recovery adopts it as
`recovery_required` without ever re-sending it. A branch whose attempt has no
established effect refuses new control until the effect is established from fresh
evidence or the attempt is explicitly resolved.

The desired state is written at the same boundary, which is the conservative
direction: after a crash the record claims "this branch was asked for this
condition and may already be in it", not the reverse. When an adapter states that
it refused or could not attempt the command, that desired state is repaired,
because the adapter has said something definite about the outcome.

Verification needs evidence that is *fresh*, of *good* quality, from the *current*
device generation, and *ordered after* the command. An observation qualifies only
when it was measured at or after the command instant and accepted strictly after
it. A read-back through an adapter is recorded as evidence like any other and is
never verification by itself.

### Idempotency retention

The idempotency window retains the most recently accepted attempts, bounded by
`EngineOptions::idempotency_window` (default 256, hard bound
`ModelBounds::max_idempotency_window`). Refused requests are journalled but not
retained: a refused request is not an accepted attempt, and re-sending it
re-evaluates against current state. Eviction is observable — a retry whose key has
been evicted is a new request and is evaluated as such. The attempt journal bound
is raised to at least the window size, because a retained key must always name an
attempt the journal still holds; the window is persisted, so a retry after a
restart replays the prior result instead of actuating again.

## Persistence and recovery

The store is a dual-slot, head-committed container with CRC-32C over every
record, an explicit format version, and a documented byte layout. The full
description is in [docs/artifact-format.md](docs/artifact-format.md).

Publication: plan, reserve the generation, stage the payload into the slot the
head does not reference, flush, read back and verify, **then** write the head
record that names it and flush. The commit point is that head write. Nothing
before it is authoritative.

Recovery adopts the valid head record with the largest serial and verifies its
payload in full; generations are never stitched together. A store whose committed
payload does not verify, or whose head records are both unreadable, is refused
rather than repaired. If the newest head record is unreadable — which is what a
torn head write looks like — the previous whole generation is adopted, and that
is a rollback: a caller that requires monotonic authority arms
`min_store_generation` and gets `rollback_detected`.

Every structure in the file is bounded before it is allocated, counts are checked
against the bound that applies to them, text lengths are bounded, and a decode
that does not consume the payload exactly is refused. The decoder performs
referential integrity checks, so an internally inconsistent store is refused
rather than loaded and repaired.

Cross-process write authority is a real operating-system lock on a sidecar file,
held for the engine's lifetime. The operating system releases it when the process
dies, which is what the multiprocess tests exercise. Every publication re-reads
the head first and refuses to overwrite a generation it never saw.

### What survives a restart, and what does not

Recovery never reissues a command, never promotes recovered telemetry to fresh
evidence, and never invents a verified state. The desired state, the verified
state, the attempt journal, the idempotency window, permissions, interlocks,
limits, lifecycle, the authority epoch, and the audit ring all survive. Telemetry
comes back marked `recovered` and is stale until a fresh reading revalidates it.

## Concurrency and lock order

An engine instance is not internally synchronized: one instance is used by one
thread at a time. There is exactly one lock in this library — the operating-system
file lock of a durable store — and:

* it is acquired once, at open, and released at close;
* it is never reacquired on any call path, so there is no read-to-write upgrade,
  no re-entry through a callback or helper, and no nested acquisition;
* the engine holds no mutex at all, so no internal lock can be held across an
  adapter call, a filesystem operation, or a clock;
* it is deliberately held across adapter calls, because a second process must not
  interleave commands with this one, and no code reachable from an adapter can
  acquire it;
* a second opener is refused with `busy`, and the operating system releases the
  lock when the holder dies.

The library never reads the system clock. Time is a logical tick supplied by the
caller, wall-clock instants are audit decoration supplied by the caller, and
control decisions are taken against logical ticks only.

## Canonical state and determinism

`PduControlEngine::canonical_state()` renders the authoritative model as
deterministic text and `state_digest()` digests it. Two engines driven through
the same logical event sequence produce byte-identical text regardless of when
they ran, which process ran them, or how many times they published. Excluded by
construction: wall-clock instants, engine incarnation, store generation, open
count, audit sequence numbers, engine open/close audit entries, and the derived
freshness label. Included: every identity, generation, revision, lifecycle state,
limit, permission, interlock, observation fact, attempt, and idempotency entry.

## Safety posture

This library models decisions that would be safety-critical if connected to real
electrical equipment, and it keeps that boundary explicit. It never claims
physical actuation because a command object was created or an adapter
acknowledged receipt. It contains no vendor credential, no network endpoint, and
no secret. It performs no autonomous external control outside the documented
adapter boundary. Interlocks and protected obligations fail closed. An adapter
cannot bypass core precondition validation: the command type and its authorisation
token are constructible only by the engine, an adapter outcome that does not echo
the command it answers is fenced, and an adapter is never invoked at all when a
precondition fails.

Every control result produced in this repository comes from a deterministic
synthetic adapter and is labeled **SYNTHETIC**. No hardware was used. The
examples, the tool, the benchmark, and the tests all say so in their output.

## Command line

```sh
pdu-control init --store site.pdustore --pdu pdu-1 --generation 1 --lifecycle active
pdu-control epoch adopt --store site.pdustore --epoch 1
pdu-control branch add --store site.pdustore --pdu pdu-1 --branch br-1 --generation 1 \
    --lifecycle active --continuous-mA 16000 --limit-issuer power-capacity \
    --limit-authority cap-1 --limit-epoch 1 --interlock site-safe
pdu-control interlock declare --store site.pdustore --interlock site-safe --pdu pdu-1 \
    --branch br-1 --class protected --epoch 1 --tick 1
pdu-control interlock report --store site.pdustore --interlock site-safe --state satisfied \
    --epoch 1 --tick 1
pdu-control grant add --store site.pdustore --grant g1 --issuer power-control-plane --epoch 1 \
    --pdu pdu-1 --branch br-1 --pdu-generation 1 --branch-generation 1 \
    --actions control_energize,control_de_energize --issued 1
pdu-control observe --store site.pdustore --pdu pdu-1 --branch br-1 --pdu-generation 1 \
    --branch-generation 1 --source field --sequence 1 --tick 1 --condition de_energized
pdu-control tick advance --store site.pdustore --tick 5
pdu-control evaluate --store site.pdustore --pdu pdu-1 --branch br-1 --intent energize \
    --epoch 1 --pdu-generation 1 --branch-generation 1 --key k1 --tick 5
pdu-control issue --store site.pdustore --pdu pdu-1 --branch br-1 --intent energize --epoch 1 \
    --pdu-generation 1 --branch-generation 1 --key k1 --tick 5 --verify
pdu-control inspect --store site.pdustore --pdu pdu-1 --branch br-1
pdu-control attempts --store site.pdustore
pdu-control verify --store site.pdustore --attempt 1 --read-back
pdu-control revalidate --store site.pdustore --pdu pdu-1 --branch br-1 --pdu-generation 1 \
    --branch-generation 1 --source field --sequence 50 --tick 9 --condition energized
pdu-control history --store site.pdustore --limit 20
pdu-control store-audit --store site.pdustore
```

Verbs: `init`, `inspect`, `branch add|show|limits|enable|disable`,
`lifecycle set`, `evaluate`, `issue`, `attempts`, `verify`, `revalidate`,
`observe`, `history`, `store-audit`, `epoch adopt`, `tick advance`,
`grant add|revoke`, `override add`, `interlock declare|report`, `resolve`.

Every invocation opens the store, performs one verb, and closes, so the recovery
path runs on every command. Exit code 0 is success, 1 is a refusal (with
`error: <token>: <message>`), and 2 is a usage error — a caller can tell "ask
again with a well-formed command" from "the request was understood and refused".
`--json` prints one compact JSON object instead; `--store` may be omitted to run
against an in-memory engine with no durability.

## Library use

```cpp
#include <pdu_control/engine.hpp>
#include <pdu_control/synthetic_adapter.hpp>

using namespace pdu_control;

EngineOptions options;                       // every bound is explicit
options.evidence.max_age_ticks = LogicalTick::from(1000);

auto opened = PduControlEngine::open("site.pdustore", OpenMode::open_or_create, options);
if (!opened.ok()) { /* the status names the reason */ }
PduControlEngine& engine = opened.value();

BranchControlRequest request;
request.key = IdempotencyKey::parse("enable-1").value();
request.pdu = PduId::parse("pdu-1").value();
request.branch = BranchId::parse("br-1").value();
request.pdu_generation = PduGeneration::from(1);
request.branch_generation = BranchGeneration::from(1);
request.epoch = AuthorityEpoch::from(1);
request.intent = CommandIntent::energize;
request.actor = ActorId::parse("operator-1").value();
request.requested_at = LogicalTick::from(5);

const Decision decision = engine.evaluate(request).value();
if (decision.eligible) {
  const AttemptRecord attempt = engine.issue(request, adapter).value();
  // The acknowledgement is an acknowledgement; the effect is whatever fresh
  // evidence later establishes.
  const VerificationResult verified = engine.verify_with_adapter(attempt.id, adapter).value();
  if (verified.effect == EffectState::effective) { /* established */ }
}
engine.close();
```

### The vendor adapter interface

```cpp
class PowerAdapter {
 public:
  virtual AdapterDescriptor describe() const = 0;
  virtual AdapterOutcome execute(const AdapterCommand& command) = 0;
  virtual Result<TelemetryObservation> read(const AdapterReadRequest& request) = 0;
};
```

That is the whole boundary. No vendor type, header, error code, or transport
appears in this library. An adapter receives an already-authorised command and
answers with a disposition plus, optionally, a reading. It cannot fabricate a
command, cannot widen the preconditions the engine validated, and cannot have its
answer attributed to a command it was not given.

## Package consumption

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix /some/prefix
```

The install exports `PDUControl::pdu_control`, a `PDUControlConfig.cmake`
package, the public headers, and the license files. An out-of-tree consumer
configures against it with `find_package(PDUControl 1.0 REQUIRED)`; the consumer
in `downstream/consumer` is exactly that, and it is built and run by the
`pdu_test_downstream_install` check and by the release verification below.

## Examples

Five runnable programs, each an executable check rather than a demonstration;
each exits non-zero if its expectation does not hold.

| example | what it proves |
|---|---|
| `branch_control` | a safe enable and disable through a synthetic adapter, and that the canonical state survives a close and reopen |
| `stale_permission` | four stale-authority paths — another epoch, an older device generation, an expired grant, a revoked grant — each refused with its own code, with the adapter never invoked and the authoritative state unmoved |
| `ack_without_effect` | an adapter that acknowledges and changes nothing: the acknowledgement is recorded as an acknowledgement, and fresh evidence then establishes the opposite condition |
| `revalidation` | an effect that exists but whose telemetry is stale: verification refuses with `evidence_stale`, and a revalidated reading is what makes verification possible |
| `crash_reopen` | a real process death inside the adapter call, after the durable command-attempt boundary: recovery adopts the attempt, a retry of the same key replays without reaching an adapter, and a new key is refused until the effect is established |

## Validation

Everything below was run in this repository. Nothing is aspirational.

**Build matrix (Windows 11, MSVC 19.44.35222, CMake 4.3.2, x64).**

| configuration | result |
|---|---|
| Release, `/W4 /WX /permissive- /utf-8 /Zc:__cplusplus` | clean, no warnings, all targets |
| Debug, same warnings | clean, no warnings, all targets |
| Release with AddressSanitizer (`/fsanitize=address /Zi`) | clean build; the full test suite passes under ASan with no report |

The sanitizer configuration is enabled with `-DPDU_CONTROL_ENABLE_ADDRESS_SANITIZER=ON`.
The ASan runtime is a dynamic library that ships with the MSVC toolset, so the
tests must be run from a developer environment that matches the toolset the build
used; running them from a shell without it fails with a missing-DLL status rather
than a sanitizer report. Debug information is emitted with the sanitizer so that a
report would be usable.

**Test suite.** Eighteen CTest tests: thirteen library suites carrying 2,991
individual checks across 88 test cases, and five example programs that fail their
exit status when an expectation does not hold. A test that performs no check at
all is itself reported as a failure, so a suite cannot pass vacuously. The
structural obligations are the ones the suites are built around —
identity and checked arithmetic; the lifecycle transition table; permission and
interlock currency; telemetry provenance and freshness; control semantics
(acknowledgement versus effect, determinism of the refusal precedence, no
mutation on refusal); idempotency and its bounded window; adapter fencing;
persistence and corrupted-store refusal; crash recovery; real multiprocess
exclusion, process-death lock release, and stale-writer fencing; a seeded
randomized state machine with an independent reference model of the control gate;
adversarial parser, path, and store attacks; and the command line tool end to end.

**Real multiprocess and crash evidence.** The suite starts real child processes.
A child dies inside the adapter call, strictly after the durable
command-attempt boundary, and the parent proves that recovery adopts the
attempt as `recovery_required`, that a retry of the same key replays without an
adapter call, and that a new key is refused with `attempt_unresolved`. Another
test holds the store from a separate process, proves the second opener is refused
with `busy`, kills the holder with an operating-system termination, and proves
the lock is released and the store is still whole. A third forges a head record
out of band and proves the writer is fenced rather than allowed to overwrite a
generation it never saw.

**Install, export, downstream.** The package installs to a clean prefix, and an
independent out-of-tree consumer configures against it with `find_package`,
builds, and runs a full lifecycle: register, authorise, observe, evaluate, issue,
verify, close, reopen. It reports `effect=effective`, and confirms after reopening
that the verified state and the attempt journal survived.

**Benchmark.** `pdu_bench_control` measures completed operations only. The timed
operation is one whole accepted control command through a durable store: request
validation, precondition evaluation, encoding of the entire model, staging write,
flush to the device, read-back verification, head publication, and the head commit
flush, plus the adapter call and the verification step that follows it. The
workload is printed with the result, and the state is verified before the result
is reported.

```
workload operations=200 branches=8 repetitions=5
configuration audit-capacity=64 idempotency-window=64
label store=REAL adapter=SYNTHETIC (no hardware is driven)
run=0 completed=200 seconds=3.4132 operations-per-second=58.5961 publications=1000 state-verified=true
run=1 completed=200 seconds=3.4645 operations-per-second=57.7284 publications=1000 state-verified=true
run=2 completed=200 seconds=3.4403 operations-per-second=58.1344 publications=1000 state-verified=true
run=3 completed=200 seconds=3.40304 operations-per-second=58.7709 publications=1000 state-verified=true
run=4 completed=200 seconds=3.44713 operations-per-second=58.0193 publications=1000 state-verified=true
summary statistic=median-and-mean median-operations-per-second=58.1344 mean-operations-per-second=58.2498
```

The durable store path measured here is **REAL** file and device I/O. The adapter
is **SYNTHETIC**: it is a deterministic simulator that drives no hardware. Each
completed operation includes five publications — the acceptance, the adapter
outcome, the read-back observation, the verification, and the verification's
observation — because each of those is a separate durable fact and none of them
belongs outside the measurement. No before/after comparison is published: the
methodology does not isolate a changed variable, so only the current measured path
is reported.

## Remaining limitations

* **No hardware validation.** No physical PDU was available, and none was used.
  Everything in this repository is verified against deterministic synthetic
  adapters. The vendor boundary, the fencing, and the persistence semantics are
  designed for real integrations, but no real integration has been exercised
  here. Nothing in this repository is hardware evidence.
* **The POSIX branch is unverified.** `src/detail/file_io.cpp` and
  `src/detail/path.cpp` contain a POSIX implementation of the file, lock, and
  path primitives, and the build selects it on non-Windows hosts. It is written to
  the same contract, but it could not be compiled or run in this environment, so
  it is documented as unverified rather than claimed as portable.
* **An engine instance is single-threaded.** There is no internal locking. Two
  threads sharing one engine instance is a programming error, not a supported
  configuration. Cross-process safety is real, via the store lock.
* **Rollback after head destruction is possible, and is the caller's to fence.**
  A head record that is present but unreadable is indistinguishable from a torn
  head write, so the store adopts the previous whole generation. A caller that
  needs monotonic authority must arm `min_store_generation`; the fence is not
  armed by default because a caller recovering from a crash usually wants the
  store to come back.
* **CRC-32C is corruption detection, not authentication.** An attacker with write
  access to a store can rewrite its contents and its checksums. Nothing in the
  file is secret, and the format is not a defence against that adversary.
* **The idempotency window is bounded and evicts.** A retry whose key has been
  evicted is a new request. The bound is configurable and its retention semantics
  are documented above; there is no unbounded history.
* **The audit ring is bounded and drops.** The oldest entries are dropped when
  the ring is full, and the drop count is reported rather than hidden.
* **A policy engine is not present, by design.** This runtime cannot tell you
  whether a branch *should* be energized. It can only tell you whether the
  authority, evidence, limits, and interlocks you supplied permit the transition,
  and whether the effect was established.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
