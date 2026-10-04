# Bind accepted hash traces to their actual source constraints

This is a living ExecPlan following `.agent/PLANS.md`; the coordinator owns the
complete-security campaign plan. This lane owns this document and these three
modules in `formal/crypto/HegemonCrypto/`, in dependency order:

- `SmallWoodV8Smz9HashDependencyCertificate.lean`
- `SmallWoodV8Smz9HashRootCertificate.lean`
- `SmallWoodV8Smz9SemanticCryptographicLinks.lean`

## Purpose / Big Picture

The semantic target needs actual note, Merkle, nullifier and authorization
hashes, not an assumed equality between stored wires and primitive outputs.
Start with all 332 hash equations in the exact HGV8RP03 expression graph and
derive their consequences for every accepted packed assignment. The intended
end is the exact primitive and full cryptographic-link conjunction; intermediate
trace facts do not establish that end or any production authority.

## Progress

- [x] (2026-09-07 16:58 UTC) Located all 332 hash roots and checked their
  dependency intervals against the pinned program in an untrusted host probe.
- [x] (2026-09-07 17:32 UTC) Strict-check all 8,271 dependency intervals and
  their assembled certificate in an isolated prefix.
- [ ] Strict-check the linear root-query certificate and its lookup theorem.
- [ ] Prove arbitrary acceptance supplies every hash recurrence and fixes the
  complete trace uniquely once its initial state is fixed.
- [ ] Connect that recurrence to the exact width-16 primitive, then connect
  sponge framing and typed cryptographic families.
- [ ] Run strict Lean checks, axiom audits, and coordinator review.

The initial monolithic check was interrupted after nine minutes when its RSS
reached about 8.85 GiB; it produced no passing result. Data declarations and
checks were then split into 128-node chunks. Import-only probes showed that a
1,536 MiB Lean guard is below the cached dependency chain's baseline, even for
`SmallWoodV8Smz9ProgramPolynomials` alone. The coordinator authorized one
3,072 MiB guarded single-thread check; no return to unbounded checking is allowed.

The dependency-data prefix and all 65 interval certificates, including their
assembly, passed strict checking under that guard. Repeated random lookups in
the 8,271-node list remained expensive even when partitioned. The implementation
now checks the 686 witness nodes and 332 hash equations in one ordered scan,
and proves generically that a successful scan gives the original list lookups.
The scan and root span checks completed under the guard; the first complete
tail run reported only small proof-script errors, which have been repaired and
await the next coordinated check slot. The subsequent whole-module check
terminated at the 3,072 MiB guard without emitting theorem errors. It did not
pass. The coordinator then authorized three maintained modules: dependency
certificate, root certificate, and semantic consequences. This preserves the
same definitions and statements while avoiding retention of every proof's
elaboration state in one process. No assumption has been weakened.

At 17:47 UTC, seven concurrent Lean checks coincided with about 59 MiB free
pages and 11.33 GiB occupied by the memory compressor. This lane has no process
running and waits for a coordinator-granted serialized check. The scratch
prefix cache occupies about 12 MiB, inside the 30 MiB lane bound. The maintained
dependency module is now frozen for coordinator checking and caching. This is actual
aggregate memory coordination, not a reinstatement of the removed disk floor.

## Surprises & Discoveries

The existing `Poseidon2V8ConstraintRefinement` theorem about the permutation
assumes `HashGroupTraceMatches`; it does not derive that structure from packed
acceptance. There is no checked-in module named
`Poseidon2V8HashKernelRefinement` or `Poseidon2V8SourceProgramCSR`. The profile has
125 live permutation calls and three padded calls, sharing two 64-lane groups.
Its 332 hash roots occupy root-list indices 471 through 802 inclusive.

A separate read-only fixture audit found the same 72-addition external-layer
template at 18 source locations. Group-zero bases are 2036, 2252, 2468, 2684,
2900, 4364, 4580, 4796 and 5012; group-one bases are 5100, 5300, 5500, 5700,
5900, 7310, 7510, 7710 and 7910. Initial source nodes are `407+i` and `589+i`;
every later template at base B takes source nodes `B-76+5*i`. Output lane j is
node `B+28+11*(j%4)+[9,8,10,6][j/4]`. This covers 1,296 actual addition nodes.
This host inspection is a map for the missing kernel certificate, not that
certificate itself.

All 300 S-box occurrences also have one shape: if R is a wire root and C its
constant node, `R+1` subtracts C from the actual wire. A node B adds C back;
B+1 squares B, B+2 squares B+1, B+3 multiplies B+1 by B+2, and B+4 multiplies
B by B+3. Goldilocks cancellation and multiplication identify B+4 with the
seventh power of the actual wire once these source lookups are certified.
The existing source replay does not yet include this arithmetic-template proof.

## Decision Log

Use ordinary kernel reduction to validate generated dependency data against
the actual `FieldExpression` constructors. Interpret the graph using the
already proved `fieldAt_refines_source` theorem. Prove uniqueness without
assuming honest lowering, successful typed decoding, hash equality, or a
semantic receipt. Keep any missing primitive correspondence visible.

The replay takes the initial 16 field words as inputs. Those words can be
private; this is not a witness-free privacy simulator. It removes the rest of
the accepted trace from the constructor's inputs so that primitive equivalence
can be proved as a separate, unconditional arithmetic identity.

## Context and Orientation

Group zero has initial rows 283 through 298, pre-S-box rows 299 through 448,
and final rows 449 through 464. Group one adds 182 to every row. An equation
binds each of its 166 constrained rows to an expression involving only the
group's initial rows and earlier constrained rows. The `fieldAt` function is
the actual program's Goldilocks interpretation; its source correspondence was
proved in `SmallWoodV8Smz9ProgramPolynomials.lean`.

## Plan of Work

Create a checked root table, a conservative lower/upper dependency certificate,
and a generic graph-congruence theorem. Derive each accepted recurrence and
use induction on constrained rows to prove trace uniqueness. Then discharge
the separate exact-primitive and sponge-layout correspondence obligations.

## Concrete Steps

Read the cached source and arithmetic modules. Generate only certificate data
from `testdata/formal_core_vectors/poseidon2_v8_relation_program.bin`, whose
parser checks its current 853,429-byte successor size and pinned SHA-512 value.
Apply all local
edits with `apply_patch`. From `formal/crypto`, run:

    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9HashDependencyCertificate.lean
    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9HashRootCertificate.lean
    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticCryptographicLinks.lean

Run in that order, after each dependency is cached by the coordinator. Only
the coordinator owns shared-cache writes and aggregate check-slot scheduling.

Run isolated `#print axioms` checks for the main theorems, retaining only
`propext`, `Classical.choice`, and `Quot.sound` as applicable.

## Validation and Acceptance

Certificates must refer to the exact generated graph and actual root list.
Semantic conclusions must quantify over arbitrary `AcceptsPacked` inputs.
Strict compilation and ordinary-axiom audits are necessary, while the full
primitive/link target and independent review are separate acceptance items.

## Idempotence and Recovery

Edits are additive. Reuse cached Lean 4.32.2, one direct Lean process, no shared
cache writes, and at most 30 MiB source/scratch. No Rust build, git operation,
wire change, node action, publication or production authorization is in scope.

## Outcomes & Retrospective

Implementation and checking are in progress. The source currently contains
the complete recurrence, uniqueness, initial-state-only source replay, and per-call
reconstruction statements; none has yet passed this lane's strict check.
Do not credit the assumed `HashGroupTraceMatches` receipt, or substitute the
new source-DAG replay definition for equality with the exact primitive.

## Interfaces and Dependencies

Import the frozen semantic decoder, program polynomial interpretation and
asset-membership helpers. Do not import the coordinator's changing canonical
witness assembly. The final intended endpoint remains `V8CryptographicLinksValid`;
name and document narrower intermediate theorems precisely.

Revision: opened this source-bound cryptographic-links lane on 2026-09-07 and
recorded the unconstructed primitive-trace boundary found during inspection.

Revision: partitioned both certificate data and kernel checks after stopping
measured excessive memory growth; recorded failed import-only guards and the
coordinator-authorized bounded retry. No mathematical premise was relaxed.
