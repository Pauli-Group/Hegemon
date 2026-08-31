# SmallWood complete-ZK and PQ128 gate

This directory retains the fail-closed security evidence for a rejected V6
SmallWood candidate.  The architecture tournament source-disqualified its
Boolean adapter: at least 1,258,569 hash-only rows imply a 75,589,554-byte
inner-proof lower bound, and the resulting matrix columns exceed the `SMZ2`
wire's `u16` limit before non-hash logic or ZK repair.  The checked-in candidate
is deliberately not authorized:

```sh
python3 .agent/hardening/smallwood-pqc-zk/strict_profile.py \
  --profile .agent/hardening/smallwood-pqc-zk/target-profile.json \
  --certificate .agent/hardening/smallwood-pqc-zk/candidate-certificate.json \
  --trust-root .agent/hardening/smallwood-pqc-zk/trust-root.json
```

Exit status `0` means every required receipt is pinned and both derived
capabilities pass.  Status `2` means the inputs are valid but authority remains
false.  Status `1` means an input is malformed or unsafe.  The checker never
accepts candidate-provided `complete_zk`, `pq128`, or
`production_authorized` booleans.

## Exact protocol audited

The production SmallWood core in
`circuits/transaction/src/smallwood_engine.rs` is an LPPC/PACS polynomial IOP
compiled through LVCS and DECS to a Merkle polynomial commitment.  All
algebraic challenges are in the Goldilocks prime field

```text
q = 2^64 - 2^32 + 1 = 18446744069414584321.
```

The active parameter tuple is

```text
rho = 5                     PIOP openings = 5
beta = 2                    PIOP proof-of-work bits = 0
DECS domain = 2^20          DECS openings = 23
DECS eta = 5                DECS proof-of-work bits = 0
packing factor = 64
```

The compressed Level-5 Rust path selects `Sha512Level5`.  Merkle leaves,
nodes, roots, transcript digests, and transcript expansion use the full
64-byte SHA-512 output with distinct domains.  There are four physical
Fiat-Shamir challenge families:

1. the uniform DECS coefficient matrix derived after the Merkle commitment;
2. the uniform PIOP constraint-coefficient matrix;
3. five distinct PIOP opening points outside the 64 packing points; and
4. 23 fixed-sampler DECS query positions.

The PIOP nonce is the verifier-recomputed first valid nonce and is capped at 16
trials.  The DECS sampler has no prover-selected nonce: it takes the first 23
distinct in-range indices from exactly 50 transcript candidates.  A stale Rust
comment still says 40 candidates and 20 openings; the executable constants and
active profile are 50 and 23.  Both proof-of-work fields are zero.  These rules
remove prover grinding, but their abort-conditioned distributions still have
to be covered by the ZK simulator and QROM reduction.

The canonical Level-5 proof encoding exact-consumes, in order, the wire magic,
32-byte salt, four-byte PIOP nonce, 64-byte `h_piop`, nonlinear quotient high
coefficients, linear-mask high coefficients, LVCS combination tails, DECS
subset evaluations, partial witness evaluations, 23 Merkle authentication
paths, DECS masking evaluations, DECS high coefficients, and the opened-witness
bundle (row scalars plus any auxiliary words).  The decoder rejects trailing
bytes.  Every one of those correlated fields is part of the ZK and extraction
view; none may be omitted from a simulator because it is described as
"auxiliary."

For the currently formalized 699-row, 890-constraint Poseidon-era geometry,
the checked interactive error terms in
`formal/lean/Hegemon/Transaction/SmallWoodNoGrindingSoundness.lean` are

```text
epsilon_1 = 1 / q^5
epsilon_2 = 1 / q^5
epsilon_3 = falling(544, 5) / falling(q - 64, 5)
epsilon_4 = falling(397, 23) / falling(2^20, 23).
```

Their sum is approximately `2^-262.3777366177`.  The exact rational ideal-CMS
envelope in the existing formal model is

```text
12 t^2 epsilon + 48 t^3 / 2^512 + 2 k^2 / 2^512,
```

with global quantum-query budget `t` and base-game arity cap `k`.  At the
conservative `k = 2^20`, it is approximately `2^-130.7927741170` at
`t = 2^64` and `0.1443082697904` at `t = 2^128`.  Those are ideal logical-oracle
figures, not deployed SHA-512 security results.  The conventional-hash
relation changes the production geometry, so its row count, constraint count,
effective degree, discrepancy degree, LVCS width, and arity cap remain `null`
until measured and source-bound.

## Strict finite-QROM composition

The machine-checked `security_accounting` object in `target-profile.json` fixes
the complete ideal ledger instead of treating the omitted terms as negligible:

```text
q_low = 2^64                 q_work = 2^128
relation hash = SHAKE256-448  79 relation-hash targets
transcript = SHA-512-512      11,574 worst-case physical requests
CMS Fiat-Shamir factor = 12   CMS transcript factor = 48
PCS oracle bridge factor = 2  global history multiplier = 1
PIOP nonce trials = 16        DECS candidates = 50
opening/decs grinding bits = 0
```

For each global query budget `t`, the strict checker sums the active
PCS/IOP/DECS error amplified by `12*t^2`, the 512-bit CMS collision and PCS
oracle-bridge terms, exact canonical-PIOP and fixed-first-distinct DECS
sampler-exhaustion probabilities, the relation-hash union
`4*79*t^3/2^448`, and the transcript-request union
`4*11574*t^3/2^512`.  The grinding and independent per-proof history terms are
explicitly zero only because the profile binds both proof-of-work fields to
zero and uses one global budget; changing either premise rejects the profile.
The resulting ideal finite ledger is approximately `2^-130.7927741170` at
`t = 2^64` and `0.1443082698` at `t = 2^128`, so both declared arithmetic gates
pass with margin.

This is a checked parameter bound, not a deployed security certificate.  The
checker still requires independent machine-checked receipts for the complete
serialized-view simulator, compiled prover/verifier refinement, SHA-512 and
SHAKE concrete-QROM reductions, canonical relation refinement, global
composition, and independent review.  Until those receipts exist,
`complete_zk`, `pq128`, and `production_authorized` remain false.

The rejected target used SHAKE256-448 because the generic quantum
collision scale `t^3 / 2^448` remains about `2^-256` at `t = 2^64` and
`2^-64` at `t = 2^128`.  A 384-bit digest has the boundary exponent
`384 / 3 = 128` and no composition margin.  These generic scales are only
parameter screens; the `relation_hash_security` receipt must bind the actual
domain grammar, number of targets, collision/preimage definition, constants,
and global composition.

The strict relation identity is circuit 6, crypto suite 5, family 1, action 8,
backend 2, profile 2, and domain set 1, with statement magic `HGF6ST01`,
semantic tag `HEG-F6V1`, and `SWV6` envelope version 1.  The canonical statement
is exactly 893 bytes and is encoded losslessly as 128 seven-byte little-endian
Goldilocks limbs; the final three transport bytes must be zero padding.  Raw
chain id, genesis id, and rules hash are each 56 bytes.  Intent and balance
SHAKE computations remain inside the relation rather than becoming
verifier-derived public fields: the exact intent payload is 725 bytes, its
framed input is 744 bytes.  Both exact 2,147-byte ciphertext-hash payloads are
also constrained inside the proof (2,182-byte frames, 17 permutations each),
so the complete semantic schedule is 79 SHAKE256 invocations / 124
Keccak-f[1600] permutations.  Any 853-byte/122-limb, 77-call/90-permutation, or
host-ciphertext-hash profile is a different rejected relation.

## Zero-knowledge status

The Rust prover already samples all of the following hiding material:

- five random high coefficients on each interpolated witness polynomial;
- one random nonlinear quotient mask for each of the five repetitions;
- one random zero-sum linear mask for each repetition;
- LVCS row rerandomization;
- five DECS masking polynomials; and
- a 32-byte random salt for Merkle-domain randomization.

That construction is not zero knowledge as serialized today.  The retained
radix-2 DECS domain contains field point `64` at leaf index `163840`; after the
23-coordinate LVCS random-prefix rotation, point `64` is actual committed
column `41`.  If that fixed leaf is among the 23 queries (exact probability
`23 / 2^20`, greater than `2^-16`), the proof's subset evaluations expose
polynomial coefficients `5..68`.  The five ordinary PIOP openings then form a
full-rank Vandermonde system for coefficients `0..4`, recovering all 69
coefficients and all 64 packed witness values.  Run the dependency-free
certificate with:

```sh
rustc --edition=2021 --test \
  circuits/transaction/examples/smallwood_zk_domain_audit.rs \
  -o /tmp/smallwood_zk_domain_audit_tests
/tmp/smallwood_zk_domain_audit_tests
```

The engine now contains an inactive `Radix2DisjointCoset` implementation.  It
deterministically selects the first multiplicative coset avoiding every LVCS
interpolation point; the retained 398-point geometry selects shift `398` and
adds no proof bytes.  The prover and verifier keep sampled Merkle leaf indexes
separate from the corresponding algebraic coset points.  Historical `SMW1`,
`SMW2`, and `SMW3` bytes retain their old interpretation.

The retained Merkle-leaf preimage has a second theorem mismatch.  It binds the
public global salt and evaluations, but omits both the leaf index and the
independently random per-leaf tape used by the published DECS ROM simulator.
The inactive inner `SMZ1` research wire gives the historical-`Sha512Level5`
repair a distinct identity: the prover samples a 64-byte tape for every one of the `N` committed
leaves, hashes the exact leaf index and tape with the committed and masking
evaluations, and serializes exactly 23 opened tapes (1,472 bytes).  Its parser
and serializer reject any other opening/tape count and trailing bytes.  A
32-byte tape is disqualified: its generic
QROM-guessing scale `Q_H^2 / 2^256` reaches one at `Q_H = 2^128` before
constants or union terms, whereas the 512-bit target leaves roughly `2^-256`
at that query count.  `SMZ1` can never be reinterpreted as V6; the reserved
fresh identity is `SMZ2`, paired only with `Sha512V6` and the disjoint-coset
domain.  Neither is an active frontend/consensus profile, and this necessary
framing supplies no capability without a whole-proof simulator and compiled
refinement.

Even after both repairs, no audited theorem constructs one simulator for the
complete serialized view: correlated PIOP messages, opened randomized witness
evaluations, LVCS combinations, DECS high coefficients and masks, Merkle leaves
and paths, proof length, the canonical PIOP nonce, fixed-sampler exhaustion,
and repeated adaptive proofs.  Salt alone does not prove hiding.

`joint-simulator-design.md` records the exact implementable construction
boundary.  In particular, the 23 LVCS random tail values act on 23 distinct
disjoint-coset openings through a full-rank Cauchy matrix, and the DECS mask
representation can be simulated conditionally from those values.  The
dependency-free `smallwood_piop_zk_audit.rs` additionally checks the exact
local PIOP affine reconstruction: witness openings have rank `5/5`, nonlinear
mask views have full rank through the V6 degree-5 case (`277/277`) and engine
degree-8 ceiling (`481/481`), the degree-131 zero-sum linear view has rank
`131/131` for the checked nonzero correction factor, and PCS partial tails are
free coordinates.  It also constructs the exact distinct non-packing points
`[1000, 1001, 1002, 1003, 9145141821497892284]`, whose correction factor is
zero: the historical prover predicate accepts them while the verifier rejects
the view.  It prints `whole_proof_simulator=false` and
`complete_zk=false`: fresh V6 SHA-512 binding, joint commitment/Merkle
correlations, abort-conditioned Fiat--Shamir/QROM lifting, compiled
distribution refinement, and independent review remain explicit blockers.

The whole-proof simulator was not built after the size and wire gates failed.
These audits remain regression and negative evidence for a future
Boolean-native architecture; they do not make the current adapter viable.

The minimum acceptable statement is a joint simulator for every valid public
statement whose output is identical or quantitatively indistinguishable from
the production prover's complete accepted proof distribution, including
conditioning on all rejection/abort events.  It must then be lifted through
the four-round Fiat-Shamir transform in the QROM under one global query budget,
with an explicit compiled-prover distribution refinement, a production RNG
refinement, and a quantitative distinguishing bound at both `2^64` and
`2^128` quantum queries.  If the existing masks satisfy that argument, the
proof itself needs no additional bytes.  Until the theorem is complete, any
required protocol overhead is unknown rather than zero.

## Soundness and proof-of-knowledge status

`SmallWoodCmsQrom.lean` and `SmallWoodBcsQrom.lean` account for an ideal
logical oracle and caller-supplied losses.  They do not instantiate deployed
SHA-512 or SHAKE256, prove that arbitrary accepted Rust bytes construct the
modeled transcript, or compose all blocks, prior proofs, Merkle targets, and
relation hashes.  `SmallWoodDeployedQromBridge.lean` exposes these obligations
but does not discharge them.  `SecurityAuthority.lean` therefore has no valid
deployed-end-to-end constructor.

PQ128 promotion additionally requires round-by-round extraction, PCS/Merkle
binding to one oracle, a noninteractive proof-of-knowledge extractor for the
exact accepted bytes, canonical-transaction relation refinement, exact parser
and verifier refinement, global adaptive multi-target accounting, conventional
hash instantiation bounds, and independent review.  An interactive error
calculation cannot substitute for any of these receipts.

## Evidence format and trust boundary

Every evidence item has a checker-owned claim, allowed evidence kinds, and
capability mapping in `strict_profile.py`.  A qualifying receipt must:

- be marked `verified` in the candidate certificate;
- hash to a digest independently listed for that evidence id in the trust root;
- use the exact profile, evidence id, claim, and `deployed-end-to-end` scope;
- be machine checked, non-assumption-only, and have exit status zero;
- bind at least one repository-relative, non-symlink artifact by SHA-256; and
- supply exactly the quantitative claims required by policy.

The trust-root file is a review input, not a signature.  A production or CI
caller must pin and review it outside candidate control.  Editing both a local
certificate and a locally selected trust root is not independent review.

The checker derives the four interactive terms and the CMS envelopes with
exact rational arithmetic.  `complete_zk` requires every ZK receipt and both
numeric ZK gates.  `pq128` also requires every soundness, extraction,
implementation, hash, composition, identical-byte, and review receipt plus:

```text
total advantage <= 2^-128 at a global 2^64 quantum-query budget;
total success    <  1/2    at a global 2^128 quantum-query budget.
```

The checked-in empty trust root and negative candidate preserve the honest
current result: `complete_zk = false`, `pq128 = false`, and
`production_authorized = false`.
