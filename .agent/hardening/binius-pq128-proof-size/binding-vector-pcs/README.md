# Binding vector PCS screen

Status: executable source-only audit. `strict_admitted`, complete-ZK, source
witness binding, and QROM composition are all `false`. Nothing here is a
production proof artifact or filler-byte claim.

This directory audits the missing hiding/binding transparent vector-opening
PCS for the frozen `86,752`-byte mixed-field VEIL geometry. The remaining raw
PCS plus algebraic-ZK budget is exactly

    124,068 - 86,752 = 37,316 bytes.

The code uses real `B128 = GF(2^128)` committed symbols, real
`E384 = B128[Y]/(Y^3+Y+1)` challenges, SHAKE256-512 for Fiat--Shamir, and
SHAKE256-448 (56-byte nodes) for Merkle authentication. It never runs Cargo,
allocates a production oracle, uses setup/pairings/aggregation, or changes a
consensus backend.

## Executable artifacts

`binding_vector_pcs.py` contains:

- B128 arithmetic, E384 arithmetic, irreducibility, and a product-ring
  zero-divisor negative control;
- canonical SHAKE/Merkle proving, parsing, and tamper rejection for a tiny
  allocated instance;
- the frozen full-M4 source inventory: 853-byte public statement, 114 public
  words, 671 private u64 words, 83 Keccak-f calls, and exactly
  `83 * (24*5*5*64) = 3,187,200` Keccak chi BitAnd constraints;
- executable u64 BitAnd/shift/public-transport probes and exact packing of
  two M4 words per B128 symbol (`ceil(671/2) = 336`). This is not a full
  CircuitBuilder evaluation; active trace symbols are not emitted by the
  source-only artifact and the 26,000-symbol n15 sensitivity value is marked
  an assumption;
- a canonical toy `[pi || omega]` joint commitment. It samples two E384
  gamma candidates after a single 56-byte Merkle root, opens both authenticated
  dimensions, and checks `alpha=<pi',T>` / `sigma=<omega,T>` for one linear
  claim. Every E384 mask has all three B128 coordinates on the wire;
- an exact full-M4 byte search under a 28 GiB joint-oracle cap and 512 KiB
  envelope, with sigma/alpha, three-coordinate masks, padding-aware terminal
  accounting, and an explicit unresolved nonlinear BitAnd cross-term price;
- a `GhashSq256b` two-repetition screen: 136 classical bits per repetition,
  272 arithmetic product bits, and only a conservative 136-bit composed
  margin until independence/QROM theorems exist.

Run from the repository root:

    python3 .agent/hardening/binius-pq128-proof-size/binding-vector-pcs/binding_vector_pcs.py --toy-check --report
    python3 -m unittest discover -s .agent/hardening/binius-pq128-proof-size/binding-vector-pcs -p 'test_*.py'

The local suite currently has 20 tests. The report remains fail-closed.

## Full-M4 replacement seam

The old one-lane affine toy is retained only as a negative regression control.
It is not a full-M4 construction: shared quadratic BitAnd gates mean that
translating a witness by a relation-kernel mask does not preserve
`c = a & b`, and one B128 lane cannot hide an E384 scalar.

The replacement model is relation-independent:

    pi' = (1 - gamma) * pi + gamma * omega
    sigma = <omega, T>
    alpha = <pi', T>

`gamma` is a true E384 scalar. A hash-only verifier cannot safely derive and
authenticate `pi'` from a post-commitment challenge while opening only one
share; the joint Merkle leaf therefore carries both `pi` and `omega`. Each
share has three B128 coordinates, so the queried row is charged at six times
the ordinary B128 row width. The joint leaf uses one root/frontier, not an
aggregation claim; it is simply one canonical leaf containing both shares.

For the optimistic folded transcript, retained relation claims are

    alpha = 113 wide + 2*fold sumcheck + 2^(n-fold) terminal E384 values
    sigma = one E384 value for every retained alpha claim

Terminal target elision is disabled by default. With a full random `omega`,
known zero padding is no longer a known zero, so omitting rank-3 B128
coordinates per terminal row requires a separate zero-tail mask theorem and
terminal-index binding. The report shows the padding prefix/suffix but does
not silently deduct it.

The best conservative rows under the 28 GiB joint-oracle cap are:

    n15: fold=5, rate=13, q=44, frontier=768,
         joint vector=178,296, alpha/sigma=110,112,
         raw=288,408, envelope=288,420, joint oracle=24 GiB.
    n16: fold=5, rate=12, q=47, frontier=816,
         joint vector=190,200, alpha/sigma=208,416,
         raw=398,616, envelope=398,628, joint oracle=24 GiB.

Both fit the 512 KiB outer envelope but miss the 37,316-byte budget by a wide
margin. More importantly, the compressed full-M4 reduction and nonlinear
BitAnd cross-term compiler are not proved. The explicit Boolean expansion has
three cross-term products per gate, so its naive per-gate auxiliary price is
`3 * 3,187,200 * 48 = 458,956,800` bytes; the report does not pretend that
an unproved compression is a proof. Consequently this is an exact no-go
for the declared optimistic wire model, not a strict PCS candidate.

The previously reported `113,904`-byte affine point is explicitly rejected
and appears only under `legacy_affine_in_place_negative_control` for audit
traceability. It is not a full-M4 candidate.

## GhashSq256b comparison

The screen records the pinned `GhashSq256b` quadratic extension seam as a
possible alternative, but the source is not built in this disk-gated run. At
log degree at most 120, one 256-bit repetition has 136 classical error bits;
two independent repetitions give 272 arithmetic bits, but the conservative
composition screen is only 136 bits. The two repetitions share the joint
`[pi || omega]` commitment and use two B128 mask coordinates. Independence,
QROM composition, and verifier refinement remain unproved, so this lane is
not strict PQ264/PQ128 admitted.

The separate hash ledger uses an explicit `83 * 68 = 5,644` multi-target
assumption. It reports 211.5375 classical birthday bits and 136.8708 generic
QROM collision bits for SHAKE256-448 Merkle nodes, versus 243.5375 and
158.2042 bits for SHAKE256-512 Fiat--Shamir. These are arithmetic screens,
not a composed security theorem.

## Scope and claim ceiling

The 264-bit Johnson query term (`q=68` at inverse-rate log 8) is only a
component calculation. Hash binding is conditional on the stated SHAKE
assumption. The source inventory is frozen and source-anchored, but the full
compiled trace dimension, nonlinear masking compiler, complete simulator,
verifier refinement, multi-target ledger, and QROM reduction are absent.

The only positive executable claim is a tiny parser/verifier seam with exact
wire lengths and tamper rejection. It must not be called a strict hiding PCS,
complete-ZK proof, measured VEIL artifact, or production frontier point.
