# Random-padding PCS / one-round FRI executable seam

Status: isolated small-n executable prototype. It is not a production proof
system, not zero knowledge, not a strict-PQ result, and not a frontier point.

This directory supplies the concrete layer that the source-only random-padding
screen did not have. It encodes a polynomial over the pinned GHASH B128 field,
commits its Reed--Solomon evaluations on a nonzero affine coset, derives two
true `GhashSq256b` E256 branches, commits one coefficient-fold table per branch,
opens canonical Merkle multiproofs, exact-decodes the wire, and verifies an
honest small-n low-degree/fold roundtrip.

The executable proof deliberately reveals every small table. Full revelation
lets the verifier interpolate the base and folded codewords and makes its
degree and fold checks exact. It also makes the proof non-succinct and visibly
non-ZK. Query-only n15 rows are byte models of the same serializer topology;
they are not promoted into a FRI proof.

## Exact construction

The base message is `[active coefficients || fresh random high coefficients]`.
It is evaluated as a univariate polynomial over

    (1 << 127) + span(1, X, ..., X^(log_domain-1)).

The additive coset contains no zero. The API rejects a zero-containing domain,
because evaluation at zero reveals the constant coefficient regardless of the
high random tail.

Every commitment leaf contains four canonical little-endian B128 symbols and
a 32-byte salt. The leaf and node hashes use domain-separated 64-byte SHAKE256
outputs. This 64-byte width is the strict proof commitment and Fiat--Shamir
profile. The old 56-byte screen is retained only as an explicit non-strict
negative control. The executable 32-byte salt has no integrated BCS/QROM
theorem; the production report separately prices the external direct-BCS
diagnostic per tree as `130 + log2(leaves)` bytes (148 bytes at `n=2^18`, 149
at `n=2^19`), without claiming that theorem is composed or proved here.

The shared base root derives a separate E256 `beta` for each branch. E256 is

    B128[Y] / (Y^2 + X*Y + X),

so `Y^2 = X*Y + X`; it is not two componentwise B128 challenges. Branch `b`
folds adjacent coefficients as

    g_b[i] = c[2i] + beta_b * c[2i+1].

Each E256 folded evaluation is serialized as two B128 coordinate lanes. Two
folded evaluations therefore fill the same four-symbol leaf grammar. After
both folded roots are fixed, each branch derives root-bound base and folded
query schedules plus a terminal E256 point. The proof sends the original and
folded terminal values for each branch.

The exact canonical grammar is:

    48-byte header
    3 * 64-byte roots
    64-byte root-derived query-schedule digest
    4 * 32-byte E256 terminal values
    canonical base opened leaves and frontier
    canonical branch-0 folded opened leaves and frontier
    canonical branch-1 folded opened leaves and frontier

Indices are not serialized. The verifier derives them from the public context
and all roots, requires every encoded opening/frontier count to equal the
canonical count, and rejects truncation and trailing bytes. Each opened leaf
costs `4*16 + 32 = 96` bytes. The fixed prefix is 432 bytes.

The default fixture has eight message symbols, rate `1/4`, eight leaves in each
of three trees, and fully opens all three trees. Its exact proof size is 2,736
bytes.

## Full observation-matrix audit

`open_commitment` exposes the canonical leaf payloads and minimal frontier;
`export_observation_matrix` exports the B128-linear row for every serialized
view of the original coefficients:

- every opened base evaluation;
- both coordinate rows for every opened E256 folded evaluation;
- both coordinate rows of each original terminal value; and
- both coordinate rows of each folded terminal value.

The fixture exports 104 rows over eight coefficients. Gaussian elimination in
B128 computes, rather than infers, padding rank 4 and joint rank 8 for four
active and four random coefficients. The fixed matrix is not witness
independent. The Fiat--Shamir schedule also depends on salted roots, so the
fixed-matrix lemma is not an adaptive-ZK proof even when a smaller view happens
to have sufficient padding rank.

Reusing a random tail remains forbidden. The regression evaluates two active
messages at the same fixed point with one reused tail and checks that XORing
the views cancels every random-tail term exactly.

## What the n15 topology changes

At rate `1/32`, an n15 message has 1,048,576 B128 base symbols and 262,144
four-symbol leaves per tree. One E256 coefficient fold has half as many E256
evaluations but exactly the same number of B128 coordinate symbols, so the base
tree and both folded trees have the same leaf count.

The actual one-round serializer topology costs:

| schedule and salt | base / folded opened leaves | base / folded frontiers | one-round query wire | delta over precursor screen |
|---|---:|---:|---:|---:|
| q33 per branch, salt 32 (unproved) | 66 / 33 each | 788 / 427 each | 118,192 B | +54,872 B over 63,320 |
| q66 per branch, salt 32 (unproved) | 132 / 66 each | 1,444 / 788 each | 219,056 B | +102,104 B over 116,952 |
| q33 per branch, salt 148 theorem scope | 66 / 33 each | 788 / 427 each | 133,504 B | +70,184 B over 63,320 |
| q66 per branch, salt 148 theorem scope | 132 / 66 each | 1,444 / 788 each | 249,680 B | +132,728 B over 116,952 |

This answers the missing-term question: a real proximity layer adds later
roots, salted leaf payloads, canonical frontiers, terminal values, and
cross-layer consistency checks. The 63,320/116,952 rows were first-level
screens, not complete proof sizes. The one-round totals above still omit later
FRI rounds, the maximum-M4 PIOP, characteristic-two ZK messages, extraction,
adaptive BCS simulation, two-branch product soundness, and composed QROM loss.
They are therefore topology diagnostics, not lower bounds or candidates.

The two comparison numbers in the last column are the explicitly requested
legacy 56-byte screens. The corrected strict precursor rows are 69,632 bytes
for conditional q33 and 128,512 bytes for double-full q66. Relative to those
strict rows, the four one-round deltas are +48,560, +90,544, +63,872, and
+121,168 bytes respectively. No old precursor source hash is pinned here.

The q33 row is also conditional security arithmetic, not an admitted query
budget: its ideal algebraic union is only about 132.606 bits and still needs an
independent-branch product theorem and its QROM composition. Separately, the
allocation-free maximum-relation geometry now permits only 2,289 to 9,174 random
tail symbols after the applied packed-decode rewrite. Until compilation freezes the active prefix and the real
production matrix is exported, no production rank claim exists.

The exhaustive n15 form would be 75,497,904 bytes with 32-byte salts or
166,724,016 bytes with 148-byte salts. Those values are calculated only; the
prototype never allocates a production oracle.

### Maximum combined-tree structural saving

There is one honest packing improvement. One combined folded tree can put the
fixed lane order

    [branch0.low, branch0.high, branch1.low, branch1.high]

for one evaluation point in each four-symbol leaf. At n15/rate-1/32 that tree
has 524,288 leaves. In the maximum-overlap best case, both branches use the
same 33 folded query indices. The base commitment still opens its independent
66-leaf union and authenticates 788 frontier nodes; the combined folded tree
opens 33 leaves and authenticates 460 frontier nodes. Two roots, all payloads,
and all authentication remain on wire.

That exact one-round screen is 89,744 bytes with 32-byte salts, saving 28,448
bytes from the separate-fold-tree 118,192-byte topology. With theorem-scoped
per-tree theorem-scoped salts it is 101,261 bytes. The shared folded-query schedule has no
parallel-product soundness theorem, so this is a structural best case only.

No E256 terminal value can be honestly elided in the implemented seam. Both
the original and folded terminal values depend on hidden coefficients and are
not verifier-known. The model therefore credits zero bytes of target/value
elision; a future PIOP would need to supply and bind such a public value before
any removal is valid.

### Completing the degree reduction

One adjacent-coefficient fold reduces the coefficient bound by only a factor
of two. Starting from n15 requires 15 folds to reach a constant, so the
executable first fold leaves 14 rounds. Even under the combined-tree, fully
shared-q33 best case, charging every later root, salted opened leaf, and
canonical frontier gives an authenticated structural floor of 325,424 bytes
with 32-byte salts or 387,427 bytes with exact per-tree theorem-scoped salts. The former is 235,680
bytes beyond the 89,744-byte combined one-round screen.

That floor is not a complete-FRI estimate. It omits a proved cross-layer local
consistency grammar, the maximum-M4 PIOP, characteristic-two ZK, extraction,
adaptive simulation, branch-product soundness, and QROM composition. A
query-only verifier remains unauthorized regardless of how many roots it
parses.

Therefore no implemented or screened full low-degree profile is at or below
the 124,068-byte raw cap. The 89,744-byte combined row fits only because it is
one round, not a full low-degree proof; the most optimistic authenticated
15-round structural floor is 325,424 bytes before omitted terms. This is a
no-result for the constructions in this directory, not a universal
impossibility theorem for every future PCS.

## Validation

From the repository root, run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/random_padding_fri.py \
      --check --report

The first line must be:

    RANDOM_PADDING_FRI_CHECK_PASS

Then run:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/test_random_padding_fri.py

The suite runs 25 tests. It covers the honest roundtrip plus B128/E256 KATs,
partial membership, point/fold/terminal row reproduction, exact matrix rank,
mutation, truncation, trailing bytes, root drift, query drift, zero-domain
rejection, noncanonical counts, terminal mutation, and random-tail reuse.

Both commands use only the Python standard library, create no bytecode cache
when invoked as shown, invoke no Cargo build, and allocate no production table.

## Authority boundary

Every production gate in `report()` is false. In particular, this directory
does not freeze the compiled maximum-M4 active prefix, establish enough random
tail for the production union matrix, prove succinct FRI proximity or
extraction, prove adaptive zero knowledge, integrate the 148-byte salt theorem,
prove salted-Merkle binding/hiding in the QROM, prove E256 parallel repetition,
compose PQ128, or refine a production parser/verifier. No ledger or frontier
file is touched.
