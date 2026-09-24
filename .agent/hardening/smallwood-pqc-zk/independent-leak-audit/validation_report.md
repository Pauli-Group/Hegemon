# Independent SmallWood complete-ZK leakage validation

Date: 2026-08-22  
Scope: legacy active SmallWood Level-5 engine geometry only (`699` witness
polynomials, packing `64`, five PIOP openings, `375 + 23 = 398` LVCS
interpolation points). This report makes no claim about the separate V6
`893`-byte statement / `128`-limb relation fixture.

## Verdict

**Validated.** The retained radix-2-subgroup profile is not zero knowledge.
If its fixed DECS sampler includes leaf `163840`, one serialized subset leaf
and the five serialized PIOP openings recover all `69` coefficients—and hence
all `64` packed evaluations—of witness polynomials `41` and `416`. The exact
per-proof inclusion probability, conditioned on successful fixed sampling, is

```text
23 / 2^20 = 0.00002193450927734375 = 2^-15.4764380439.
```

The proposed multiplicative-coset change removes this particular deterministic
collision without changing the polynomial degree, query count, or proof bytes.
It is only one necessary repair. Complete ZK still fails its evidence gate
until the DECS leaf construction has independently hidden per-leaf tapes,
absorbs each leaf index, opens the selected tapes on the wire, and is covered by
an exact composed NIZK/QROM simulator and bound.

## Exact reproduction

The engine uses the Goldilocks prime
`p = 0xffff_ffff_0000_0001`, the two-adic root
`0x1856_29dc_da58_878c`, and a `2^20`-element DECS domain. Independently
recomputing

```text
h = two_adic_root^(2^(32 - 20)) mod p
```

gives `h = 3511170319078647661`, `h^(2^20) = 1`, and
`h^(2^19) != 1`. The leaf-to-field map in the subgroup profile is `i -> h^i`,
and

```text
h^163840 mod p = 64.
```

The active geometry follows directly from `SmallwoodConfig`'s degree and width
formulas:

| Quantity | Exact value |
|---|---:|
| witness polynomial degree | 68 |
| nonlinear polynomial degree / width | 480 / 8 |
| linear polynomial degree / width | 131 / 2 |
| committed polynomials | 699 + 5 + 5 = 709 |
| unstacked matrix | 69 x 749 |
| stacked LVCS matrix | 138 x 375 |
| per-row LVCS randomizers | 23 |
| rotated row interpolation length / degree | 398 / 397 |
| full-rank rows omitted from `subset_evals` | 0..4 and 69..73 |

`lvcs_commit` first constructs `[data_0 .. data_374 | random_0 .. random_22]`
and rotates left by `375`, yielding
`[random_0 .. random_22 | data_0 .. data_374]`. Therefore rotated coordinate
`64` is exactly original data column `64 - 23 = 41`.

The PCS stacking map is

```text
unstacked_row = lvcs_row mod 69
unstacked_offset = floor(lvcs_row / 69) * 375.
```

Consequently:

- Witness polynomial `41 = 0 * 375 + 41` occupies data column `41` in LVCS
  rows `0..68`. The proof omits rows `0..4` for reconstruction but directly
  serializes rows `5..68`; at leaf point `64`, those are coefficients
  `c5..c68`.
- Witness polynomial `416 = 1 * 375 + 41` occupies data column `41` in LVCS
  rows `69..137`. The proof omits rows `69..73` but directly serializes rows
  `74..137`; those are again coefficients `c5..c68`.

The five `opened_witness.row_scalars` values contain each target polynomial's
evaluation at the five canonical PIOP points. Canonical validation requires the
points to be distinct and outside packing coordinates `0..63`. Subtracting the
known `c5..c68` contribution leaves a `5 x 5` Vandermonde system in
`c0..c4`, which is invertible for every five distinct points. The full system
has rank `69`; with only four openings it has rank `68`. Once all coefficients
are recovered, evaluation at `0..63` recovers the complete packed target row.

The fixed SHA-512 sampler rejection-reduces uniform Goldilocks elements into
the `2^20` domain, keeps the first `23` distinct indices, and sorts them.
Conditioned on sampler success this is a uniform subset, so symmetry gives a
fixed leaf inclusion probability of exactly `23 / 2^20`. Sorting and the fixed
zero nonce do not change that marginal. Repeated independent proofs reach
approximately 50% chance of at least one hit after `31,601` proofs.

## Wire audit

At the observed source snapshot, `PcsProof` serializes `rcombi_tails`,
`subset_evals`, `partial_evals`, Merkle authentication paths, masking
evaluations, and high coefficients. `SmallwoodOpenedWitnessBundle` separately
serializes the five row-scalar vectors. `DecsProof` has no leaf-tape field.

Both leaf-hash paths absorb the public salt and the committed/masking
evaluations. Neither absorbs the leaf index nor an independently secret leaf
tape. The public, proof-wide salt cannot substitute for a tape: after seeing the
salt, a distinguisher can query witness-dependent candidate leaf preimages. A
shared tape also does not satisfy the per-index guessing hybrid.

This differs from Figure 1 and Theorem 2 of the
[SmallWood paper](https://eprint.iacr.org/2025/1085.pdf), where each leaf is
`Hash(P(e_j), M(e_j), j, rho_j)`, the prover samples `N` independent
`lambda`-bit tapes, and an opening reveals the selected tapes. The paper's
appendix explicitly lists the leaf tapes as one of three required hiding
layers. Theorem 2 is an honest-verifier ZK theorem in the classical ROM with
advantage bounded by `Q / 2^lambda`; it is not an end-to-end Fiat-Shamir/QROM
NIZK theorem.

The [upstream prototype at commit
`6d0a801`](https://github.com/CryptoExperts/smallwood/tree/6d0a80157fc91396ca18191757897fa548c86d8f)
has an optional `use_commitment_tapes` switch and appends one tape per opened
leaf, but its inspected CAPSS profiles disable the switch and its leaf helper
does not absorb the index. It is implementation context, not authority for
weakening the paper's construction.

## Disjoint-coset repair audit

For a multiplicative coset `gH`, collision with an interpolation point `x` is
equivalent to `(x / g)^(2^20) = 1`. Exhaustively checking all coordinates
`0..397` shows that the old subgroup collides at `1`, `8`, and `64`. The
candidate search begins at `g = 398` (every nonzero `g < 398` necessarily
collides at `x = g`) and `g = 398` is disjoint from all `398` coordinates.
Because `g != 0` and `h` has exact order `2^20`, the coset contains exactly
`2^20` distinct points. The formerly vulnerable leaf maps to
`398 * 64 mod p = 25472`, outside the interpolation domain.

The implementation strategy `a_k -> a_k * g^k` followed by the existing FFT
correctly evaluates `P(g h^i)`. It must be applied identically to committed row
polynomials and DECS masking polynomials, while the verifier must use the same
`g h^i` points for LVCS reconstruction and degree-test restoration. The
candidate patch observed during this audit does those mappings and adds a
distinct domain label to verifier-profile material. The active frontend still
selects `Radix2Subgroup`, so the patch is inactive and cannot yet be counted as
a repair.

The coset leaves the domain size `N`, row-polynomial degree `397`, and number of
queries unchanged. Thus the root-count/Schwartz-Zippel term and sampling
combinatorics are unchanged. A deterministic shift derived from profile-bound
geometry costs zero wire bytes. It must nevertheless be frozen in the proof
version/profile preimage; silently changing the search algorithm is a consensus
change.

## Remaining complete-ZK gates

Before any production authorization, the repair needs all of the following:

1. **Leaf preimage:** absorb a canonical domain tag, leaf index, committed
   evaluations, masking evaluations, and a tape in both prover and verifier.
2. **Independent tapes:** sample one hidden tape per leaf. A master-seed/PRF
   optimization is not covered by the paper's independent-tape theorem and
   needs an explicit PRF hybrid and key-erasure/lifetime argument.
3. **Wire/parser:** serialize exactly one tape for every sorted queried leaf,
   enforce exact count/width/order, reject trailing or duplicate material, and
   mutation-test tape and index binding. The index itself is transcript-derived
   and need not add bytes. Tape overhead is exactly `23 * tape_bytes`: `368`
   bytes at 16 bytes, `736` at 32, or `1472` at 64.
4. **QROM sizing:** do not inherit the paper's classical `lambda = 128`
   example. A quantum guessing term is of order `Q_H^2 / 2^lambda` before
   constants and union terms, so the selected width must come from the exact
   bounded-query, multi-oracle, multi-proof composition.
5. **Joint simulator:** simulate the exact serialized distribution across PCS
   random rows, LVCS random evaluations, DECS masking polynomials, leaf tapes,
   compact authentication paths, PIOP and DECS Fiat-Shamir challenges,
   canonical nonce handling, fixed-sampler aborts, statement/profile binding,
   repeated proofs, and adaptive/QROM oracle access. The paper's layered
   classical HVZK theorems alone do not establish this.
6. **Fail closed:** retain production rejection until the new wire version,
   mutation tests, restart/fresh-node transport, Rust-verifier refinement,
   simulator proof, and composed PQ/QROM certificate all pass.

## Reproduction artifact

Run from repository root:

```sh
python3 .agent/hardening/smallwood-pqc-zk/independent-leak-audit/poc.py
python3 -m unittest discover \
  -s .agent/hardening/smallwood-pqc-zk/independent-leak-audit \
  -p 'test_*.py' -v
```

The PoC uses only the Python standard library. It independently computes the
domain mapping, matrix ranks, exact coefficient and packed-value recovery for
both targets, sampler probability, all old interpolation collisions, the first
disjoint shift, and tape wire deltas. Six tests pass in under one second; no
Cargo build or large artifact was produced.

Observed shared-checkout source snapshot:

```text
base HEAD: 038ec2d1275d7c1d7de4325d071f43a1fd8e66a1
smallwood_engine.rs sha256:
00875607506f4f3dd301448bf341130f25c7db4862988f155dfac7b84e12f264
```

The checkout was concurrently dirty; function names and the snapshot hash, not
mutable line numbers, are the durable audit anchors.
