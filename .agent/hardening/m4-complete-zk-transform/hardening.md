# Hardening assessment

## Outcome

**NO-GO for retained M4.** The current committed/opened codeword topology is not complete zero knowledge and cannot be repaired by adding more independent mask coordinates while continuing to open a raw message-codeword coordinate. The candidate must be removed from any complete-ZK or strict-PQ128 winner set.

## High-severity finding: the opening reveals the message lane

Let the public statement be empty and the private Boolean witness be `b`. Use the valid relation

```text
b * b = b.
```

Both `b=0` and `b=1` are valid witnesses for the same public statement. At any position `x` where their encoded message codewords differ, the retained opening has the form

```text
(RS(message)[x], RS(mask)[x], tape, authentication path).
```

The first projection is deterministic in the witness. Its supports for the two witnesses are disjoint, independently of the second coordinate, the 512-bit tape, or the Merkle path. Thus

```text
Delta(View_0 | x queried, View_1 | x queried) = 1.
```

For the depth-20 tree with 319 distinct queries, a single differing coordinate is hit with exact probability `319/2^20`; a constant nonzero differing codeword is exposed with probability one. A public-only simulator distribution `S(public, verifier-coins)` cannot match both witness-conditioned views. By the triangle inequality, at least one of `Delta(S,View_0)` and `Delta(S,View_1)` is at least `1/2` on the conditional event. This is a concrete simulator impossibility, not a rank heuristic.

The executable mutation controls show:

| Opened value | Exact TV for witnesses 0 and 1 |
|---|---:|
| `(message, random_mask, tape, root)` | `1` |
| `message + random_mask` only | `0` |
| `(message + random_mask, random_mask)` | `1` |

Changing a leaf index, group, layer, lane, or tape changes the SHA-512 leaf digest in the mutation suite. This confirms that binding is orthogonal to hiding: index binding prevents substitution but leaves the raw scalar visible.

## E384 and E512 local mask checks

The existing E384 rank leak is reproduced over `GF(2^3)` with weights `[5,6,6,4]`: same-public witness images have rank `3`, while the current constant trace mask has rank `1`; the conditional TV distance is `1`. Three independent B128 coordinate masks close this local affine span, but do not construct a whole-proof simulator.

The E512 analogue is exhaustively checked over `GF(2^4)` with weights `[15,10,10,12,10,12,12,8]`: witness-image rank is `4`, current mask rank is `1`, and four independent B128 masks are necessary for local closure. Omitting one coordinate again gives TV distance `1`. Two B128 outer dummies have rank `2` and fail against an extension translation for either degree.

E512 is therefore not a cure for the raw-opening topology. It only increases field width and the number of local mask coordinates.

## Exact byte accounting

For the explicit mixed B128/E(128d) direct-column repair shape with relation size `2^16`, six folded variables, and `q` openings, the new serialized payload floor is

```text
32*d*q + 16*d*(d+1) bytes.
```

It consists exactly of `q*d` opened B128 mask values, `q` extension padding-RLC values, `d` extension mask evaluations, and one extension claim. Randomness is `q*64` B128 padding coefficients plus `(1024+q)*d` B128 mask elements. This is an exact lower bound for that named direct-column topology, not a universal bound for every hiding PCS.

| Shape | E384, d=3 | E512, d=4 | E512 minus E384 |
|---|---:|---:|---:|
| one level, q=38, baseline + floor | 148,336 | 168,064 | 19,728 |
| one level, q=61, baseline + floor | 174,736 | 195,200 | 20,464 |
| direct floor only, q=319 | 30,816 | 41,152 | 10,336 |
| retained max raw projection | 1,548,704 | 1,763,232 | 214,528 |
| retained max projection + floor | 1,579,520 | 1,804,384 | 224,864 |

An all-E512 counterfactual widens the B128 input rows too and changes M4 packing. Its same-schedule raw projection is `1,883,136` bytes and its degree-one analogous floor is `40,960`, totaling `1,924,096` bytes. None of these totals fit the 524,288-byte cap, and none is a complete-ZK proof size because the new PCS/tree schedule is absent.

## Exact conditional QROM screen

For domain `M=2^20`, miss set `G=589824`, and distinct queries,

```text
epsilon_q = (G)_q / (M)_q.
CMS = 12*t^2*epsilon + 48*t^3/2^512 + 2*k^2/2^512,
t=k=2^64.
```

The dependency-free rational computation gives:

- query-only CMS threshold: `q=313`;
- pessimistic twelve-equal-component CMS threshold: `q=317`;
- strict policy requiring every component at most `2^-264`: `q=318` (`q=317` is about 263.187 bits; `q=318` about 264.018 bits);
- with `epsilon <= 12/2^264`, the CMS first term is exactly `9/16` of `2^-128`, and both 512-bit hash/arity tails keep the total below `2^-128`.

So E384 is conditionally sufficient for this query/hash envelope at `q>=318`; E512 is not structurally required by this arithmetic. The production qualifying query count remains **none** because the exact M4 error union, RBR/special soundness, whole-view HVZK, and BCS/CMS applicability are missing. E512 adds 128 exponent bits to field-size-dependent terms, but no exact M4 field-error numerator exists to turn that observation into a theorem.

## Hiding-WHIR boundary

[CFW26 ePrint 2026/391](https://eprint.iacr.org/2026/391) proves interactive HVZK for constrained interleaved linear-code proximity together with round-by-round knowledge soundness and a straightline extractor. [Plonky3 PR #1767](https://github.com/Plonky3/Plonky3/pull/1767) merged a full `HidingWhirPcs` pipeline: randomized interleaved RS encoding, masked sumcheck, private zero-evader/code switch, and masked base case. This topology addresses the exact raw-opening failure: it appends random coefficients before encoding and never exposes message and mask evaluations as separable lanes.

It is not a theorem-valid source-local repair:

- Plonky3 requires two-adic multiplicative DFT fields. `GF(2^m)^*` has odd order `2^m-1`, so B128 has no nontrivial power-of-two multiplicative subgroup.
- Retained M4 uses Binius additive Gao–Mateer domains and a different committed/folding relation.
- The merged code is a parallel pipeline precisely because the carried relation differs from plain WHIR.
- The hiding PCS API is not inherently R1CS-only, but CFW26's ready-made full-ZK R1CS clause assumes characteristic not equal to two. It therefore does not cover the B128 Boolean/M4 instantiation.
- The Plonky3 KoalaBear/Poseidon2 benchmark and its roughly 120 KiB fixed opening overhead are not eligible hashes or transferable M4 byte counts.
- Interactive HVZK/RBR does not by itself prove a SHA-512/SHAKE256-512 noninteractive QROM argument.

The minimal viable *security topology* is Hiding-WHIR-like randomized codeword sharing across every round and the terminal case. The minimal viable *implementation change* is not an opening-layer patch: it is either an odd-field Boolean/R1CS compiler plus the entire Hiding-WHIR IOP/PCS stack, or a new characteristic-two theorem plus a source-faithful additive implementation.

## Authority

Every authority flag is false. No exact whole-view simulator, indistinguishability theorem, M4 RBR/special-soundness theorem, hiding/extracting PCS theorem, conventional-hash QROM composition, or parser/serializer refinement is present.

