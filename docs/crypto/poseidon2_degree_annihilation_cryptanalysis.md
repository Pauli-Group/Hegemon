# Poseidon2 Degree-Annihilation Cryptanalysis

Date: 2026-06-18

Reviewed paper: [Top Gun: Degree Annihilation Attacks on Poseidon](https://eprint.iacr.org/2026/1254.pdf)

Generated artifact: [poseidon2_degree_annihilation_report.json](poseidon2_degree_annihilation_report.json)

Reproduction command:

```bash
python3 scripts/analyze_poseidon2_degree_annihilation.py --check
```

## Judgment

No practical break of Hegemon's active Poseidon2-384 surface is found.

The paper is a real review trigger. It introduces degree annihilation, an algebraic attack framework that cancels dominant high-degree terms in Poseidon-family permutations and gives concrete reduced-round attacks. It does not claim a break of recommended full-round parameter sets, and its concrete attacks do not transfer directly to Hegemon's active 6-limb digest surface.

The active risk is not "ignore this." The active risk is "do not keep claiming Poseidon2-384 is reviewed unless future external Poseidon/Poseidon2 review explicitly includes degree annihilation and skipping-class attacks."

## Hegemon Surface

Hegemon's consensus-critical in-circuit hash surface is the sponge in `circuits/transaction-core/src/hashing_pq.rs`, backed by `circuits/transaction-core/src/poseidon2.rs` and constants in `circuits/transaction-core/src/constants.rs`.

The parsed active parameters are:

- Field: Goldilocks, modulus `18446744069414584321`
- Width: `12`
- Rate: `6`
- Capacity: `6`
- Output: `6` field elements, `48` bytes
- S-box: `x^7`
- Initial linear layer: present
- Initial full external rounds: `4`
- Internal partial rounds: `22`
- Final full external rounds: `4`
- Total full rounds: `8`

The SmallWood proof stack also contains Poseidon2 transcript/XOF paths in `circuits/transaction/src/smallwood_engine.rs`. That path is in scope for future review because a transcript hash break can become a proof-system attack even if note/Merkle hashing remains intact.

The older `crypto/src/hashes.rs::poseidon_hash` helper is not the primary consensus-critical Poseidon2-384 sponge. The default application-level `commit_note` and nullifier helpers in that crate use BLAKE3/SHA3-style hashes.

## What The Paper Breaks

The paper's concrete table targets reduced-round Poseidon/Poseidon-like challenge instances over KoalaBear with:

- S-box degree `3`
- Full rounds `6`
- Partial rounds `7` or `8`
- CICO/zero-test output constraints equivalent to `2` field constraints

The useful new idea is degree annihilation. Instead of only skipping rounds, an attacker chooses an algebraic family of states and imposes equations that make leading degree terms vanish before partial S-boxes. This can lower the degree of the final univariate or multivariate solve.

The paper explicitly says concrete deployments should be analyzed parameter by parameter. That is the work done here for Hegemon's active parameter tuple.

## Local Model

The generated report uses an attacker-favorable model:

1. It grants skipped initial full rounds and then computes the degree entering the first remaining partial round.
2. It counts how many leading coefficients must be forced to zero before that partial S-box to remove one effective `alpha` degree factor.
3. It separately reports the stricter count required to force the partial-round input down to an affine polynomial.
4. It compares the required equations to the paper-style control template, which uses roughly `1 + 2a` controls to annihilate `a` partial rounds in the bivariate/multivariate construction.
5. It accounts for Hegemon's six output limbs when considering reuse of a CICO-2-style final solver.

This is not a formal lower bound. It is a reproducible engineering cryptanalysis pass meant to determine whether the 2026/1254 technique gives an immediate attack and to scope the external review work.

## Results

Granting the attacker two skipped initial full rounds leaves two initial full rounds before the first partial round. With Hegemon's `x^7` S-box, the first partial-round input has degree:

```text
7^2 = 49
```

To reduce that first partial input enough to remove one effective `alpha` factor, the attacker must cancel the coefficients from degree `49` down through degree `7`, which is:

```text
43 coefficient cancellations
```

To force the input fully affine, the stricter target used in the paper's RF=6 construction, the count is:

```text
48 coefficient cancellations
```

That is before satisfying any Hegemon digest constraints.

The generated table gives the key rows:

| Annihilated partials | Degree exponent after annihilation | Degree log2 | One-factor equations | Paper-style controls | Equation gap |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 | 28 | 78.61 | 0 | 0 | 0 |
| 1 | 27 | 75.80 | 43 | 3 | 40 |
| 2 | 26 | 72.99 | 49 | 5 | 44 |
| 3 | 25 | 70.18 | 55 | 7 | 48 |

The "degree log2" column is not a security claim by itself. It is the size of the final restricted univariate degree under this very favorable CICO-style model. Hegemon does not expose only two constrained output words in its commitment/Merkle/nullifier digest. It exposes six field limbs. Reusing a CICO-2 style solver leaves four output limbs to check, which contributes about:

```text
4 * log2(Goldilocks modulus) ~= 256 bits
```

of residual field constraints if handled by root filtering.

A true CICO-6 algebraic solver would have to incorporate all six output equations directly. This report does not claim such a solver is impossible; it records that no such solver is provided by the paper, and the degree-annihilation equation budget for Hegemon's full `x^7`, RF=8, RP=22 surface is much less favorable than the reduced-round cubic challenges.

## Security-Budget Check

The generated report computes the digest budget from six canonical Goldilocks limbs:

- Classical collision budget: about `192` bits
- Quantum collision budget using BHT-style collision search: about `128` bits
- Classical preimage budget: about `384` bits
- Quantum preimage budget using Grover search: about `192` bits

That remains consistent with the repo's current 48-byte digest claim. Degree-annihilation work changes the review obligation around the concrete permutation; it does not by itself lower these generic bounds.

## Conclusion

Do not rotate Poseidon2 on this paper alone.

Do require a fresh external review item before mainnet or before any claim that the Poseidon2-384 surface has completed cryptanalysis. That review must cover:

- Hegemon's exact Goldilocks `width=12`, `rate=6`, `capacity=6`, `alpha=7`, RF=`8`, RP=`22` tuple.
- The initial linear layer and Hegemon's specific external/internal matrix structure.
- The six-output-limb sponge mode used by note commitments, nullifiers, Merkle nodes, and balance tags.
- The SmallWood Poseidon2 transcript/XOF paths.
- Degree-annihilation, skipping-class, CICO-k, preimage, collision, and sponge-mode adaptations.

If an external reviewer finds a concrete cost below the 128-bit post-quantum target, the next step is not an in-place tweak. The protocol should introduce a new `CryptoSuiteId` / `VersionBinding`, ship a new circuit/hash binding, and retire the old binding through the manifest/version schedule so the shielded pool remains unified.
