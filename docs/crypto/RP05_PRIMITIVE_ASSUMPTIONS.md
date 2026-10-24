# RP05 primitive assumption audit

Status: audited conditional assumptions. No concrete advantage bound is supplied
for any of the six games. This audit does not establish unconditional 128-bit
security, an efficient quantum reduction, Rust refinement, or production authority.
The machine-readable companion is `rp05_primitive_assumptions.json`; its source
hashes identify the exact evidence examined.

The authorization and initialized-history endpoints already map charged failures
to concrete primitive-game events and compose their masses on the same original
outcomes. These are meaningful mechanized inclusions. They do not by themselves
construct standalone efficient quantum adversaries or bound the advantages of
the instantiated primitives. In particular, `3*2^64` is the proof-model oracle
query cap; it does not supply a resource bound for each primitive adversary.

## Instantiated permutation and modes

The pinned suite is `hegemon-p2w16-v1-114a4e7eb2684d29`: width 16 over
Goldilocks, S-box degree 7, eight full rounds and 22 partial rounds. Its
variable-length sponge uses rate 8/capacity 8, field-addition absorption, and
capacity markers for domain, exact length, mode, final block and suite.
`Compress14` instead uses one permutation of
`left[7] || right[7] || domain || suite`, with no feed-forward, then takes seven
output lanes. The two modes need bounds for their actual constructions.

The parameter manifest still says `candidate_external_review_required`,
`required_external_review = true`, and `production_authorized = false`.
Its generic-work arithmetic and local reduced-round attack screens are not
concrete advantage bounds for these six games. This audit pins the Rust
permutation, Lean mirror and parameter manifest; it does not replace the
independent exact-parameter review or establish implementation refinement.

## Exact six games

All outputs below contain seven complete canonical Goldilocks field words,
with modulus `18446744069414584321`. Truncated output equality is insufficient.
The executable event/evaluator names and exact source pins are in the JSON.

| Term | Concrete target and input | Domain |
| --- | --- | --- |
| `epsilonNoteCommitment` | Collision in the exact note commitment: 18 effective words, comprising value, asset, and four words each of recipient, rho, randomness and authorization | `1` |
| `epsilonMerkle` | Collision in ordered `Compress14(left[7], right[7])` | `4` |
| `epsilonNullifier` | Collision on key[5], zero[2], position and rho[4] | `0x484e554c56320001` |
| `epsilonSingle` | Collision in SingleKey on five canonical key words plus two zero words | `0x48534b4156320001` |
| `epsilonAccumulator` | Collision in authorization-binding `Compress14(policyKey[7], accumulatorDigest[7])` | `0x484d424456320001` |
| `epsilonMixed` | Cross-domain claw between the complete SingleKey and accumulator authorization-binding outputs | The preceding two domains |

The nullifier target is not the legacy domain-2 nullifier. The accumulator
target is not a generic domain-6 state hash. Domain separation specifies the
games; it does not prove collision or claw resistance. For each term, closing
the numerical obligation requires a standalone game, the adversary's time/query
budget, an efficient reduction with explicit overhead and target accounting,
and a supported bound for the actual Poseidon2 construction at that budget.

## Numerical accounting

The checked fixed-context extraction loss is strictly below `2^-130` under
its stated model and resource premises. The conditional composed expression
adds the six advantage terms. A sufficient allocation for that expression to
remain strictly below `2^-128` is:

    sum(six primitive advantages) <= 3 / 2^130

An equal allocation of at most `2^-131` to each term suffices arithmetically.
`SmzaRp05PrimitiveBudget.below_128_of_aggregate_budget` and
`six_individual_bounds_suffice` check this arithmetic in Lean. They assume the
input bounds and do not establish that any real primitive meets them.
This allocation excludes the separate assumptions below and the adaptive
context/extractor obligation. It is not an end-to-end product-security bound.

## Separate assumptions and implementation boundaries

SHA-512 is modeled as an ideal quantum random oracle; digest width does not
certify the real instantiation. Ciphertext binding requires a bound for the
exact framed BLAKE2b-384 function after each of its six 64-bit limbs is reduced
modulo the field. Distinct raw digests can have equal projected commitments,
so raw BLAKE2b collision resistance alone does not discharge that obligation.

The opaque Lean BLAKE2b interpretation and the actual Rust framing, hashing,
projection and serialization require an implementation-correctness boundary
separate from binding. Likewise, the post-parser proof-field model has no
universal serialized-Rust-acceptance refinement theorem. ML-KEM, ML-DSA,
AEAD/KDF confidentiality and RNG assumptions remain separate product obligations.
See [the implementation boundary](RP05_IMPLEMENTATION_BOUNDARY.md).

H2 also remains open: the current bound fixes context before the proof-view
producer runs. Supplemental bind/replay proofs preserve the producer's actual
unnormalized oracle state and derive ambient classification and mass
decomposition and a below-`2^-130` adaptive parsed-context model endpoint.
The parsing connection and efficient extractor/resource theorem remain required. See
[the H2 obligation](RP05_ADAPTIVE_CONTEXT_OBLIGATION.md).

## Reproduction and claim enforcement

From the repository root:

    python3 -I -B scripts/rp05_primitive_assumptions.py check
    python3 -I -B scripts/test_rp05_primitive_assumptions.py
    python3 -I -B scripts/rp05_primitive_assumptions.py check --require-quantified

The first command must report `PASS_AUDIT_INTEGRITY`, six terms and zero concrete
bounds. The final command must fail while the six bounds remain unquantified.
CI checks evidence freshness, exact event/evaluator/domain bindings and these
claim limits. Updating a numerical bound requires a separately reviewed evidence
schema and validator change; editing a JSON string cannot confer security authority.

The audit also repaired a stale parameter-manifest source hash. Commit
`ce63228f4` had replaced bounded ceil-division arithmetic with `usize::div_ceil`
without refreshing that hash. Fresh parameter derivation matched every other
digest, algebra certificate, security-status field and known-answer vector.
Only `digests.source_sha256` changed; external review remains required.
