# Strict-QROM profile selection

## Verdict

No strict-QROM profile is selectable from the current repository. The retained arithmetic establishes two **conditional, zero-ZK-cost source screens**, not a proof-system certificate:

| Challenge field | Smallest conditional fixed grammar | q | Bytes | Local-envelope bits (display only) |
| --- | ---: | ---: | ---: | ---: |
| E384 | p=5, R=2048, M=4096, rate 1/2 | 130 | 206,992 | 128.506637186235 |
| E512 | p=6, R=1024, M=2048, rate 1/2 | 130 | 232,768 | 128.598281632386 |

Every admission comparison is performed as an exact `Fraction` against the strict inequality `< 2^-128`. The decimal bit values are presentation only. These profiles assume that the augmented CMS game budget itself is `t=2^64`; because CMS hides the exact `BCSExpand` overhead in `O(q log ell)`, the corresponding external adversary-query budget is unknown rather than `2^64`.

The exact local formula is

```text
epsilon_source = ((M-R-1)/(2M))^q + p*(M+2)/2^field_bits
epsilon_local  = 12*t^2*epsilon_source + 48*t^3/2^512 + 2*K^2/2^512
K              = M                 (conditional screen choice)
t              = 2^64              (augmented-game input)
```

At this `t`, the middle term is exactly `3/2^316`. The formula is a conservative repository corollary derived from CMS Section 8.5.1 and Lemma 4.9; it is **not** the verbatim statement of CMS Theorem 8.6. The theorem uses big-O notation, its base-game arity is `a=O(q log ell)`, and the local replacement `a <= K^2` is not yet instantiated for an exact compiler.

## Union headroom

`q=130` only closes a one-source-error arithmetic screen. Re-running the global fixed-grammar minimization with equal source-error unions gives:

| Equal source-error terms | E384 q / bytes | E512 q / bytes |
| ---: | ---: | ---: |
| 1 | 130 / 206,992 | 130 / 232,768 |
| 2 | 131 / 207,696 | 131 / 233,920 |
| 8 | 132 / 208,400 | 132 / 235,072 |
| 16 | 132 / 208,400 | 132 / 235,072 |
| 64 | 133 / 209,104 | 133 / 236,224 |

These rows are sensitivities, not a substitute for the missing ledger. Proximity, algebraic/reduction, commitment/hash, Fiat–Shamir reprogramming, grinding/retry, multi-proof/action/consensus, and parser/refinement terms must be charged by their own proved bounds. The manifest therefore retains `overall_total=null`, `selected_query_count=null`, and every authority flag false.

The 512-MiB encoded-oracle limit only bounds this dependency-free search. It is not an immutable proof-size cap or an architecture-tournament disqualifier. Likewise, any separate provisional 512-KiB parser-safety ceiling is not treated as a cryptographic theorem.

## Why one-level Ligerito plus M4 does not qualify

### Observed

- [Ligerito Equation (15)](https://eprint.iacr.org/2025/1187.pdf) supplies the accepted-view source expression used above. It does not prove that this exact one-level protocol is generalized special sound, CMS round-by-round sound, or CMS round-by-round knowledge sound.
- The M4 candidate source is a relation compiler with raw geometry projections, not a typed interactive IOP with an accepting proof verifier and extractor. There is therefore no “exact M4 IOP” epsilon to lift.
- [Block et al. Theorem 1.1 and Corollary 1.6](https://eprint.iacr.org/2023/1256.pdf) can turn a proved generalized special-sound IOP into RBR soundness and adaptive QROM soundness. Its premises require an efficient extractor from the complete accepting transcript tree and pairwise-distinct challenges. The current source proves neither.
- Block et al. Theorem 1.3 and Remark 1.7 explicitly prevent using special soundness as RBR **knowledge** soundness.
- The exact CMS-modified BCS transcript/domain grammar, exact base-game arity, augmented query overhead, and a concrete SHA-512-as-QRO reduction are absent.

### Inferred

The q=130 profiles are useful lower screens for a future exact IOP, but promoting either now would substitute an ordinary source-error equation for the RBR premise that the QROM theorem actually consumes.

## Statistical zero knowledge

[BCS Lemma 3.4 and Lemma 7.5](https://eprint.iacr.org/2016/116.pdf) give a direct salted-Merkle term `p*2^(-lambda/4+2)`, in addition to the underlying IOP's HVZK error. With `lambda=512`, even the optimistic committed-unit floors here yield only:

- E384 (`p>=4096`): `2^-114`;
- E512 (`p>=2048`): `2^-115`.

This is a limitation of the direct theorem bound, not a lower bound on the actual leakage of a repaired protocol. Strictly beating 128 bits under that expression requires `lambda>568` for 4096 units (minimum integer 569, byte-aligned 576) or `lambda>564` for 2048 units (minimum integer 565, byte-aligned 568). A wider compiler changes the hash identity, salts, wire dimensions, CMS instantiation, and byte ledger, so those numbers are not selectable parameters.

The current unsalted direct Ligerito view is not HVZK and exposes witness-dependent messages/openings. Complete ZK remains false.

## Conditional HVZK-WHIR lane

[Chiesa–Fenzi–Weissenberg, ePrint 2026/391](https://eprint.iacr.org/2026/391.pdf) gives a constrained-interleaved-code IOPP with explicit HVZK composition and a straightline relaxed RBR-knowledge extractor. [Plonky3 PR #1767](https://github.com/Plonky3/Plonky3/pull/1767) merged a full `HidingWhirPcs`, which is credible implementation-feasibility evidence.

At theorem-shape level, this lane can conditionally feed CMS soundness (the relaxed notion implies ordinary RBR soundness) and BCS/CMS ZK once exact parameters and the CMS compiler exist. It cannot currently feed CMS's knowledge clause: [BCFW25 Section 2.8 and Appendix C](https://eprint.iacr.org/2025/753.pdf) describe the witness-propagating notion as a strict relaxation of prior CMS-style RBR knowledge and prove only the old-to-new direction. The same source says BCS is QROM-secure but merely conjectures analogous QROM security for its reduction-adapted strategy.

Consequently the WHIR lane retains null exact epsilon, profile, M4 lowering, proof bytes, and CMS-knowledge applicability. The merged external implementation is not Hegemon integration or verifier refinement.

## Field choice

- E384 is 48 bytes per extension element but has degree three over B128. The live Binius `ExtensionField` interface encodes degree as `2^LOG_DEGREE`, so this field is not representable without a trait redesign.
- E512 is 64 bytes per extension element and degree four over B128, matching the live trait's power-of-two shape. No E512 scalar/channel implementation exists: it still needs a fixed irreducible polynomial, canonical bases, arithmetic and inversion, serialization, KATs, and either a heterogeneous B128-commitment/E512-challenge channel or an all-E512 conversion.

E512 reduces integration-shape risk but costs 16 more bytes per extension element and produces the larger conditional wire above. Neither field is selected.

## Retained artifacts and validation

- [`profile_manifest.json`](./profile_manifest.json) is the canonical fail-closed profile and full-ledger manifest.
- [`theorem_premise_map.json`](./theorem_premise_map.json) maps each primary theorem to its exact missing Hegemon premise.
- [`strict_qrom_profile.py`](./strict_qrom_profile.py) performs exact rational searches and source checks.
- [`test_strict_qrom_profile.py`](./test_strict_qrom_profile.py) covers strict comparison, q thresholds, union sensitivities, BCS bounds, theorem overclaims, source drift, and capability mutations.

The source binding deliberately says `retained_source_closure=false` and `live_mutable_dependency=true`. It pins only isolated ledger inputs; the M4 relation, scalar relation, complete-ZK source, and symlinked Binius tree remain unpinned while other owners are active. A separate quiescent repin is required before release.

Run only the dependency-free checks while the disk gate is active:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 .agent/hardening/strict-qrom-profile-selection/strict_qrom_profile.py --check --report
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .agent/hardening/strict-qrom-profile-selection -p 'test_*.py' -v
```

No Cargo, Lake, proof generation, or production allocation is part of this package.
