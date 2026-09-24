# SHAKE400 full-M4 proof byte profile

This profile replays, but does not regenerate, repetition 0 from
`artifacts/shake400-v1-final/proof.hgsb`.

- repetition bytes: **448,224**
- repetition SHA-256:
  `a8bdf7003aa343f4c4799de636d811e5b1c5e56c7ac2ac521a61d87afcc152b8`
- field element: B128, 16 bytes
- commitment digest: SHAKE256-400, 50 bytes
- FRI queries: 116
- FRI input-oracle tree depths: 13, 18, 20, 11
- FRI-round tree depths: 16, 12, 9
- FRI fold arities: 4, 4, 3
- terminal codeword: 512 B128 elements

## Exact additive decomposition

| Byte class | Count | Bytes |
|---|---:|---:|
| Input-oracle commitment roots | 4 digests | 200 |
| FRI fold/terminal commitment roots | 4 digests | 200 |
| Sumcheck messages | subset of scalar messages | 2,464 |
| Other transcript field messages | 830 B128-equivalent elements | 13,280 |
| Multi-opening internal layers | 7 x 128 digests | 44,800 |
| Input-oracle authentication nodes | 3,944 digests | 197,200 |
| FRI-round authentication nodes | 1,856 digests | 92,800 |
| Input-oracle opened leaves | 928 B128 elements | 14,848 |
| FRI-round opened leaves | 4,640 B128 elements | 74,240 |
| Terminal committed vector | 512 B128 elements | 8,192 |
| **Total** |  | **448,224** |

Equivalently, the PCS/FRI wire is 432,480 bytes and all field messages are
15,744 bytes. The latter split into 2,464 sumcheck bytes and 13,280 other
transcript-field bytes.

Verifier-stage accounting supplies an independent exact sum:

| Stage | Bytes |
|---|---:|
| Outer ZK precommit root | 50 |
| Inner full-M4 IOP, including its trace root | 14,178 |
| Direct outer-Spartan wrapper messages, including two roots | 788 |
| Combined BaseFold/FRI | 433,208 |
| **Total** | **448,224** |

The directly attributable outer-ZK wrapper wire is therefore **838 bytes**
(50 + 788). This is not the wrapper's marginal proof-size cost: its three
oracles also participate in the combined BaseFold/FRI opening, whose shared
authentication data cannot be assigned uniquely to one oracle.

The current HGSB envelope is exactly:

```text
48 + 3 * (32-byte nonce + 4-byte length + 448,224-byte proof)
= 1,344,828 bytes
```

## What round-parallel co-commitment can share

One joint root per oracle/stage can replace three repetition-specific roots.
The 48-byte HGSB header/source binding can also remain global. Merkle
authentication paths and internal layers may be shared only when the lanes
are committed in the same leaf and the verifier uses a sound union-index
multiproof.

The following are not shareable merely by changing framing:

- independently challenged sumcheck/transcript messages;
- three lane values required to reconstruct a co-committed leaf;
- terminal codeword lanes;
- ZK masks, precommit keys, or prover coins;
- independent FRI query entropy.

Sharing query indices without a direct-product theorem does not amplify the
96-bit per-lane FRI query bound. It therefore does not establish PQ128.

Even the optimistic, security-unproven limit that shares every root and every
authentication/internal-layer digest once, while retaining three lanes of
field data, is:

```text
400 roots
+ 334,800 shared authentication/internal-layer bytes
+ 3 * 89,088 opened-leaf bytes
+ 3 * 8,192 terminal bytes
+ 3 * 15,744 transcript-field bytes
= 674,272 proof bytes
+ 84 bytes for one joint HGSB record
= 674,356 bytes
```

That exceeds 512 KiB by **150,068 bytes**. Co-commitment by itself is
therefore insufficient. A successful design must also reduce the opened-value
schedule, for example through a proven single wide-field argument or a
different hash-based PCS/oracle batching construction. Three B128 coordinates
treated as a product ring do not satisfy this requirement.

## Production design budget

Use a 480-KiB engineering target, leaving 32 KiB below the 512-KiB consensus
cap:

| Class | Hard budget |
|---|---:|
| Envelope and commitment roots | 4 KiB |
| All algebraic/sumcheck/ZK messages | 64 KiB |
| Opened leaf/coset values | 128 KiB |
| Authentication/multiproof data | 240 KiB |
| Terminal data | 16 KiB |
| Unclassified/safety reserve | 28 KiB |
| **Target** | **480 KiB** |

Promotion requires one measured full-maximum-M4 artifact within this budget
and all of the following, rather than a parameter screen:

1. A complete adaptive ZK simulator for the grouped precommit relation,
   outer Spartan wrapper, BaseFold/FRI openings, aborts, and selective failure.
2. A QROM Fiat-Shamir/direct-product theorem covering every parallel lane,
   with independent challenges and query entropy. Any shared paths or indices
   must appear explicitly in that theorem.
3. A genuine field for wide challenges (for example E384) with the complete
   union-degree bound. Three independent B128 coordinates are not a field.
4. Soundness accounting for constraint reductions, batching, sumchecks, FRI
   folding/query error, PCS binding, proof-of-knowledge/extraction, and every
   union term at at least 128 post-quantum bits.
5. SHAKE256 output lengths justified for all proof and semantic commitments,
   plus exact transcript domain separation.
6. Full Rust-to-M4 statement/refinement evidence and the existing restart,
   mutation, truncation, trailing-byte, and replay gates.

No SmallWood, Poseidon, Pay1x2 narrowing, aggregation, or sidecar is involved
in this profile.
