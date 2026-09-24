# All-private IronSpartan input prototype

This directory contains an applyable patch against Binius64 revision
`3f96163049f680b2909f6545690bd929f1b48c44`. It adds explicit pinned private-input allocation to
the IronSpartan frontend. Hegemon's hidden SHAKE input bits can then share the existing private
oracle with the Keccak intermediates instead of occupying a separate precommit oracle.

## Full V5/Delta Pay1x2 result

The optimization was applied only to a disposable, hash-guarded copy of the frozen full Pay1x2
backend. This is the actual 2,448-byte witness, 478-byte network-bound public statement, forty
SHAKE permutation, prospective V5/Delta action, and exact composed HGSP envelope verifier—not the
repeated-parent proxy.

| `log_inverse_rate` | Proof bytes | Envelope bytes | Prove ms | Verify ms |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 381,200 | 381,212 | 1,212 | 175 |
| 3 | **350,800** | **350,812** | 2,065 | 185 |
| 4 | 355,856 | 355,868 | 4,341 | 205 |

Rate 3 is the measured local optimum. Relative to the frozen rate-3 precommit proof of 380,496
bytes, co-committing every constrained witness-source bit into the private oracle removes 29,696
bytes (7.80%). The 12-byte envelope fits 188 actions in the current 64 MiB capacity model, versus
174 before this layout change. A separate rate-3 harness repeat observed 5,474,025,472 bytes peak
RSS; timings and RSS are host-dependent, while transcript sizes are deterministic for this fixed
profile.

Every rate passed honest composed-envelope verification, all public/proof/trailing mutations,
envelope parsing and V5/Delta action-projection gates, relation/range/carry checks, and three fresh
forgery controls. Those controls intentionally show that a newly generated raw proof can accept a
mutated ciphertext hash, network binding, or balance tag while the authoritative composed verifier
rejects each mismatch.

Reproduce from the exact frozen sources with:

```sh
./run-full-pay1x2.sh /private/tmp/binius64-api-3f961630
```

The runner guards the four frozen backend hashes, its source-bearing local dependency closure, both
patches, and the measurement wrapper; refuses the wrong or dirty Binius revision; maintains a
16 GiB disk reserve; builds in `/private/tmp`; and deletes its exact source and target directories
on every exit. The applyable backend-only changes are in `pay1x2-all-private-layout.patch`, and the
frozen result is `full-pay1x2-measurement-2026-08-19.json`.

This result remains prototype-only: upstream fixes 96 query-security bits, SHA-256 proof hashing,
and GF(2^128). End-to-end zero knowledge and composed strict-PQ128 security are not established.

## Repeated-parent API spike

This is a real prover/verifier prototype, not a transcript size model. On 2026-08-19, the exact
serialized proof sizes were:

| Relation | `log_inverse_rate` | Proof bytes | Inout fields | Padded public fields |
| --- | ---: | ---: | ---: | ---: |
| 1 SHAKE parent, final digest public | 3 | 231,200 | 448 | 1,024 |
| 40-parent chain, final digest public | 2 | 381,200 | 448 | 1,024 |
| 40-parent chain, final digest public | 3 | **350,800** | 448 | 1,024 |
| 40-parent chain, final digest public | 4 | 355,856 | 448 | 1,024 |
| 40 independent parents, every digest public | 3 | 350,800 | 17,920 | 65,536 |

Rate 3 is therefore the measured local optimum for the 40-parent circuit. Hiding and reusing the
39 intermediate digests collapses the padded public geometry from 65,536 to 1,024 field elements,
although it does not change proof bytes because the same private and constraint oracle logarithms
remain dominant.

The 40-parent chain is only a proof-geometry proxy for forty real SHAKE256-448 permutations. It is
not the Pay1x2 relation and must not be presented as proving Pay1x2 semantics.

The change preserves the standalone proof topology. It does not aggregate transactions, expose a
witness, change SHAKE semantics, remove Booleanity constraints, or alter Fiat-Shamir ordering. In
the current prover, precommit and private commitments are both sent before the first verifier
challenge; this fixed relation therefore obtains no binding benefit from putting its source bits
in precommit. `write_private` also asserts exact private-allocation order, preventing a mismatched
circuit/witness traversal from aliasing source inputs with operation outputs.

`run.sh` exports a clean copy of the exact pinned source, applies the patch, copies the existing
one-block SHAKE256-448 relation into the disposable harness, generates real proofs, checks exact
proof consumption, rejects changed public input and proof bytes, and deletes both source and build
directories on exit. It refuses a dirty or wrong-revision source tree.
The harness uses a deterministic RNG solely to make measurements and tests reproducible; a real
prover must use fresh cryptographic randomness.

Run:

```sh
./run.sh /private/tmp/binius64-api-3f961630
```

Rust 1.97.1 is selected explicitly because the pinned Binius source uses a standard-library API
that is still unstable in Rust 1.91.1. `measurements.json` freezes only deterministic dimensions,
proof bytes, and rejection outcomes; timings are intentionally excluded.

The measurements remain non-production. Upstream still uses 96 query-security bits, SHA-256 proof
hashing, and GF(2^128); it does not satisfy Hegemon's strict-PQ128 profile.
