# HX512 joint classical-ROM zero-knowledge closure v1

## Verdict

This retained artifact closes the **specification of what a whole-view simulator must sample jointly**, not the proof that the deployed HX512 prover and verifier realize that simulator. The 33-field view is exhaustively covered, the component ranks and retry/abort arithmetic are executable, and the release gate is deliberately negative. Every complete-ZK, QROM, concrete-hash, compiled-refinement, and production flag remains `false`.

The strongest defensible statement is:

> Conditional on exact compiled PIOP/PCS/LVCS/DECS affine-kernel receipts, a correct lazy-Merkle ROM-programming refinement, exact bounded-sampler/prover-API refinement, an adaptive Fiat-Shamir programming proof, and a prefix-free tagged-product-oracle refinement, the construction plan matches the simulator order of SmallWood Theorems 2, 4, 6, 8, and 10. None of those cross-layer conditions is yet discharged.

This is not witness obfuscation. Independently random-looking fields are insufficient: their correlations can reveal the witness.

## Retained artifacts

- `certificate.json` is the canonical 33-field dependency ledger, theorem-premise map, exact transcript/oracle map, sampler law, source/PDF pin set, and negative authority manifest.
- `check_certificate.py` performs dependency-free exact finite-field ranks and integer probability comparisons, validates all source pins, checks all 33 fields and eight transcript events, and rejects any authority promotion.
- `test_check_certificate.py` retains eight focused mutation and arithmetic tests, including a counterexample where every marginal is uniform but the joint view reveals the witness.
- `EXECPLAN.md` records the scoped plan, discoveries, decisions, and outcome in the repository's ExecPlan format.

Run the bounded checks from the repository root:

```sh
python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/check_certificate.py --check-local-pdfs
python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/test_check_certificate.py
python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/check_certificate.py --require-complete
```

The first command must report `VALIDATED_FAIL_CLOSED`. The tests must pass. The last command must exit 2 with `BLOCKED`; that is the expected production result.

## Exact view boundary

The certificate preserves all 33 fields in the source certificate, but corrects their canonical HX512 wire roles without editing the owner file:

- the 4-byte PIOP nonce is forbidden and absent; event 5 directly samples six opening points;
- the legacy opened-witness mode tag and auxiliary counts/words are absent because fresh HX512 has one mandatory row-scalar grammar and `aux_count=0`;
- the canonical fresh inner prefix is `decs_root[64] || piop_input_digest[64] || h_piop[64]`;
- `piop_input_digest` and `h_piop` are deferred claims for the event-2 and event-4 SHA-512 queries. Verifier late checks must re-evaluate the byte-identical logical query and must not be counted as new programmable events;
- authentication-path lengths and nodes are deterministic, correlated projections of the sorted DECS query set and one Merkle tree; overlapping paths share nodes;
- every matrix is one canonical `u32-be rows || u32-be columns || u64-be field words` frame; authentication count and every compact-path length are `u32-be`; the parser must consume exactly the declared inner and outer lengths.

The first audited source snapshot lacked this prefix and routed HX512 opening derivation into the generic panic. A concurrent owner edit subsequently added the prefix and direct event-5 path. The separate ZK certificate owner file still describes the older width/endian grammar and legacy tags, so reconciliation remains a blocker. This artifact also requires the final source pin and compiled/refinement receipt; a later source edit invalidates the SHA-512 pin so wire drift cannot be silently accepted.

## Joint simulator, in construction order

The simulator construction is intentionally not the real verifier's chronological order. It preselects challenge targets and then programs the real eight-event chain, as SmallWood's ROM simulator does.

1. Copy the public statement, verifier context, profile, and grammar exactly.
2. Sample one uniform 512-bit salt and **all** `N=2^20` independent 576-bit leaf tapes before any opening set is known. Only the 48 indexed tapes are later serialized. Independence of the deployed RNG calls is still unproved.
3. Sample complete raw SHAKE candidate tapes for all four challenge events from their bounded laws. Preserve every rejected word and the 64 bytes read after the final acceptance as the next chain digest. Split the unconditional prover outcome from the emitted-proof law conditioned on all four samplers succeeding.
4. Conditional on `Gamma-prime` and the six PIOP points, run the Theorem-8 kernel: sample `P`, sample the packing-sum-zero `Q`, and set `M = Q - batched_F(P)`. High coefficients and openings are one affine projection, never independent fields.
5. For PCS Equation 6, sample width-minus-one coordinates and solve the final coordinate for each polynomial/opening. Combination heads are derived from those same values.
6. Sample the LVCS tails once, solve the omitted rows once, and evaluate the same rows at the 48 selected coset points. Recombination tails, subset values, omitted rows, and PCS heads therefore share one conditional law.
7. Conditional on the DECS coefficient challenge and opened `P(e)`, sample `R` and set `M(e)=R(e)-Gamma*P(e)`. Program each opened leaf using its exact tape. Assign each unopened maximal-subtree root once, derive/program shared ancestors once, and obtain one root and compact multiproof. This lazy algorithm still needs a proof that it equals the paper's full-tree ROM game, including collisions and prior adversarial queries.
8. Program the eight exact transcript requests to the preselected targets. Abort on a prior conflicting oracle query. Serialize only after every correlation and query succeeds.

The full conditional kernels and exact parents/outputs are machine checked in `certificate.json`.

## Why seven full ranks do not prove complete ZK

The source certificate correctly establishes seven useful local ranks for its synthetic q48/s6 fixture:

| Obligation | Exact rank |
|---|---:|
| Witness random highs | 6 |
| PIOP nonlinear mask | 5,151 |
| PIOP linear zero-sum mask | 2,052 |
| PCS Equation-6 randomizers | 180 |
| LVCS random tails | 98,880 |
| LVCS omitted rows | 12 |
| DECS masks and highs | 28,365 |

Those are diagonal/component facts. For an affine conditional view

`Y = A_random r + A_witness w + b`,

witness independence requires at least

`rank(A_random) = rank([A_random | A_witness])`

and equal fiber cardinality at every adaptive conditioning point. The checker retains the counterexample `Y1=r, Y2=r+w`: both marginals are perfectly uniform and each local randomness map has full rank, but `Y2-Y1=w`. No actual compiled joint matrices are attached, so `joint_affine_receipts` is empty and whole-view equality remains false.

## Exact retry and abort distribution

For a field stage requesting `n` values, the implementation examines at most `B=n+256` independent 64-bit SHAKE words and accepts `x<p`, where

`p = 2^64 - 2^32 + 1`.

The exact abort probability is

`2^(-64B) * sum_{j=257..B} C(B,j) * (2^64-p)^j * p^(B-j)`.

The checker proves the exact integer upper bound

`C(B,257) * (2^64-p)^257 / 2^(64*257)`.

For the retained non-authoritative `R=11,209` fixture, the three field-stage counts are 56,095, 56,045, and 6. Their strict abort-bound floors are respectively 5,860, 5,861, and 8,190 bits.

For DECS indexes, `N=2^20` divides `2^64`, so modulo reduction has no bias rejection. With `q=48` and `C=560`, the exact abort probability is

`N^(-C) * sum_{j=0..47} falling(N,j) * S(C,j)`,

where `S` is a Stirling number of the second kind. Its exact strict floor is 7,346 bits. The exact union of that value and the three field-stage upper bounds has a 5,859-bit strict floor.

These tiny probabilities do not remove the refinement obligation. The real API returns a poisoned-transcript error and performs no outer retry. A proof simulator must therefore match both the unconditional error mass and the proof distribution conditioned on success; it cannot independently condition each serialized field.

## Theorem-to-oracle mapping

SmallWood Theorem 10 assumes independent `Hash`, `XOF_i`, and `XOF'_i` for `i=1..4`. HX512 instead uses two physical families:

| SmallWood logical oracle | HX512 event/role | Physical primitive |
|---|---|---|
| `XOF_1` | 0, DECS root binding | SHA-512 |
| `XOF'_1` | 1, DECS coefficients | SHAKE256 |
| `XOF_2` | 2, PIOP input binding | SHA-512 |
| `XOF'_2` | 3, PIOP coefficients | SHAKE256 |
| `XOF_3` | 4, PIOP transcript binding | SHA-512 |
| `XOF'_3` | 5, six PIOP openings | SHAKE256 |
| `XOF_4` | 6, DECS opening binding | SHA-512 |
| `XOF'_4` | 7, 48 DECS queries | SHAKE256 |
| `Hash` | leaf, node, and history roles | SHA-512 |

Domain separation does not by itself prove the independent-oracle premise. The missing bridge is a prefix-free tagged-product-RO lemma that proves the full length-framed request encoding injective across every role, statement binding, event index, chain digest, descriptor, message, counter, leaf index, level, and node index. It must then relate the independent logical oracles to the two physical families and count one global adversarial query budget `Q` across all roles. Merkle/history programming events must be counted; the eight scheduled events are not the whole programming ledger.

The deferred h3/h5 checks are same-query re-evaluations. Treating them as fresh queries would change both distribution and GHCM event accounting.

## Exact theorem boundaries

- SmallWood Theorems 2, 4, 6, and 8 supply the correct component simulator structure, but the deployed joint conditional kernels and compiled maps are not refined.
- SmallWood Theorem 10 gives `Q*(2^-lambda + 2^-2lambda)`. With `lambda=256` and `Q<=2^64`, that formula alone has a 191-bit strict floor. This is only conditional arithmetic: the independent-oracle, filtering, adaptive programming, and implementation premises remain open.
- BCS16 Lemma 7.5 adds `p(x)*2^(-lambda/4+2)`. At `lambda=512`, even `p(x)=1` gives at most 126 bits, so that direct quantitative route is disqualified for strict `>128` security.
- CMS19 Theorem 8.6(3) says the BCS transform is statistical ZK when the IOP is HVZK. It does not itself prove that HX512 is that exact BCS construction or refine this wire/parser/prover API.
- GHCM20 Proposition 2 gives an adaptive reprogramming bound only after every programmed input distribution and its conditional maximum probability are mapped. HX512 lacks that all-events entropy/refinement receipt and the concrete SHA-512/SHAKE256 QROM bridge.

The pinned paper pages and SHA-512 digests are in `certificate.json`; local PDF verification is optional so the retained artifact does not depend on `/private/tmp` remaining populated.

## What must exist before any flag can change

At minimum, a successor artifact must carry:

1. frozen final relation/profile/identity and exact compiled source pins;
2. actual joint affine matrices (or equivalent executable kernels) with source-map hashes and rank-containment/equal-fiber receipts for every adaptive conditioning point;
3. one executable joint simulator that emits exactly the canonical bytes and verifier state, including the no-nonce prefix and deferred same-query checks;
4. a full-tree-to-lazy-Merkle ROM-programming proof and mutation tests for shared-path inconsistencies;
5. exact sampler trace/prover-error refinement, not only negligible abort bounds;
6. the tagged-product-oracle, adaptive Fiat-Shamir, GHCM all-event, QROM, and concrete-hash bridges;
7. canonical parser/serializer and compiled prover/verifier refinement;
8. retained real proof bytes plus mutation, restart, reorg, fresh-node, and release-manifest receipts.

Until then, `--require-complete` must fail and production must remain disabled.
