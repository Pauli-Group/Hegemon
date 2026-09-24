# Frozen coefficient-aware M4 trace-mask source patch

Status: `SOURCE_AUDIT_PASS`, `COMPILED=false`, `ROUNDTRIP=false`, `COMPLETE_ZK=false`, `STRICT_PQ=false`, `FRONTIER_ELIGIBLE=false`.

This is an isolated source-only repair for the final rank-one trace-evaluation claim. It is not an end-to-end zero-knowledge proof and is not release evidence.

## Frozen identity

- checkout: `/private/tmp/hegemon-zk-structural-patch`
- branch: `codex/m4-zk-structural-repair`
- immutable base: `3f96163049f680b2909f6545690bd929f1b48c44`
- patch: `/private/tmp/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch`
- patch bytes: `85,454`
- patch SHA-256: `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54`
- source manifest: `/private/tmp/hegemon-m4-zk-coefficient-mask-source-only-3f961630.sha256`
- ExecPlan: `/private/tmp/hegemon-m4-zk-coefficient-mask-execplan.md`
- diff size: 25 files, 1,277 insertions, 135 deletions

## Exact repaired invariant

Only the final private-trace ring switch uses fixed-shape paired challenges. For each of the seven B128-over-B1 row-batching coordinates, the prover and verifier consume both candidates and select the first unless it equals one, otherwise the second. If both equal one they finish consuming all fourteen draws and return typed `ChallengeAbort`.

The selected coordinates satisfy

`c = product_j (1-r''_j) = eq_r_double_prime[0] = sum_x rs_eq_ind(x) != 0`.

The trace oracle is committed as `pi + k*1`, where `k` is the first fresh scalar in the already committed outer precommit segment. The only allowed clear trace relation is replaced by

`M = s + k*c`,

and the outer circuit enforces `M-s-k*c=0`. Both the precommit oracle and shifted trace oracle must have BaseFold `is_zk=true`. The key is committed before any challenge, is consumed exactly once, and cannot be reused as a transcript OTP.

Ordinary and public ring switches retain the upstream seven-draw schedule and ordinary oracle methods. Masked mode fails closed unless there is exactly one first/only inner trace oracle and no IntMul-added relation.

The paired rejection probability in the random-oracle model is

`1-(1-2^-256)^7 <= 7*2^-256 ~= 2^-253.19`.

Conditioned on success, every selected coordinate is uniform on `GF(2^128) \ {1}`.

## Source-derived structural delta

Relative to the previous wrapped rank-one path:

- final trace challenges: 7 to 14, i.e. +7 B128 Fiat-Shamir draws (+112 derived XOF bytes), not serialized;
- serialized challenge bytes: +0;
- ring-switch proof messages: unchanged;
- selected outer inout challenge wires: unchanged at seven;
- masked-claim inout fields: unchanged at one; the masked field replaces the clear claim;
- logical precommit fields: +1 for `k`;
- outer relation IR before compiler elimination: +1 multiplication, +1 zero/linear constraint, and +2 private temporaries;
- selection constraints in the outer circuit: +0, because the native transcript recomputes selection and supplies only the selected public value.

Exact compiled constraints and proof-byte delta are unknown. The extra precommit field or relation may cross a power-of-two padding/FRI tier, so `+0 proof bytes` is not a supported claim.

## Applicability to the 83-Keccak full M4 relation

Structurally eligible, but not yet integrated or demonstrated.

The current full source relation is one main M4 circuit with no numbered chips, and its 83 Keccak-f calls are inline BitAnd/word constraints rather than IntMul or extra oracle relations. That matches this patch's one-trace/rank-one gate in principle. The transform is not Pay1x2-specific at the algebraic seam: trace length and Keccak call count do not change `c=sum(rs_eq_ind)`.

However, this patch does not add a full-M4 wrapper/configuration entry point, has not compiled the 83-call source, and has not proved that the current maximum-production build still has exactly one supported oracle relation after compilation. Before use, setup must derive the full M4 oracle specs with both trace and outer precommit hiding enabled and reject unless the compiled relation count/rank is exactly the supported one. Pay1x2 measurements cannot be reused for the full relation.

## Smallest reusable joint-hiding PCS seam

The smallest existing seam is the current combined multi-oracle BaseFold opening, not a new grouped-relation protocol:

1. `fri::encode_masked` commits every `is_zk` oracle with its own independent equal-length mask.
2. BaseFold `finish` computes and sends one mask inner product per ZK oracle.
3. A shared post-commitment gamma folds each message with its independent mask.
4. All oracle relations are reduced and opened in one combined BaseFold/FRI proof.

This can carry the correlated outer precommit oracle `K=(k, otp...)` and shifted trace `pi+k*1` without adding a second standalone PCS. It is an implementation mechanism, not yet a joint-hiding theorem.

## Remaining simulator/composition obligations

Promotion requires all of the following:

1. A joint BaseFold simulator for multiple independently masked but witness-correlated oracles, including adaptive public linear relations and the common gamma/batching challenges.
2. A proof that the view containing commitments to `K` and `pi+k*1`, the masked scalar `M`, every per-oracle mask inner product, all sumcheck/FRI messages, and Merkle openings is witness independent up to the stated leakage.
3. Composition with the outer Spartan simulator for `M-s-k*c=0` and all OTP-encrypted witness-dependent inner messages, including first-key nonreuse and exact event ordering.
4. Abort-conditioned Fiat-Shamir/ROM and QROM analysis for paired selection; source-level symmetry alone is not a QROM theorem.
5. A complete inventory/rank proof that every witness-dependent clear functional in the maximum relation is either OTP protected or included in the jointly simulated PCS view.
6. Executable witness-indistinguishability/leakage negative tests and a real full-M4 prove/verify/mutation roundtrip.
7. A strict E384/wide-challenge backend and composed PQ128 accounting; B128 ring-switch soundness remains about 2^-125.193 classically and is not strict 128-bit evidence.

## Static validation and disk gate

Passed:

- `git diff --check`
- standalone `rustfmt --edition 2024 --check` over every changed Rust file
- repository-wide caller sweep for the fallible M4 `prove_chip` API
- exhaustive-match sweep for the new typed channel abort
- searches confirming no live bare `s+k`, global paired sampler, or panic-based abort path
- two independent source audits, both reporting no remaining scoped P0/P1

Source tests were added for first-candidate selection, fallback, both-one typed abort, all-pair consumption, nonzero coefficient, `sum(rs_eq_ind)=eq_r_double_prime[0]` across supported packing widths, uniform trace-shift algebra, replay acceptance, and masked-claim mutation rejection.

Not run: Cargo, compilation, tests, prover, verifier, proof measurement, or strict-hash build.

Final disk sample: `26,258,512 KiB` available on `/System/Volumes/Data` (about 25.0 GiB), below the hard 28 GiB admission gate. No Cargo target or proof artifact was created.

## Changed files

- `crates/iop-prover/src/basefold/channel.rs`
- `crates/iop-prover/src/channel/mod.rs`
- `crates/iop/src/basefold/channel.rs`
- `crates/iop/src/channel/mod.rs`
- `crates/ip-prover/src/channel.rs`
- `crates/ip/src/channel.rs`
- `crates/ip/src/fracaddcheck.rs`
- `crates/ip/src/prodcheck.rs`
- `crates/ip/src/sumcheck/error.rs`
- `crates/m4-prover/benches/prove_hash_primitives.rs`
- `crates/m4-prover/src/composite.rs`
- `crates/m4-prover/src/prove.rs`
- `crates/m4-prover/tests/prove_hash_primitives.rs`
- `crates/m4-verifier/src/verify.rs`
- `crates/prover/src/error.rs`
- `crates/prover/src/prove.rs`
- `crates/prover/src/ring_switch.rs`
- `crates/recursion/src/filler.rs`
- `crates/spartan-prover/src/wrapper/replay_channel.rs`
- `crates/spartan-prover/src/wrapper/zk_wrapped_prover_channel.rs`
- `crates/spartan-verifier/src/wrapper/builder_channel.rs`
- `crates/spartan-verifier/src/wrapper/zk_wrapped_channel.rs`
- `crates/verifier/src/ring_switch.rs`
- `crates/verifier/src/verify.rs`
- `crates/verifier/src/zk_config.rs`
