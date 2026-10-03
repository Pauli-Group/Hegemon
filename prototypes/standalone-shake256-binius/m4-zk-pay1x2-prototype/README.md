# Rejected Pay1x2 M4 ZK-wrapper experiment

**Verdict: rejected; not a zero-knowledge frontier point.**

This isolated executable routes the exact chip-free, single-main Pay1x2 M4
constraint system and witness through the pinned upstream Binius64 ZK wrapper.
It does **not** turn on trace masking in the transparent 65,440-byte M4 wire.

The transform exercised here combines:

- 128 satisfiable, relation-bound random `a & b = c` blinding rows (384 private
  words), without increasing the original `2^15` private-word or AND tiers;
- upstream masked BaseFold oracle encoding;
- one-time padding of private inner-verifier messages;
- symbolic checking of the inner verifier; and
- an outer Spartan proof.

The active blinding rows attempted to address a known review seam in the pinned
wrapper: an oracle-relation evaluation is sent outside the one-time-padded inner
messages. The attempt fails the complete-ZK gate. The appended words occupy a
contiguous region sharing high multilinear-address bits, so an evaluation point
can annihilate every added mask coefficient. For honest uniform challenges the
bad-event estimate is about `5 / 2^128`, already above the target; an interactive
malicious verifier can force the annihilating coordinates. The measured proof is
preserved only as a rejected experiment.

The source also contains a compile-checked strict-hash mode using
`StrictShake256HashSuite` and `StrictTranscriptDigest`. No strict-hash setup or
proof was run after disk headroom fell below the 28 GiB admission gate. That hash
component does not repair the ZK failure or the GF(2^128)/96-bit profile.

## Structural replacement under test

`zk_trace_claim_mask_model.py` specifies the narrow repair for the remaining
clear trace-evaluation claim. The trace PCS must already be independently
hiding. Before the verifier evaluation point exists, the prover commits a fresh
one-time field key `k` and the shifted trace `pi' = pi + k * 1`. Because the
Boolean equality tensor always sums to one, the only public claim becomes
`c = <pi, eq_r> + k = <pi', eq_r>` for every `r`; there is no annihilating
evaluation point. The outer proof must constrain the shift equation and keep
`k` private.

This is not yet a ZK compiler. Its admission inventory fails closed unless the
compiled circuit has exactly one main equality-evaluation claim, no other clear
witness-dependent claim, no numbered chip, no lookup/table relation, and an
independently proved hiding trace PCS. Reusing `k` across proofs leaks the XOR
of the two original claims, so production must use fresh OS entropy and enforce
non-reuse. The model keeps `simulator_theorem`, `rng_nonreuse_evidence`,
`maximum_relation_compiler_inventory`, `complete_zero_knowledge`, and
`frontier_eligible` false.

`structural-trace-evaluation-mask.patch` is the corresponding source-level
implementation against pinned Binius revision
`3f96163049f680b2909f6545690bd929f1b48c44`. It adds an explicit
equality-evaluation oracle contract, commits `pi + k * 1`, sends only `s + k`,
and constrains `(s + k) - s - k = 0` inside the outer Spartan relation. The
wrapper rejects a second inner oracle, a second relation, or an ordinary
relation on the masked oracle. The exact patch is rustfmt-clean and
`git diff --check` clean, but it
is deliberately **uncompiled and unmeasured**: free disk fell below the hard
20 GiB reserve before a build could be admitted. It is therefore implementation
work, not ZK evidence or a frontier point.

The disk-light property suite checks the shift identity for arbitrary B128
points through eight variables, the equality-basis sum, exact one-time-pad
distribution on an exhaustive 8-bit projection, the key-reuse leakage
counterexample, context/nonce-separated test derivation, and every compiler
inventory rejection:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test_zk_trace_claim_mask_model.py
```

## Reproduce

Do not run a proof unless at least 28 GiB is free. From this directory, after the
exact M4 dependency has been built:

```sh
CARGO_TARGET_DIR=/private/tmp/hegemon-m4-zk-target \
  cargo +1.97.1 build --release --locked --offline

/private/tmp/hegemon-m4-zk-target/release/hegemon-m4-zk-pay1x2-prototype \
  --rate 3 --seed 5207646907099205210 --compare-freshness \
  --proof-out /private/tmp/hegemon-m4-zk-blinded-r3.proof
```

The default uses system entropy. `--seed` switches to deterministic test coins
and is only for reproducible evidence; the JSON output marks that mode
`test_only: true`.

The bounded rate sweep is:

```sh
for rate in 1 2 3 4 5 6; do
  /private/tmp/hegemon-m4-zk-target/release/hegemon-m4-zk-pay1x2-prototype \
    --rate "$rate" --seed 5207646907099205210
done
```

See `measurements/rate-sweep-2026-08-21.json` for the sealed, rejected results
and exact claim boundary.

## Claim boundary

The executable checks an honest round trip, statement/proof tamper rejection,
canonical transcript exhaustion, fresh-coin proof variation, deterministic
replay under a fixed test seed, rejection of malformed blinding rows, and
absence of literal 16-byte private-witness blocks.

Those tests do not overcome the annihilating-coordinate counterexample and are
not a ZK simulator proof, a local formal ZK proof, or an audit.
The pinned stack also has a 96-bit query budget, SHA-256, and GF(2^128), so this
prototype is neither strict-PQ128 nor production-authorized. The compact
transparent terminal-target and padding-fiber optimizations are deliberately
disabled because their compatibility with masked oracles is unproved.
