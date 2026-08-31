# M4 n15 random-tail source integration

This directory preserves a narrow source-only integration seam for putting fresh prover randomness
in every whole unused B128 symbol of the maximum one-main M4 trace commitment. It is not a proof of
zero knowledge, a strict-security result, a proof-size measurement, or a frontier point.

The delta applies only after this exact prerequisite stack on pinned Binius revision
`3f96163049f680b2909f6545690bd929f1b48c44`:

1. `../m4-zk-coefficient-mask-patch/hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch`,
   SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54`.
2. `../m4-zk-grouped-relation-patch/hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch`,
   SHA-256 `37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df`.
3. `hegemon-m4-random-tail-after-zk-stack-3f961630.patch`, SHA-256
   `0602c48f3cc7545186e625d033c3cefe4563431499977531e365144d12232c18`.

The prerequisites remain prerequisites even though this seam uses the ordinary one-main M4
channel. They are the selected coefficient-aware and grouped-relation source stack; applying this
delta directly to stock source is unsupported. None of the three patches establishes complete ZK
or strict security.

## What is integrated

`binius_prover::IOPProver::prove_with_random_trace_tail` constructs one word buffer as follows:

```text
[ exact declared private words | zero high half if the last symbol is partial |
  fresh uniform whole B128 symbols through the deterministic n15 boundary ]
```

That exact buffer is passed both to `pack_witness` and `prove_shift_reduction`. This shared-buffer
rule is essential. Randomizing only the packed commitment would leave the shift reduction folding
the old zero tail, so its trace evaluation would disagree with the later ring-switch opening.
Operation columns still read the original `ValueVec`, so the random tail is not introduced as a
circuit value.

`RandomTraceTailGeometry` exports the exact runtime values
`log_trace_symbols`, `total_symbols`, `active_words`, `active_symbols`, and
`random_tail_symbols`. `active_symbols` is `ceil(active_words / 2)`: if the active word count is
odd, its containing B128 symbol remains part of the active prefix and the unused high 64 bits stay
zero. No source assumption such as 26,000 symbols is substituted for the compiled value.

The low-level gate additionally requires the existing shift reduction to span the full n16 word
domain corresponding to an n15 B128 message. Without that equality, extending the word slice would
change the number of sumcheck rounds while the verifier retained the old dimension. Such a system
is rejected before randomness or transcript state is consumed.

`ProverM4::prove_main_with_random_trace_tail` admits only:

- zero numbered chips and zero witness tables;
- zero IntMul constraints;
- exactly one committed oracle;
- an unmasked oracle whose message and main-trace dimensions are both exactly n15; and
- an exact private-word/key prefix with at least one whole unused B128 symbol.

All structural checks run before the transcript channel is created. The verifier is unchanged and
continues to derive its deterministic dimensions from the constraint system. The random-tail
delta does not edit the maximum relation; its separately optimized live sources are pinned at
SHA-256 `f8ac13bdd657b47d614d8a7b65524ddb21498efcedf0e9888d0951d7fa851d6b` for `src/lib.rs` and
`d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c` for `src/main.rs`.

## Why the tail is outside the relation

The source-static exclusion chain is:

- `crates/core/src/constraint_system/system.rs` rejects every value index outside its declared
  segment, making padding unaddressable.
- `crates/prover/src/protocols/shift/phase_1.rs::build_g` zips the supplied words with the shorter
  `segment.key_ranges`, so tail words create no keys.
- `crates/prover/src/protocols/shift/monster.rs::build_monster_segments` materializes exactly
  `segment.n_words()` selector values and zero-resizes the remainder.
- Phase 2 multiplies the randomized witness fold by that zero-tailed monster polynomial.
- `crates/verifier/src/protocols/shift/verify.rs` cuts its wiring tensor at `cs.n_private`, so no
  operand can address a tail word.

The checker ratchets these anchors and runs odd/even packing plus zero-tail-selector KATs. This is
source evidence for relation exclusion, not compiled or formal evidence.

## Exact observation export is still blocked

The active-prefix count is exported. The complete union of clear B128-linear observations is not.
Current pinned APIs pass only already-evaluated field elements to `IPProverChannel::send_one` and
`send_many`; they discard the coefficient row and its derivation. The missing rows include at
least:

- every tail-dependent phase-2 shift sumcheck round polynomial and `witness_eval` in
  `crates/prover/src/protocols/shift/phase_2.rs`;
- all 128 `s_hat_v` ring-switch coordinates in `crates/prover/src/ring_switch.rs`;
- the trace-relation Phase-A sumcheck messages and reduced alpha in
  `crates/iop-prover/src/basefold/channel.rs`; and
- every actual queried codeword/coset value and terminal value selected in
  `crates/iop-prover/src/fri/fold.rs` and `query.rs` after the Fiat--Shamir schedule is known.

A sound rank-audit interface must add a transcript-synchronized `LinearObservationSink` carrying
an oracle identifier, phase/kind, exact B128 coefficient row, observed value, and public challenge
provenance. Shift phase 2, ring switch, BaseFold Phase A, and the FRI query/terminal paths must emit
through it after their real adaptive challenges and indices are fixed. A verifier/replay path must
rederive or bind the same schedule before the E256 coordinates are expanded and the union matrix
is audited once. Adding a callback only around point openings is insufficient. Even a complete
realized matrix does not by itself prove adaptive BCS/ROM zero knowledge because the commitment
root and Fiat--Shamir schedule depend on the random tail.

## Strict hash boundary

This patch is commitment-hash agnostic and does not alter Binius hashing. Any downstream strict PCS
must use SHAKE256 with a 512-bit, 64-byte commitment digest. A 56-byte SHAKE output is non-strict.
No strict digest, mixed-field backend, QROM reduction, or proof byte count is integrated here.

## Disk-safe validation

From a clean pinned Binius checkout, apply the three patches in the order above, then run from the
Hegemon repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python3 \
  prototypes/standalone-shake256-binius/m4-random-tail-integration-patch/check_random_tail_integration.py \
  --tree /path/to/post-stack-binius
```

The result must contain `"status": "SOURCE_STATIC_PASS"`,
`"active_prefix_exported": true`, and
`"complete_linear_observation_union_exported": false`. The checker pins 20 post-stack source
files, the three patch hashes, the five-file delta scope, and the separately pinned maximum source.

Free disk was about 25,016,296 KiB, below the 28 GiB Cargo admission gate. No Cargo command,
compilation, prover, verifier, or proof-size measurement was run. The authority state therefore
remains:

```text
source_static_pass = true
compiled = false
roundtrip = false
complete_linear_observation_union_exported = false
complete_ZK = false
strict_security = false
proof_bytes = null
frontier_eligible = false
```

## Artifacts

- `hegemon-m4-random-tail-after-zk-stack-3f961630.patch` — exact five-file post-prerequisite delta.
- `check_random_tail_integration.py` — read-only source/hash/algebra gate.
- `hegemon-m4-random-tail-integration-report.md` — construction boundary and source anchors.
- `hegemon-m4-random-tail-integration-execplan.md` — completed source milestone and deferred
  executable/observation work.
- `hegemon-m4-random-tail-after-zk-stack-3f961630.sha256` — artifact and post-stack source manifest.
