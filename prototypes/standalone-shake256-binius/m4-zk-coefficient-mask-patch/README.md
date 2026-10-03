# M4 coefficient-aware trace-mask source patch

This directory preserves the frozen source-only repair for the final rank-one M4 trace-evaluation claim. It is an audited experiment, not an accepted proof frontier point.

```text
base_revision = 3f96163049f680b2909f6545690bd929f1b48c44
patch_sha256 = 684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54
patch_bytes = 85454
complete_ZK = false
strict = false
strict_PQ = false
compiled = false
roundtrip = false
proof_bytes = null
frontier_eligible = false
```

The patch replaces the invalid bare trace mask with the exact coefficient-aware relation

```text
c = product_j (1-r''_j) = eq_r_double_prime[0] = sum_x rs_eq_ind(x)
M = s + k*c
```

and guarantees `c != 0` through a dedicated fixed-shape two-candidate sampler used only by the final private-trace ring switch. All fourteen B128 candidate draws are consumed before a typed `ChallengeAbort`; ordinary and public ring switches retain their original seven-draw schedule. The outer wrapper reserves the first committed, nonreused precommit scalar for `k`, shifts the trace by `k`, and enforces `M-s-k*c=0`.

The arithmetic/transcript repair passed two independent source audits. It still does not establish complete zero knowledge. Promotion requires a joint simulator for the correlated precommit and shifted-trace BaseFold commitments/openings, outer Spartan and OTP composition, a complete inventory of witness-dependent clear functionals, abort-conditioned ROM/QROM analysis, executable leakage tests, a full M4 roundtrip, and a strict E384/wide-challenge backend.

The transform is not intrinsically Pay1x2-specific. The current 83-Keccak maximum relation is structurally compatible because it is one main M4 circuit with no numbered chips and inline word/BitAnd constraints. This archive does not provide the missing full-M4 wrapper/configuration entry point or executable evidence. Setup must still derive hiding specs for both precommit and trace and reject unless the compiled maximum relation has exactly one supported trace relation and no IntMul-added oracle relation.

## Artifacts

- `hegemon-m4-zk-coefficient-mask-source-only-3f961630.patch` — exact 25-file source patch.
- `hegemon-m4-zk-coefficient-mask-source-only-3f961630.sha256` — patch and per-file source hashes.
- `hegemon-m4-zk-coefficient-mask-source-only-3f961630-report.md` — structural delta, applicability, validation, and simulator obligations.
- `hegemon-m4-zk-coefficient-mask-execplan.md` — source-only implementation record.

Frozen ancillary hashes before this README was added:

```text
manifest_sha256 = 39296570b47e3dccc50733eb9bfdc746abde27e404aad9f17b38eeaa0f3a4b0c
report_sha256 = 83189b10ae78d31aa266aecdfe6952ce0af41dfac948f32da838a3b51d8305cf
execplan_sha256 = 288a38938f0871eb3d26c17793336fdd5a5646101b7f616265eabffa219bd1c5
```

No Cargo command, compilation, proof generation, or proof measurement was run while freezing this directory because available disk remained below the 28 GiB admission gate.
