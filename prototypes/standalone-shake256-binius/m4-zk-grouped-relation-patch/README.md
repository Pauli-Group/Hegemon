# M4 grouped outer-relation source patch

This directory preserves a source-only Phase-A repair applied **after** the frozen coefficient-aware trace-mask patch. It removes the separate outer precommit functional and proves only

```text
<K,T_precommit> + <V,T_private> = batched_sum - public_eval
```

as one grouped claim. Individual term claims are absent from the API and transcript. Independent masks contribute one aggregate sigma, one gamma masks every hiding oracle, unequal oracle sizes are padded per term, one reduced alpha remains per oracle, and Phase B is unchanged. The wrapper prover, concrete verifier, symbolic builder, and replay path bridge exactly one aggregate scalar.

```text
base_revision = 3f96163049f680b2909f6545690bd929f1b48c44
coefficient_prerequisite_sha256 = 684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54
grouped_patch_sha256 = 37dfdee589e476c09fe5c955bd46942cd5aa293a3177d7a43d07f14aeb8ef9df
grouped_patch_bytes = 49656
source_static_pass = true
compiled = false
roundtrip = false
complete_ZK = false
strict_security = false
proof_bytes = null
frontier_eligible = false
```

The code is field-generic at its public seam, but this artifact is evidence only for pinned B128 weak/profile mechanics. Same-field B128 masking is diagnostic; it is not evidence for E384, `GhashSq256b`, another extension-field construction, strict PQ security, or complete zero knowledge.

Apply the coefficient patch first, then this delta. `check_grouped_relation_patch.py` pins the resulting 15 files, validates the aggregate-mask and padding identities, checks wrapper event symmetry, and ratchets the unchanged Phase-B slices. A clean ordered `git apply --check`, rustfmt check, and `git diff --check` pass. Cargo and proof execution were withheld because free disk remained below the 28 GiB gate.

## Artifacts

- `hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.patch` — exact 15-file delta.
- `hegemon-m4-zk-grouped-relation-after-coefficient-3f961630.sha256` — patch, checker, plan, report, and post-stack source hashes.
- `check_grouped_relation_patch.py` — read-only dependency-free static gate.
- `hegemon-m4-zk-grouped-relation-report.md` — construction and validation boundary.
- `hegemon-m4-zk-grouped-relation-execplan.md` — implementation and deferred executable plan.

No proof-size reduction is claimed until an honest proof is generated, exact-decoded, verified, and reproduced.
