# M4 complete-ZK transform audit

Verdict: **the retained M4/BaseFold opening topology is disqualified for complete zero knowledge**. It cannot instantiate the existing public-only `WholeProofViewSimulator` because a queried initial leaf opens `RS(message)[x]` separately from `RS(mask)[x]`. The two valid witnesses of the Boolean tautology `b*b=b` therefore induce disjoint opened-view supports (conditional total-variation distance `1`). Merkle randomization authenticates this value; it does not hide it.

This is a sealed negative result, not a provisional winner. All capability and production flags in the executable certificate remain false.

The strongest repair direction is CFW26 Hiding-WHIR, but it is not an opening-layer swap for retained M4. The merged Plonky3 implementation uses a parallel two-adic multiplicative-DFT protocol, while M4 uses characteristic-two Binius additive Gao–Mateer codes. Moreover, CFW26's ready-made full-ZK R1CS clause assumes characteristic different from two. A theorem-valid next attempt must therefore either:

1. compile the Boolean relation into R1CS over an odd two-adic field and adopt the whole Hiding-WHIR relation/transcript stack; or
2. prove a new characteristic-two HVZK/RBR theorem and implementation for the exact additive M4 relation.

Neither route exists in the retained source, so neither qualifies now.

## Reproduce the bounded checks

These commands use only Python's standard library and suppress bytecode caches:

```sh
python3 -B .agent/hardening/m4-complete-zk-transform/test_m4_complete_zk_audit.py
python3 -B .agent/hardening/m4-complete-zk-transform/m4_complete_zk_audit.py --compact
python3 -B .agent/hardening/m4-complete-zk-transform/m4_complete_zk_audit.py \
  --check-certificate .agent/hardening/m4-complete-zk-transform/certificate.json \
  --check-repo . \
  --check-pinned-binius /Users/pldd/.cargo/git/checkouts/binius64-4521fba04f156135/3f96163
```

No Cargo, rustc, Lake, build, proof generation, dependency installation, clone, or large download is used.

## Artifact map

- `hardening.md`: decisive finding, proof, byte ledger, and repair boundary.
- `THEOREM_MAP.md`: exact theorem/implementation premises and their status.
- `m4_complete_zk_audit.py`: executable finite-field, distribution, byte, and rational checks.
- `test_m4_complete_zk_audit.py`: algebra and mutation tests.
- `certificate.json`: fail-closed canonical executable result.
- `source-manifest.json`: reviewed-source hashes and external primary sources.
- `proposals/hiding-whir-replacement.md`: two theorem-valid future routes.
- `implementation/README.md`: exact topology requirements for any future repair.

