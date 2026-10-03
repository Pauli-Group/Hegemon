# Aurora binary-relation negative closeout

This directory retains a fail-closed verdict: **no executable characteristic-two sparse R1CS was
produced**. There are no canonical expanded `A/B/C` coordinates, selected binary extension field,
Aurora backend, proof artifact, proof-byte measurement, security certificate, native refinement,
release authority, or production route.

`relation_manifest.json` retains the last reproducible pre-correction source-macro projection only:

- `m = 37,364,095`
- `n = 21,531,353`
- `l = 9,704`
- `nnz = 156,526,483`
- projected padding `H1 = 2^26`, `H2 = 2^25`, and `k+1 = 2^14`
- `6,679` canonical public-zero inputs would be needed, shifting every original private/derived
  index by `6,679`

Those numbers are not final geometry. The retained source cost was based on `29,509,133` odd-field
macro rows, while the later semantic source requires `29,510,157`: a `1,024`-row policy-master
repair. No corrected binary lowering or nonzero count was produced, so corrected `m`, `n`, and
`nnz` are null.

The policy-master boundary is explicit. The private transport contains two independent 64-byte
masters at offsets `6,088` and `6,152`. Mode-specific zero/equality and call-selection constraints
must cover all 2,560 semantic rows. Even a correct relation would not establish wallet entropy
generation, uniform sampling, retention, erasure, or lifecycle.

The all-W64 V2 verifier context is exactly:

    manifest_root64 || parent_height:u64le

It is not the snapshot digest. The statement snapshot is derived from
`parent_height:u64le || manifest_root64`. A native verifier must still obtain and authenticate the
canonical parent manifest root and height; no such refinement exists here. Policy version zero is
valid, and legacy 48-byte authorities must be rejected rather than padded, truncated, or rehashed.

Run the dependency-free readback checks from the repository root:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/compiler.py --check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/compiler.py --summary
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/test_compiler.py

The checker has no write or compile mode. Every authority value in the retained ledger is false;
corrected geometry, proof bytes, and security bits remain null.
