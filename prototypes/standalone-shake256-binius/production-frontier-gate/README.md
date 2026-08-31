# Production proof-frontier admission gate

This directory is the hard boundary between proof-size experiments and the
Hegemon production frontier. A smaller proof is not a frontier point unless all
six gates pass independently:

1. the prospective full fixed-slot V5/Delta relation: exact 853-byte
   `HGF4ST02` statement, 56-byte semantic digests, two inputs, two outputs,
   four balance slots, 61-bit values, typed Ordinary/Accumulator/ValueLock
   notes, all five private-authorization transitions, and the exact 9-accepted
   / 7-rejected activity-mask matrix;
2. exact action, network, backend, profile and version binding;
3. complete zero knowledge for the full witness;
4. composed post-quantum security of at least 128 bits with complete QROM loss
   accounting;
5. canonical, exact-consuming proof parsing over two retained clean proof
   artifacts; and
6. Lean-kernel semantic/refinement closure plus production differential parity.

`frontier_gate.py` hashes the live production surface and requires a canonical,
content-addressed certificate from a different trusted issuer for each gate.
Certificates must live below `evidence/verified/`; candidate claims or benchmark
booleans cannot replace them. Each exact certificate digest must also be
allowlisted in the sealed policy, so a candidate cannot mint its own trusted
issuer string. Any missing, stale, malformed, symlinked,
self-issued or failing evidence rejects the point. Aggregation and external
sidecar authority are categorically rejected for this per-transaction frontier.

Run the current candidate through the gate:

```sh
python3 prototypes/standalone-shake256-binius/production-frontier-gate/frontier_gate.py
```

The command currently exits `1`. The retained 65,440-byte historical M4
measurement has no retained proof artifacts, proves only Pay1x2, is
transparent, uses a nonqualifying 96-bit/SHA-256/GF(2^128) profile, has no
release-manifest authorization, and has no closed full-relation
semantic/refinement certificate. The new 83-Keccak full-relation M4 source has
not been compiled or proved under the disk gate and remains transparent and
non-PQ128. Neither point has production-frontier status.

The sealed production surface includes the scalar 853-byte relation and action
adapter, exact HGSP composed envelope, concrete wallet-v3 ciphertext
canonicalizer, single-main M4 source, prospective action/manifest integration
surfaces, and formal verifier/refinement boundaries. The finite-vector bridge is
sealed end to end: its Lean generator, generator target wiring, Lean toolchain
and dependency manifest, committed JSON fixture, and no-serde Rust differential
test all contribute bytes to the same production-surface digest. Per-path
mutation and deletion regressions keep that inventory fail closed. No
certificate digest is authorized. The frontier is therefore intentionally
empty.

The policy is sealed by a digest embedded in the executable. Changing the
relation or security target is a reviewable policy change, not a candidate
optimization. `--surface-digest` prints the current source-bound production
surface digest for independent certificate generation.
