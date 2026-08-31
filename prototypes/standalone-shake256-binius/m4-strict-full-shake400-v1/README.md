# Full-M4 SHAKE256-400 proof-size prototype

This isolated prototype retains the exact maximum M4 relation and replaces only the proof
Merkle/Fiat-Shamir digest width: 64-byte SHAKE256-512 becomes 50-byte SHAKE256-400. The rate-3
artifact contains three 448,224-byte proofs in one exact-consumed 1,344,828-byte envelope. It is
281,568 bytes (17.31%) smaller than the retained 1,626,396-byte SHAKE256-512 baseline.

The authoritative retained run is `artifacts/shake400-v1-final`. Its proof SHA-256 is
`0ce525a6c790e1be4c47cf6d482b767f455616f06e5ab013d561378d6ab81a56`; its source-bundle SHA-256
is `99e6422d8bdf04a28f030a1ab4f02391ba22408d39424b1c42b1593b0a00c2e0`. The bundle binds the
50-byte hash profile and the BufferPool U50 patch. Restart verification, exact consumption,
per-proof mutation, statement mutation, truncation, trailing-byte, and fresh-forgery replay gates
all pass.

The proof carries the full 853-byte statement, 83 Keccak-f calls, 51,449 AND constraints, 52,374
private words, and 114 verifier-owned public words. It uses neither SmallWood nor Poseidon, and it
does not narrow the relation to Pay1x2.

The 133.332424-bit value is an arithmetic screen, not an established security theorem. The active
challenge field is B128; the three sequential transcripts still lack a reviewed direct-product
QROM reduction, and complete adaptive zero knowledge is not established for every outer protocol
message. The manifest therefore keeps `security_claim_established` and `production_authorized`
false. This is a measured full-M4 proof-size baseline, not release authorization.

Build and verify locally:

```sh
cargo +1.97.1 build --release --offline \
  --manifest-path prototypes/standalone-shake256-binius/m4-strict-full-shake400-v1/Cargo.toml \
  --target-dir target
target/release/hegemon-m4-strict-full-baseline-shake400 verify \
  --artifact prototypes/standalone-shake256-binius/m4-strict-full-shake400-v1/artifacts/shake400-v1-final
```

The pinned Binius checkout is revision `3f96163049f680b2909f6545690bd929f1b48c44`. Apply the
coefficient-mask patch, grouped-relation patch, grouped-stack compile fix, and BufferPool U50 patch
in that order. The last patch has SHA-256
`8414f73f5cf8fc487905809d6dd25dd68a54a35227121d426f490d40173484fd`.

`artifacts/shake400-v1` and `artifacts/shake400-v1-bound` are earlier measured runs retained for
comparison. The first omitted allocator-patch binding; the second predates the fail-before-growth
allocator guard. Both are superseded by `shake400-v1-final`.
