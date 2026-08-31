# Standalone proof envelope prototype

This isolated crate fixes the byte boundary for Hegemon's proposed standalone
binary transaction proof. It is executable prototype code, not a consensus
activation and not evidence that the unfinished proof backend is sound or zero
knowledge.

The V1 wire grammar is exactly:

    offset  bytes  meaning
    0       4      ASCII `HGSP`
    4       2      envelope version, little-endian (`1`)
    6       1      backend (`1` = direct Binius64 IronSpartan)
    7       1      fixed relation profile (`1` = Pay1x2, `2` = Consolidate2x1)
    8       4      direct proof byte length, little-endian
    12      N      direct backend proof bytes

The fixed overhead is 12 bytes. The complete envelope cap is 1,048,576 bytes,
so the direct proof payload may contain at most 1,048,564 bytes. The parser
borrows the proof slice and checks the declared cap before backend work. Empty, unknown-version,
unknown-backend, unknown-profile, short, truncated, trailing, and oversized
forms reject.

The envelope does not serialize the public transaction statement. The verifier
reconstructs that statement from the canonical action and supplies the exact
bytes, envelope version, backend, and relation profile to the proof backend as
`ProofBinding`. This avoids the retired `NativeTxLeafArtifact` metadata and
prevents an envelope-carried statement from disagreeing with the transaction.

Run the focused suite without building the production workspace:

    CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR=/private/tmp/hegemon-proof-envelope-target \
      cargo test --manifest-path circuits/standalone-proof-envelope-prototype/Cargo.toml

The unit tests pin the exact wire bytes and overhead; accept the exact 1 MiB
payload cap; reject trailing, truncated, malformed, and oversized encodings;
and demonstrate statement, proof, and cross-profile mutation rejection through
the backend binding interface. The test-only digest verifier is not a proof
system and makes no cryptographic security claim.
