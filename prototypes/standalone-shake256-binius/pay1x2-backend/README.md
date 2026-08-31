# Full standalone Pay1x2 Binius prototype

This isolated crate proves Hegemon's fixed native-asset Pay1x2 cryptographic
core with direct IronSpartan at pinned Binius64 revision
`3f96163049f680b2909f6545690bd929f1b48c44`. It is the actual relation, not
the repeated-Merkle-parent geometry proxy:

- one 48-byte spend key derives `auth56 || nullifier_key56` in one SHAKE call;
- one input note and two output notes use the exact `HEG-S4V2` frames;
- the input follows one hidden depth-32 Merkle path;
- input and mandatory change authorization equal the derived owner key, while
  change uses a fresh recipient diversifier;
- all values and the public fee are 61-bit, every asset id is fixed to native,
  and a binary ripple-carry adder proves exact integer conservation;
- the public anchor, nonzero nullifier, two nonzero output commitments, and fee
  are bound directly; and
- the exact network-bound 478-byte HGS2 adapter—including fixed
  IDs/shape/native asset, two ciphertext hashes, a SHAKE256-448 binding of
  chain/genesis/rules identity, and the public-derived balance tag—is the sole
  public statement observed by Fiat-Shamir. Core fields are slices, not
  duplicates; and
- the verifier exact-decodes the 12-byte-header `HGSP` envelope, enforces its
  V1/Binius64-IronSpartan/Pay1x2 route, reconstructs HGS2 from the authoritative
  prospective Kernel V5/Delta family-1/action-7 projection and network, and only
  then builds the Binius public vector and exact-consumes the proof transcript.

The frozen statement identifiers are statement/circuit/crypto/backend/profile
`2/5/4/1/1`. The action projection additionally fixes two ciphertexts with
exact declared sizes, one nullifier, two commitments, native balance slots
`[0, u64::MAX, u64::MAX, u64::MAX]`, zero `value_balance`, no stablecoin, no
candidate artifact, the expected network binding, and the exact 64-byte HGS2
binding digest.

The scalar witness is 2,448 bytes, the canonical public statement is 478 bytes,
and the exact workload is 5,153 absorbed bytes across 40 Keccak-f[1600]
permutations. The compiled relation has 1,883,192 constraint rows, padded to
2,097,152. It includes 1,536,000 Keccak chi multiplications and 39,794
source-level non-hash multiplications for bitness, path swaps, nonzero gates,
and the two ripple-carry additions.

## Frozen measurement

On the local Apple Silicon host, the deterministic-test inverse-rate size sweep
was:

| log inverse rate | proof bytes | prove ms | verify ms |
| ---: | ---: | ---: | ---: |
| 1 | 574,000 | 803 | 161 |
| 2 | 413,008 | 1,195 | 150 |
| 3 | **380,496** | 2,040 | 172 |
| 4 | 382,992 | 4,505 | 255 |

Rate three was regenerated after correcting the HGS2 fixed prefix and adding
host-side composition. Rates one, two, and four retain the prior timing rows
because public-vector and constraint geometry did not change; their sizes
remain the relevant sweep result.

The selected rate-3 proof is 380,508 bytes with the 12-byte direct envelope,
below the 512 KiB optimization target. The final disk-safe harness reported
2,040 ms for the honest proof, 172 ms for composed verification,
5,524,226,048 bytes peak RSS, and capacity of 174 actions in a 64 MiB block
under the current 4,967-byte non-proof action budget. Exact results are frozen
under `measurements/`.

The executable checks the valid proof, all public-field mutations, a changed
proof byte, trailing bytes, recomputed-hash balance/native-asset/authorization
attacks, a carry-generating payment at `(2^61)-1`, terminal overflow, range
overflow, and acceptance of a fresh change recipient.
It separately mutates the adapter profile byte, each ciphertext hash, the
balance tag, the network binding, and each of chain id/genesis/rules at the
adapter source; every old-proof/new-statement combination rejects.

The stronger negative control generates three fresh proofs: one each over a
forged ciphertext hash, network binding, and balance tag. The private raw
verifier accepts every forged statement/proof pair, proving those bytes are not
relation-derived. The composed verifier rejects all three against the original
authoritative action/network. Seven malformed-envelope classes reject before
statement reconstruction, and fifteen malformed-action classes—including
kernel/route/count/size/native-slot/value-balance/stablecoin/candidate/binding
errors—reject with the proof-call counter still zero.

## Run safely

Keep build artifacts out of the already-full repository volume:

    df -h /private/tmp
      CARGO_TARGET_DIR=/private/tmp/hegemon-pay1x2-composed-target \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 \
      cargo +1.97.1 run --release --locked --offline -- \
      --rate 1 --rate 2 --rate 3 --rate 4 --deterministic-test

Then run the fail-closed repository harness in explicitly unsupported prototype
mode:

    python3 scripts/measure_standalone_shake256_prototype.py \
      --allow-unsupported-prototype -- \
      /private/tmp/hegemon-pay1x2-composed-target/release/hegemon-standalone-shake256-pay1x2-binius-backend \
      --rate 3 --deterministic-test

Remove that exact disposable target after measuring.

## Claim boundary

This is a real proof backend prototype, but it is not release-qualified and is
not connected to consensus. Upstream still fixes 96-bit query security,
SHA-256 proof commitments/transcript, and GF(2^128), while Hegemon targets a
composed PQ128 profile with SHAKE256-512 and GF(2^384). End-to-end zero
knowledge is not yet established. The proof binds all 478 canonical HGS2 bytes
in Fiat-Shamir and constrains the fixed IDs/shape/native asset plus every
core-field equality. The composed prototype now performs exact envelope and
prospective action/network reconstruction, but that action route is not
registered in production. Exact wallet ciphertext parsing/canonical
re-encoding, active node type integration, and consensus integration remain
external.
