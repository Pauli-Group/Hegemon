# Cryptoagility + ML-KEM-1024 Note Encryption

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

This plan upgrades shielded note encryption from ML-KEM-768 (≈96-bit post-quantum security accounting) to ML-KEM-1024 (targeting ≈128-bit post-quantum security accounting) and, at the same time, makes note encryption *crypto-agile*: a future algorithm swap should be achievable via a normal runtime/wallet upgrade rather than “rewrite the ciphertext format and hope.”

After this work, a user can:

1. Generate a shielded address that explicitly declares which cryptographic suite it uses.
2. Encrypt notes to that address using ML-KEM-1024, producing larger KEM ciphertexts and longer addresses as expected.
3. Decrypt notes reliably even when multiple cryptographic suites coexist (because each note ciphertext is self-identifying and domain-separated).

The “it works” proof is:

- Wallet unit/integration tests demonstrate ML-KEM-1024 encryption/decryption roundtrips.
- The node can mint shielded coinbase notes to a v2 address and the wallet can decrypt them.
- A dev chain started from fresh genesis accepts shielded transfers whose encrypted notes use the new format and KEM, and wallet sync can recover them.

This plan assumes a chain reset (new genesis) is acceptable for this upgrade. That removes the need to migrate old on-chain ciphertexts, but we still implement the *future* migration mechanisms so the next upgrade does not require another reset.

## Progress

- [x] (2026-01-13 23:02Z) Draft the cryptoagility + ML-KEM-1024 ExecPlan.
- [x] (2026-01-14 00:39Z) Confirm current note-encryption and address formats; write down exact byte layouts and size budgets.
- [x] (2026-01-14 00:39Z) Define “crypto suite” IDs and the v2 address / v2 ciphertext formats.
- [x] (2026-01-14 00:39Z) Implement ML-KEM-1024 as the default note-encryption KEM.
- [x] (2026-01-14 00:39Z) Make ciphertexts self-identifying and domain-separated by suite.
- [x] (2026-01-14 00:39Z) Update on-chain `EncryptedNote` encoding + wallet extrinsic encoding to support non-fixed KEM ciphertext lengths safely.
- [x] (2026-01-14 00:39Z) Add security hardening checks + tests (downgrade/confusion/DoS parsing).
- [ ] Update docs + website security table; validate end-to-end on fresh dev chain (completed: docs + website + test updates; remaining: dev-chain validation).

## Surprises & Discoveries

- Observation: The repo’s documentation says “Addresses encode algorithm identifiers” (see `METHODS.md` §5.2), but the current address format in code does not actually encode a `kem_id` / `crypto_suite` field; it implicitly hardcodes ML-KEM-768 by fixed key length.
  Evidence: `wallet/src/address.rs` encodes `(version, index, pk_recipient, pk_enc)` and `ML_KEM_PUBLIC_KEY_LEN` is a compile-time constant (1184).

- Observation: The wallet’s Substrate extrinsic encoding assumes the runtime `EncryptedNote` SCALE layout is exactly a fixed concatenation of `579 + 1088` bytes, and does not currently SCALE-encode fields.
  Evidence: `wallet/src/extrinsic.rs` checks `note.len() == PALLET_ENCRYPTED_NOTE_SIZE` and then `extend_from_slice(note)` without any per-field length prefix encoding.

Update this section as implementation uncovers additional constraints (for example, Substrate block length/PoV limits that require tighter ciphertext caps).

## Decision Log

- Decision: Treat `protocol_versioning::CryptoSuiteId` as the single “suite identifier” used consistently across (a) transaction proof version bindings and (b) note-encryption/address metadata.
  Rationale: A single ID avoids split-brain upgrades where proofs say “suite X” but note ciphertexts are interpreted as “suite Y”. Even though note encryption is not consensus-verified today, consistency reduces footguns and supports future policy enforcement.
  Date/Author: 2026-01-13 / Codex

- Decision: Add `crypto_suite: u16` to both the Bech32 address payload and the on-chain note ciphertext header, and bind it into both the AEAD AAD and the key-derivation input.
  Rationale: This prevents suite-confusion and downgrade/substitution attacks: if an attacker flips the suite ID, decryption must fail cryptographically (not merely “the wallet chose the wrong algorithm”).
  Date/Author: 2026-01-13 / Codex

- Decision: Keep the “circuit recipient bytes” (the 37-byte `DIVERSIFIED_ADDRESS_SIZE` layout used for commitments) unchanged for now, and treat `crypto_suite` as an *encryption-layer* identifier.
  Rationale: The join–split/commitment circuit depends on `pk_recipient`, not on the KEM; changing circuit-visible encodings expands the blast radius (fixtures, proof system, and commitment format) without improving confidentiality. Encryption agility can be achieved without touching the commitment circuit.
  Date/Author: 2026-01-13 / Codex

- Decision: Make the runtime `EncryptedNote` representation support variable KEM ciphertext lengths (bounded and validated), and update wallet extrinsic encoding to match SCALE exactly.
  Rationale: If the runtime storage/extrinsic format is pinned to one fixed KEM size, algorithm swaps become “hard forks by data structure.” Variable-length (but bounded) KEM bytes preserve DoS limits while enabling future suites.
  Date/Author: 2026-01-13 / Codex

## Outcomes & Retrospective

Delivered: ML-KEM-1024 note encryption, crypto-suite-bound address/ciphertext headers, variable-length KEM ciphertext support in the pallet + wallet SCALE encoding, and downgrade/confusion checks across wallet/node/runtime paths. Docs and the website security table are updated; crypto test vectors regenerated.

Open: end-to-end validation on a fresh dev chain and any performance/weight re-checks tied to larger ciphertexts.

## Context and Orientation

Key terms (defined for this repository):

A “shielded note” is an amount/value commitment plus encrypted recipient data. On-chain we store only commitments, nullifiers, and an encrypted payload so the recipient can recover note details. The ZK proof validates the commitment and spend rules; the encryption layer is for wallet privacy and is not currently verified by the runtime.

“Note encryption” in this repository is implemented as:

1. A KEM (Key Encapsulation Mechanism) to establish a shared secret with the recipient’s encryption public key.
2. A symmetric AEAD (Authenticated Encryption with Associated Data) to encrypt the note payload and memo under keys derived from that shared secret.

“ML-KEM” is the NIST-standard lattice-based KEM (FIPS 203). This repo currently uses ML-KEM-768 (category 3). We will move to ML-KEM-1024 (category 5). For implementation purposes:

- ML-KEM-768 sizes: `pk = 1184`, `sk = 2400`, `ct = 1088`, `shared = 32`.
- ML-KEM-1024 sizes: `pk = 1568`, `sk = 3168`, `ct = 1568`, `shared = 32`.

In code, the relevant modules are:

- `crypto/src/ml_kem.rs`: wrapper over the `ml-kem` crate (currently hardcoded to ML-KEM-768).
- `crypto/src/note_encryption.rs`: ML-KEM + ChaCha20-Poly1305 note encryption and serialization helpers.
- `wallet/src/address.rs`: Bech32m encoding/decoding for shielded addresses; currently assumes fixed ML-KEM-768 key length.
- `wallet/src/notes.rs`: wallet-facing note encryption wrapper and the “pallet format” bytes (`579 + kem_ct`).
- `wallet/src/extrinsic.rs`: manual Substrate extrinsic encoding; currently assumes fixed-size `EncryptedNote`.
- `pallets/shielded-pool/src/types.rs`: on-chain `EncryptedNote` type; currently fixed `[u8; 579]` + `[u8; 1088]`.
- `node/src/shielded_coinbase.rs`: coinbase note encryption bridge; currently assumes fixed sizes and layout.
- `runtime/src/lib.rs`: runtime API `get_encrypted_notes` that concatenates ciphertext + kem bytes for wallet sync.

Versioning already exists for proofs and consensus:

- `protocol/versioning/src/lib.rs` defines `VersionBinding { circuit, crypto }` and `CryptoSuiteId`.
- `consensus/src/version_policy.rs` defines `VersionSchedule` for activation/retirement of bindings.

Our goal is to extend that concept so “crypto suite” also identifies the encryption KEM used by addresses and notes.

## Attack Analysis and Security Requirements

The main new risks introduced by “crypto-agile, self-identifying ciphertexts” are *confusion* and *parsing/DoS* risks. This section defines the attacker model and the required hardening so the upgrade does not create new failure modes.

Attacker model (specific to this plan):

- The attacker can submit arbitrary shielded transfers, meaning they can put arbitrary ciphertext bytes on-chain (within any size limits).
- The attacker can feed arbitrary addresses and ciphertext blobs to wallet software (for example via copy/paste, QR codes, or malicious RPC endpoints).
- The attacker can observe all on-chain ciphertexts forever (“harvest now, decrypt later”).

Security requirements for the upgraded design:

1. Suite confusion resistance: It must be impossible for an attacker to take a ciphertext intended for suite A and make it decrypt under suite B by changing only public metadata. If public metadata changes (suite id, diversifier index, address version), decryption must fail due to AEAD authentication.

2. Downgrade resistance: If multiple suites are supported concurrently, a sender must not be able to “silently downgrade” a recipient to a weaker suite while presenting the ciphertext as belonging to the stronger suite. The metadata must be authenticated and wallet UX should treat suite mismatches as hard failures.

3. Parsing safety: All code paths that parse untrusted ciphertext/address bytes must be length-bounded, must not allocate unbounded memory, and must fail closed on unknown suite IDs or malformed lengths.

4. On-chain DoS bounds: Variable-length KEM ciphertext support must preserve strict maximum sizes so attackers cannot stuff blocks with oversized ciphertexts that are “cheap” in weight/fees. If the pallet type becomes variable-length, weights/fees must be audited so size increases are paid for.

5. Deterministic interpretation: There must be exactly one valid interpretation of bytes as (version, suite, index, payloads). No “guess the suite from length” fallback is allowed, because it enables ambiguous parsing and downgrade tricks.

Concretely, this plan enforces the above by:

- Encoding `crypto_suite` explicitly in both addresses and note ciphertext headers.
- Including `(address_version, crypto_suite, diversifier_index)` in AEAD associated data (AAD) and in the AEAD key derivation.
- Validating that the KEM ciphertext length matches the declared suite’s expected ciphertext size.
- Avoiding implicit defaults for unknown suite IDs; unknown IDs are rejected.
- Keeping hard caps in the runtime and in wallet parsing code, and adding regression tests that demonstrate failure on malformed inputs.

## Plan of Work

### Milestone 1: Baseline the current formats and size budgets

Before editing code, write down the exact byte layouts currently in use so we can deliberately version them instead of accidentally changing them.

Record these “v1” layouts in this ExecPlan’s `Artifacts and Notes` section:

- Bech32 address payload layout (`wallet/src/address.rs`).
- On-chain encrypted note layout (`pallets/shielded-pool/src/types.rs`) and the wallet’s “pallet format” (`wallet/src/notes.rs::to_pallet_bytes`).
- The AEAD AAD and key-derivation inputs (`crypto/src/note_encryption.rs`).
- All hard-coded size constants that will change (1184/1088/2400 etc.).

Acceptance for this milestone is “the plan contains a correct, unambiguous description of current v1 layouts,” so later milestones can point back here without re-reading code.

### Milestone 2: Define crypto suite IDs and the v2 address / v2 ciphertext formats

Define “crypto suite” as a concrete, code-level identifier (`CryptoSuiteId`, a `u16`) that names a bundle of crypto parameters. For this upgrade we only need one suite, but we must design for multiple.

Add a new crypto suite constant in `protocol/versioning/src/lib.rs`:

- `CRYPTO_SUITE_GAMMA: CryptoSuiteId = 3` (name is arbitrary; pick one and keep it stable).
- Update `DEFAULT_VERSION_BINDING` to use the new suite ID if we want “fresh genesis uses ML-KEM-1024 everywhere by default.”

Define new “v2 address” and “v2 ciphertext” layouts:

V2 address (Bech32 payload, `wallet/src/address.rs`):

    address_version: u8 = 2
    crypto_suite: u16 (little-endian)
    diversifier_index: u32 (little-endian)
    pk_recipient: [u8; 32]
    pk_enc: [u8; suite-specific length]

V2 note ciphertext header (inside the 579-byte ciphertext container, `wallet/src/notes.rs` and `node/src/shielded_coinbase.rs`):

    address_version: u8
    crypto_suite: u16 (little-endian)
    diversifier_index: u32 (little-endian)
    note_len: u32
    note_payload: [note_len bytes]
    memo_len: u32
    memo_payload: [memo_len bytes]
    padding: zeros to fill 579 bytes

Critical rule: parsing must *never* infer suite from lengths; it must always read `crypto_suite` first and validate lengths against that declared suite.

### Milestone 3: Implement ML-KEM-1024 as the default KEM (crypto crate)

Update `crypto/src/ml_kem.rs` to wrap ML-KEM-1024 instead of ML-KEM-768 (or introduce a small “active params” indirection so future suites can add another KEM without rewriting all call sites).

Concretely, update:

- The parameter type import from `MlKem768Params` to `MlKem1024Params`.
- The size constants to the ML-KEM-1024 values.
- Any tests that assert the old lengths.

Add a focused unit test that asserts the encoded sizes match the expected constants (pk/sk/ct/shared) so a future dependency bump cannot silently change them.

### Milestone 4: Make note encryption suite-bound (AAD + KDF) and self-identifying

Update `crypto/src/note_encryption.rs` so the cryptographic binding includes `crypto_suite`.

Required changes:

- Extend `NoteCiphertext` to carry `crypto_suite: u16`.
- Update `build_aad(...)` to include `crypto_suite` and update all callers so AAD becomes `(address_version, crypto_suite, diversifier_index)`.
- Update `derive_aead_material(...)` so the key derivation input is domain-separated by `crypto_suite` as well. A simple, explicit rule is:

    expand_to_length("wallet-aead", shared_secret || label || crypto_suite_le, 44)

  where `label` remains `b"note-aead"` or `b"memo-aead"`.

- Update the “pallet format” builders/parsers to place the new header fields into the 579-byte container.

Add tests that prove:

- Flipping `crypto_suite` in the ciphertext header causes decryption to fail (authentication failure).
- Flipping `diversifier_index` causes decryption to fail.

### Milestone 5: Update wallet address encoding and key derivation to ML-KEM-1024

Update `wallet/src/keys.rs` and `wallet/src/address.rs` so:

- New addresses default to ML-KEM-1024 (`crypto_suite = CRYPTO_SUITE_GAMMA`).
- Address encoding/decoding supports v2 format (and, optionally, still accepts v1 for backwards-compatibility during transition tooling; with a chain reset this is optional but may help test fixtures).
- `AddressKeyMaterial` exposes `crypto_suite()` and the wallet uses it when encrypting/decrypting notes.

Important: wallet note recovery currently selects key material by `(version, diversifier_index)`. With v2, selection must be by `(address_version, crypto_suite, diversifier_index)` so future upgrades can reuse diversifier indices without making old notes undecryptable.

### Milestone 6: Make on-chain `EncryptedNote` support variable KEM ciphertext length safely

This is the biggest “cryptoagility” plumbing change because it touches runtime types and wallet extrinsic encoding.

Update `pallets/shielded-pool/src/types.rs`:

- Keep `ciphertext: [u8; 579]` fixed (it is a tight cap and used by wallet scanning logic).
- Change `kem_ciphertext` from a fixed `[u8; 1088]` to a bounded variable-length byte vector, for example:

    kem_ciphertext: BoundedVec<u8, MaxKemCiphertextLen>

  where `MaxKemCiphertextLen` is a runtime constant set to at least 1568 and preferably exactly the maximum supported by the active schedule.

Add runtime-side validation in `pallets/shielded-pool/src/lib.rs::shielded_transfer`:

- Parse the v2 ciphertext header to read `crypto_suite`.
- Verify `kem_ciphertext.len()` equals the expected length for that suite (for ML-KEM-1024, 1568).
- Reject unknown suites, even if sizes happen to match.

Update `wallet/src/extrinsic.rs` to SCALE-encode `EncryptedNote` correctly:

- Encode `ciphertext` as raw 579 bytes (fixed array).
- Encode `kem_ciphertext` as SCALE `BoundedVec<u8, _>`: compact length prefix then bytes.

Do not keep the “fixed 1667 bytes” assumption anywhere after this milestone.

Update `wallet/src/notes.rs`:

- Remove `PALLET_KEM_CIPHERTEXT_SIZE` / `PALLET_ENCRYPTED_NOTE_SIZE` as fixed constants.
- Make `to_pallet_bytes()` produce `579 + kem_len` bytes and validate `kem_len` based on `crypto_suite`.
- Make `from_pallet_bytes()` accept variable-length and validate the KEM ciphertext length by reading the declared `crypto_suite` from the 579-byte header.

Update `node/src/shielded_coinbase.rs` to build the new `EncryptedNote` type and header layout. Ensure coinbase notes use the same suite id and the same AAD/KDF rules as regular wallet notes.

### Milestone 7: Tests, docs, website, and end-to-end validation on fresh genesis

Add or update tests in these places:

- `crypto/src/note_encryption.rs` tests for tamper failures and ML-KEM-1024 roundtrips.
- `wallet/src/address.rs` tests for v2 address encode/decode roundtrip and length validation.
- `wallet/src/extrinsic.rs` tests for correct SCALE encoding of `EncryptedNote` (a regression that would otherwise silently break submissions).
- `node/src/shielded_coinbase.rs` tests to ensure coinbase encrypted notes have the correct KEM ciphertext length and decrypt in wallet code.

Update documentation (must remain consistent with design intent):

- `DESIGN.md`: update stated KEM parameter set and payload sizes for addresses/notes.
- `METHODS.md`: update note encryption description to include `crypto_suite` in ciphertext header, AAD, and KDF input, and update KEM sizes and security accounting.
- `SECURITY.md` and `docs/THREAT_MODEL.md`: update the “KEM” section to reflect ML-KEM-1024 for note encryption (and clarify what remains at 128-bit PQ vs higher).
- `website/index.html`: update the Security Parameters table row “Note encryption” to `~128 bits` and `ML-KEM-1024 (NIST Level 5)`.

End-to-end validation on a fresh dev chain:

- Start a fresh dev node (`--tmp`) with mining enabled.
- Create a wallet, generate a v2 address, mine a coinbase note to it, and verify wallet sync can decrypt it.
- Send a shielded transfer to another v2 address and verify the recipient wallet decrypts it.

## Concrete Steps

All commands below assume the working directory is the repository root.

Fresh clone prerequisites:

    make setup
    make node

Focused tests while iterating:

    cargo test -p synthetic-crypto
    cargo test -p wallet
    cargo test -p pallet-shielded-pool
    cargo test -p node

Dev chain sanity check (fresh state, mining enabled):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Wallet CLI sanity checks (exact commands may change; keep this section updated as the implementation lands):

    ./target/release/wallet generate
    ./target/release/wallet address

Expected observations to add as implementation progresses:

- A v2 address encodes/decodes successfully and includes `crypto_suite = 3`.
- An encrypted note’s KEM ciphertext length is 1568 bytes.
- Decryption fails if `crypto_suite` or `diversifier_index` in the ciphertext header is modified.

## Validation and Acceptance

Acceptance is behavior-based:

1. ML-KEM-1024 is the note-encryption KEM: unit tests assert `pk=1568`, `ct=1568`, and a note-encryption roundtrip succeeds using those sizes.

2. Ciphertexts are crypto-suite bound: modifying the suite id in the ciphertext header causes decryption to fail due to AEAD authentication (not due to a panic, mis-parse, or silent corruption).

3. Wallet submissions still work: the wallet can submit a shielded transfer whose encrypted notes are accepted by the runtime, meaning `wallet/src/extrinsic.rs` encodes `EncryptedNote` in the exact SCALE form the pallet expects.

4. On a fresh dev chain, coinbase notes and shielded transfers can be recovered by the wallet using v2 addresses and v2 ciphertexts.

5. Docs and website are consistent: `METHODS.md` and `DESIGN.md` reflect the new header fields and ML-KEM-1024 sizes, and `website/index.html` reflects the updated PQ security accounting.

## Idempotence and Recovery

Most steps are safe to rerun. Tests and builds should be repeatable.

Because this plan changes runtime storage/extrinsic layouts, a clean recovery path is part of the design:

- During development, use `--tmp` chains so restarting from genesis is trivial.
- For any persistent dev chain state, delete the node’s database directory to force a resync from the new genesis.
- If wallet local state becomes incompatible, delete the wallet store file and re-run wallet initialization. If preserving keys is required, add a wallet export/import path for the root secret and viewing keys before bumping file versions.

## Artifacts and Notes

Record the finalized byte layouts here as they are implemented, replacing placeholders.

V1 address payload (current, for reference):

    version: u8
    diversifier_index: u32
    pk_recipient: [u8; 32]
    pk_enc: [u8; 1184]   (ML-KEM-768)

V2 address payload (new):

    address_version: u8 = 2
    crypto_suite: u16
    diversifier_index: u32
    pk_recipient: [u8; 32]
    pk_enc: [u8; suite-specific length]   (ML-KEM-1024 => 1568)

V1 on-chain ciphertext container (current, for reference):

    version: u8
    diversifier_index: u32
    note_len: u32
    note_payload: [note_len bytes]
    memo_len: u32
    memo_payload: [memo_len bytes]
    padding to 579 bytes

V2 on-chain ciphertext container (new):

    address_version: u8
    crypto_suite: u16
    diversifier_index: u32
    note_len: u32
    note_payload: [note_len bytes]
    memo_len: u32
    memo_payload: [memo_len bytes]
    padding to 579 bytes

V2 AEAD associated data (AAD) and KDF input (new):

    aad = address_version || crypto_suite_le || diversifier_index_le
    kdf_input = shared_secret || label || crypto_suite_le

## Interfaces and Dependencies

This plan depends on the existing `ml-kem` crate already in `crypto/Cargo.toml`, which supports `MlKem1024Params`.

At the end of implementation, these interfaces must exist:

In `protocol/versioning/src/lib.rs`, define:

    pub const CRYPTO_SUITE_GAMMA: CryptoSuiteId = 3;

In `crypto/src/note_encryption.rs`, ensure:

    pub struct NoteCiphertext {
        pub version: u8,
        pub crypto_suite: u16,
        pub diversifier_index: u32,
        pub kem_ciphertext: Vec<u8>,
        pub note_payload: Vec<u8>,
        pub memo_payload: Vec<u8>,
    }

and `encrypt(...)` / `decrypt(...)` bind `crypto_suite` into AAD and KDF as described above.

In `wallet/src/address.rs`, ensure `ShieldedAddress` carries `crypto_suite: u16` and v2 encoding/decoding is implemented.

In `pallets/shielded-pool/src/types.rs`, ensure `EncryptedNote` can represent variable-length KEM ciphertext bytes with a strict maximum, and the pallet validates the declared suite and ciphertext length.

When revising this plan, append a short note at the bottom describing what changed and why.
