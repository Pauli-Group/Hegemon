# Remove Hint Tags From Shielded Notes (Protocol Reset)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

After this work, Hegemon no longer has any “hint tag” / “address tag” field anywhere in the protocol, node, wallet, or app: addresses do not carry tags, encrypted notes do not carry tags, and wallets do not rely on tags while scanning. This removes a stable public fingerprint that lets observers enumerate notes sent to a published address by simple byte-matching.

Observable outcome: build a fresh node + wallet, start a brand-new chain from genesis, mine a few blocks, and sync a wallet. The wallet still finds and decrypts its notes, but a chain observer cannot filter ciphertexts by a per-address tag because no such tag exists on-chain or in the address format. A repo-wide search for `hint_tag`, `address_tag`, `addr_tag`, or “hint tag” returns nothing.

Non-goals (explicit): this does not make “Bitcoin-length” addresses. The dominant contributor to `shca1...` length is the ML‑KEM public key (1184 bytes). Removing a 32-byte tag saves ~50 Bech32 characters, not orders of magnitude. If we want short identifiers like `hgm1...`, that is a separate design (directory / resolver / name system) with its own privacy trade-offs.


## Progress

- [x] (2026-01-11 01:30Z) Surveyed current hint-tag plumbing and documented all impacted modules.
- [x] (2026-01-11 02:10Z) Milestone 1: Remove hint tags from `crypto` note encryption (types, AAD, serialization).
- [x] (2026-01-11 02:20Z) Milestone 2: Remove hint tags from `wallet` (key derivation, address format, note formats) and make wallet sync robust without tag prefiltering.
- [ ] Milestone 3: Remove hint tags from `node` coinbase encryption and from on-chain types/constants; bump runtime version and regenerate chainspec; restart chain from genesis. (completed: code changes + spec_version bump; remaining: regenerate chainspec + fresh chain reset)
- [ ] Milestone 4: Update app surfaces (`walletd`, `hegemon-app`) and all tests to match the new formats; ensure no tag references remain.
- [ ] Milestone 5: End-to-end validation on a fresh chain (mine → sync → send → receive) plus repo-wide grep confirming tags never existed.


## Surprises & Discoveries

- Observation: Coinbase rewards are linkable regardless of hint tags because `pallet_shielded_pool::types::CoinbaseNoteData` stores `recipient_address` in plaintext “for audit”.
  Evidence: `pallets/shielded-pool/src/types.rs` struct `CoinbaseNoteData`.

- Observation: The wallet sync engine currently treats “AEAD decryption failed” as a fatal error. Without hint tags, that failure becomes the expected outcome for “not my note”, so sync will break until error semantics change.
  Evidence: `wallet/src/async_sync.rs` only treats `WalletError::NoteMismatch` as “not mine”; everything else aborts sync.

- Observation: Several comments and docs describe an older encrypted-note layout (“recipient/value/rcm/memo”), but the actual implementation is a fixed-size container holding variable-length `note_payload` + `memo_payload` plus metadata.
  Evidence: `pallets/shielded-pool/src/types.rs` comment for `ENCRYPTED_NOTE_SIZE` vs `wallet/src/notes.rs` packing format.


## Decision Log

- Decision: Remove hint tags entirely from the protocol surface (no “reserved 32 bytes set to 0”).
  Rationale: Keeping a fixed reserved field leaves room for accidental reintroduction and keeps the “public fingerprint slot” alive. The user goal is “as if hint tags never existed”.
  Date/Author: 2026-01-11 / Agent

- Decision: Change on-chain encrypted-note ciphertext size from 611 bytes to 579 bytes (611 - 32) so the maximum payload budget remains unchanged.
  Rationale: The current payload budget is 566 bytes because 611 includes a trailing 32-byte hint tag. Shrinking the container by 32 bytes preserves `max_payload = 566` while removing the tag bytes completely.
  Date/Author: 2026-01-11 / Agent

- Decision: Remove the 6 “tag” bytes from the on-chain “diversified address” used for coinbase audit and shrink `DIVERSIFIED_ADDRESS_SIZE` from 43 to 37.
  Rationale: Those 6 bytes are derived from the address tag and exist only as a tag-shaped artifact. `pk_recipient` extraction ignores them, so removing them is safe and aligns with “no tags anywhere”.
  Date/Author: 2026-01-11 / Agent

- Decision: Treat decapsulation/AEAD failures during wallet scanning as “not my note” rather than fatal.
  Rationale: Without a tag prefilter, the wallet must trial-decrypt everything it might plausibly own; most attempts will fail by design.
  Date/Author: 2026-01-11 / Agent

- Decision: This is a hard protocol break; we restart the chain from genesis and do not provide compatibility with old ciphertexts/addresses.
  Rationale: The user explicitly wants a chain reset and “like hint tags never existed”, which conflicts with maintaining backward compatibility.
  Date/Author: 2026-01-11 / Agent


## Outcomes & Retrospective

- (To be filled during implementation.) At completion, compare: (1) privacy posture for published addresses, (2) wallet sync performance regression, and (3) any remaining linkability surfaces (coinbase audit, diversifier index visibility).


## Context and Orientation

This repository implements a Substrate-based chain (`hegemon-node`) plus a Rust wallet (`wallet` + `walletd`) and a desktop GUI (`hegemon-app/`). “Shielded notes” are encrypted off-chain by senders (wallets) and stored on-chain as opaque bytes; only recipients can decrypt.

Key terms used in this plan:

* Hint tag / address tag: a deterministic 32-byte value derived per address index, currently included in two places:
  * In the address string `shca1...` as `wallet::address::ShieldedAddress.address_tag`.
  * In the on-chain encrypted note as `hint_tag` (stored in clear inside the fixed-size ciphertext container).
  The wallet uses this tag as a fast prefilter: if the tag does not match, it skips KEM decapsulation and AEAD decryption.

* Diversifier index: a 32-bit integer carried in both addresses and ciphertext metadata, used by the recipient to deterministically derive the right per-index encryption key material.

* Pallet encrypted-note format (“pallet bytes”): the wallet and node currently represent an on-chain encrypted note as raw concatenated bytes:
  * `ciphertext` (currently 611 bytes): version + diversifier_index + note_len + note_payload + memo_len + memo_payload + padding + hint_tag(32).
  * `kem_ciphertext` (1088 bytes): ML‑KEM‑768 ciphertext.
  Total today: 1699 bytes.

After this plan lands, the on-chain format becomes:

* `ciphertext` (579 bytes): version + diversifier_index + note_len + note_payload + memo_len + memo_payload + padding. No hint tag.
* `kem_ciphertext` (1088 bytes): unchanged.
Total: 1667 bytes.

The on-chain “diversified address” used in coinbase audit data is currently 43 bytes:

* version(1) + diversifier_index(4) + pk_recipient(32) + tag(6)

After this plan lands it becomes 37 bytes:

* version(1) + diversifier_index(4) + pk_recipient(32)

Key files that currently implement hint tags:

* `crypto/src/note_encryption.rs` (protocol-level encryption; defines `NoteCiphertext.hint_tag` and includes it in AEAD AAD).
* `wallet/src/keys.rs` (derives `ViewKey::address_tag()` and stores it in `AddressKeyMaterial.addr_tag`).
* `wallet/src/address.rs` (encodes/decodes `ShieldedAddress.address_tag` into Bech32m).
* `wallet/src/notes.rs` (packs/unpacks pallet bytes including a trailing 32-byte `hint_tag` and checks it before decrypt).
* `wallet/src/async_sync.rs` (treats decryption failures as fatal except `NoteMismatch`).
* `wallet/src/substrate_rpc.rs` + `wallet/src/extrinsic.rs` (hardcode sizes/format assumptions for note bytes).
* `node/src/shielded_coinbase.rs` (encrypts coinbase notes and includes a 6-byte tag slice in coinbase `recipient_address`).

Key docs that describe hint tags and must be updated to remove them:

* `DESIGN.md` (address encoding section).
* `METHODS.md` (addresses/encryption/scanning sections).
* `docs/assets/diagrams.md` (diagram currently labels address tags).


## Plan of Work

This change is a protocol break. Implement it in a top-down, format-first way: decide the new byte layouts and constants, then update crypto, wallet, node, runtime, and finally docs/tests. Do not attempt to keep old-format decoding paths; the end state must compile and run with a clean genesis and contain no tag-related code or documentation.

### Milestone 1: Remove hint tags from `crypto` note encryption

Edit `crypto/src/note_encryption.rs`:

1. Remove `hint_tag: [u8; 32]` from `pub struct NoteCiphertext`.
2. Update `NoteCiphertext::encrypt`:
   * Remove the `address_tag: [u8; 32]` parameter entirely.
   * Build AEAD additional authenticated data (AAD) from only `(version, diversifier_index)`.
   * Do not store any tag in the ciphertext struct.
3. Update `NoteCiphertext::decrypt`:
   * Remove the `expected_tag: [u8; 32]` parameter entirely.
   * Remove the “verify hint tag matches” check.
   * Build AAD from only `(self.version, self.diversifier_index)`.
4. Update serialization:
   * `to_bytes()` must no longer append 32 tag bytes.
   * `from_bytes()` must no longer read 32 tag bytes or require them in the minimum length.
5. Update unit tests in the same file:
   * Update `test_encrypt_decrypt_roundtrip` and `test_serialization_roundtrip` to use the new signatures and to stop asserting on `hint_tag`.

End state interfaces (must exist):

* `crypto::note_encryption::NoteCiphertext` has fields: `version`, `diversifier_index`, `kem_ciphertext`, `note_payload`, `memo_payload`.
* `NoteCiphertext::encrypt(pk_enc, pk_recipient, version, diversifier_index, note, kem_randomness)` (no tag argument).
* `NoteCiphertext::decrypt(&self, sk_enc, expected_pk_recipient, expected_diversifier_index)` (no tag argument).

### Milestone 2: Remove hint tags from `wallet` (keys, addresses, ciphertexts) and fix scanning semantics

Edit `wallet/src/keys.rs`:

1. Delete `ViewKey::address_tag()` and remove any use of the `b"addr-tag"` label.
2. Remove `addr_tag: [u8; 32]` from `AddressKeyMaterial` and from `derive_with_components`.
3. Update `AddressKeyMaterial::shielded_address()` to build a `ShieldedAddress` without any tag field.
4. Update tests in `wallet/src/keys.rs` to assert on stable fields that still exist (index, pk_recipient, pk_enc), and delete tag assertions.

Edit `wallet/src/address.rs`:

1. Remove the `address_tag` field from `ShieldedAddress`.
2. Update Bech32 payload encoding/decoding sizes:
   * New raw payload size is `1 + 4 + 32 + ML_KEM_PUBLIC_KEY_LEN`.
3. Update `Default` and the encode/decode roundtrip test to match the new struct.
4. Improve the decode error message to explicitly mention that old hint-tag addresses are unsupported, if the length mismatches.

Edit `wallet/src/notes.rs`:

1. Remove `hint_tag` from `wallet::notes::NoteCiphertext`.
2. Update constants to match the new on-chain sizes:
   * `PALLET_CIPHERTEXT_SIZE: usize = 579`
   * `PALLET_KEM_CIPHERTEXT_SIZE: usize = 1088` (unchanged)
3. Update `to_pallet_bytes()` and `from_pallet_bytes()` to remove:
   * The trailing 32-byte tag slot.
   * Any `- 32` bounds checks.
4. Update `encrypt()` to call the new `crypto::note_encryption::NoteCiphertext::encrypt` signature (no tag).
5. Update `decrypt()` to:
   * Remove the “address tag mismatch” precheck.
   * Call the new `crypto::note_encryption::NoteCiphertext::decrypt` signature.
6. Update tests in this file to stop referencing tags and to validate the new size invariants.

Edit `wallet/src/substrate_rpc.rs`:

1. Update `parse_pallet_encrypted_note()`:
   * `CIPHERTEXT_SIZE` must become 579.
   * Remove extraction of `hint_tag` from the tail.
2. Ensure the resulting `wallet::notes::NoteCiphertext` matches the updated struct.

Edit `wallet/src/extrinsic.rs`:

1. Replace all hard-coded `611 + 1088` size checks with the new total size `579 + 1088`.
2. Prefer defining a single constant (in one module) used by all call encoders so it cannot drift.

Edit `wallet/src/async_sync.rs`:

1. Remove debug output that prints `hint_tag` and expected address tags.
2. Change the “decrypt note” match so that trial-decryption failures do not abort sync:
   * Treat `WalletError::DecryptionFailure` as “not my note” (same handling as `NoteMismatch`).
   * Keep structural/serialization/state errors as fatal.

Edit `wallet/src/viewing.rs`:

1. Remove `OutgoingViewingKey::address_tag()` and any tests that assert tag equality.
2. Ensure disclosure/audit functionality that depends on `pk_recipient` still works.

Remove `wallet/tests/debug_addr_tag.rs` (it exists only to debug tag derivation).

### Milestone 3: Remove hint tags from node coinbase encryption and on-chain types; restart chain

Edit `pallets/shielded-pool/src/types.rs`:

1. Change constants:
   * `pub const ENCRYPTED_NOTE_SIZE: usize = 579;`
   * `pub const DIVERSIFIED_ADDRESS_SIZE: usize = 37;`
2. Update any tests that index into `ciphertext[610]` to index the last byte via `ENCRYPTED_NOTE_SIZE - 1`.
3. Update comments that describe the encrypted-note layout so they reflect the actual byte packing used by wallet/node.

Edit `pallets/shielded-pool/src/commitment.rs`:

1. Update the “Layout” comment for `pk_recipient_from_address` to the 37-byte layout.
2. Keep the extraction slice `recipient[5..37]` (it still yields the 32-byte pk).

Edit `node/src/shielded_coinbase.rs`:

1. Update the call to `crypto::note_encryption::NoteCiphertext::encrypt` (no address tag argument).
2. Update `convert_to_pallet_format()`:
   * Remove writing a trailing 32-byte `hint_tag`.
   * Update `max_payload` computation to remove the `- 32` term.
3. Update `extract_recipient_address()`:
   * Remove the 6 tag bytes and fill only version + index + pk_recipient.
4. Update unit tests in this file to construct the new `wallet::address::ShieldedAddress` without tags.

Edit `runtime/src/lib.rs`:

1. Bump `VERSION.spec_version` by 1 to reflect the hard protocol break.
2. Rebuild the node and regenerate `config/dev-chainspec.json` from the rebuilt binary (see Concrete Steps).

### Milestone 4: App surface verification

The GUI and `walletd` do not currently mention hint tags directly, but they depend on the wallet crate’s JSON types and CLI behavior.

1. Ensure `walletd` still compiles and runs after the `ShieldedAddress` struct changes (JSON fields removed).
2. Run `npm run dev` in `hegemon-app/` and verify:
   * Address placeholders still accept `shca1...`.
   * Copy/paste of a new-format address works for send flows.
   * Contact book entries still render (they store the address string; they should not parse tags).

If the app has any hidden assumptions about address length, fix them (prefer truncation UI, not validation by length).

### Milestone 5: Docs cleanup (“as if hint tags never existed”)

Update these docs to remove tag references and to describe the new reality (full trial decryption during scan):

* `DESIGN.md`
  * Update the “Address encoding” section to remove `(pk_enc, addr_tag)` and replace with the actual address components used after this change.
  * Update wallet crate implementation bullets to remove hint-tag mentions.

* `METHODS.md`
  * Remove `addr_tag(d)` from the address definition and remove the “Option B (with hint tags)” scanning path.
  * Update the note encryption description so it no longer claims ciphertexts “record the hint tag”.

* `docs/assets/diagrams.md`
  * Remove the “Address tags” node/arrow and adjust any text that mentions tags.

Finally, run a repo-wide search to ensure no mention remains (see Validation and Acceptance).


## Concrete Steps

Run all commands from the repository root: `synthetic-hegemonic-currency/`.

Toolchain setup and builds:

    make setup
    make node
    cargo build -p wallet -p walletd --release

Fast correctness checks while iterating:

    cargo test -p crypto
    cargo test -p wallet
    cargo test -p hegemon-node
    cargo test -p pallet-shielded-pool

Full workspace tests (slower):

    cargo test --workspace

Regenerate a shared chainspec (required because this is a protocol break):

    ./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json
    shasum -a 256 config/dev-chainspec.json

Start a fresh dev node (pick one; `--tmp` is the cleanest for repeated validation):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Or, for the two-person testnet runbook flow (persistent base path, shared spec):

    rm -rf ~/.hegemon-node
    HEGEMON_MINE=1 \
    ./target/release/hegemon-node \
      --dev \
      --base-path ~/.hegemon-node \
      --chain config/dev-chainspec.json

Create two wallets and mine to one of them:

    rm -f ~/.hegemon-wallet-alice ~/.hegemon-wallet-bob
    ./target/release/wallet init --store ~/.hegemon-wallet-alice --passphrase "ALICE_CHANGE_ME"
    ./target/release/wallet init --store ~/.hegemon-wallet-bob   --passphrase "BOB_CHANGE_ME"

Get addresses (offline):

    ./target/release/wallet status --store ~/.hegemon-wallet-alice --passphrase "ALICE_CHANGE_ME" --no-sync
    ./target/release/wallet status --store ~/.hegemon-wallet-bob   --passphrase "BOB_CHANGE_ME"   --no-sync

Run the miner node with the new-format address (example pattern from runbooks):

    HEGEMON_MINE=1 \
    HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet-alice --passphrase "ALICE_CHANGE_ME" --no-sync 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
    ./target/release/hegemon-node --dev --tmp

Sync wallets and send a transaction (copied from `runbooks/two_person_testnet.md`):

    ./target/release/wallet substrate-sync \
      --store ~/.hegemon-wallet-alice \
      --ws-url ws://127.0.0.1:9944 \
      --passphrase "ALICE_CHANGE_ME"

    ./target/release/wallet substrate-sync \
      --store ~/.hegemon-wallet-bob \
      --ws-url ws://127.0.0.1:9944 \
      --passphrase "BOB_CHANGE_ME"

Create a recipients file:

    cat > /tmp/recipients.json <<'JSON'
    [
      {
        "address": "<BOB_SHIELDED_ADDRESS>",
        "value": 5000000000,
        "asset_id": 0,
        "memo": "first hegemon tx (no hint tags)"
      }
    ]
    JSON

Send:

    ./target/release/wallet substrate-send \
      --store ~/.hegemon-wallet-alice \
      --auto-consolidate \
      --ws-url ws://127.0.0.1:9944 \
      --recipients /tmp/recipients.json \
      --passphrase "ALICE_CHANGE_ME"


## Validation and Acceptance

This work is complete only when all of the following are true:

1. No hint-tag code or docs remain:

       rg -n "hint_tag|address_tag|addr_tag|addr-tag|hint tag" .

   Expect: no matches.

2. The node, wallet, and app build:

       make node
       cargo build -p wallet -p walletd --release

3. Unit and integration tests pass (at minimum, the crates touched by this plan):

       cargo test -p crypto
       cargo test -p wallet
       cargo test -p hegemon-node
       cargo test -p pallet-shielded-pool

4. On a fresh chain, the wallet can still:
   * sync without aborting due to decryption failures,
   * receive mined coinbase notes,
   * send a shielded transfer,
   * and the recipient wallet can sync and observe the received note.

5. The on-chain encrypted note byte lengths match the new format:
   * `ciphertext` is 579 bytes,
   * `kem_ciphertext` is 1088 bytes,
   * concatenated wallet-facing bytes are 1667 bytes.

6. The on-chain coinbase audit recipient address contains no tag bytes:
   * `recipient_address.len()` is 37 bytes (version + diversifier_index + pk_recipient).


## Idempotence and Recovery

Because this is a protocol break, “rerun” safety mostly means “always work on a clean chain and clean wallet stores”:

* Prefer running the node with `--tmp` while iterating so you never accidentally reuse old storage.
* If you use a persistent base path, delete it before running a new binary:
  * `rm -rf ~/.hegemon-node`
* Delete any old wallet stores created before this change:
  * `rm -f ~/.hegemon-wallet*`
* If a wallet store is kept but its recorded genesis hash mismatches, use `wallet substrate-sync --force-rescan` (if available) or delete and recreate the store for this reset-era network.


## Artifacts and Notes

Expected structural diffs you should observe during implementation:

* `shca1...` addresses become slightly shorter (one removed 32-byte field), but they remain very long due to ML‑KEM public keys.
* The wallet’s on-chain ciphertext blobs shrink by exactly 32 bytes.
* Wallet sync no longer prints or reasons about any tag values under debug mode.


## Interfaces and Dependencies

At the end of this plan, these “no-tag” interfaces must exist and be used everywhere:

* `wallet::address::ShieldedAddress` contains:
  * `version: u8`
  * `diversifier_index: u32`
  * `pk_recipient: [u8; 32]`
  * `pk_enc: MlKemPublicKey`

* `crypto::note_encryption::NoteCiphertext` contains:
  * `version: u8`
  * `diversifier_index: u32`
  * `kem_ciphertext: Vec<u8>` (1088 bytes)
  * `note_payload: Vec<u8>`
  * `memo_payload: Vec<u8>`

* Pallet constants and formats:
  * `pallet_shielded_pool::types::ENCRYPTED_NOTE_SIZE == 579`
  * `pallet_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE == 37`
