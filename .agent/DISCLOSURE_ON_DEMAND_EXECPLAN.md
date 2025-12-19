# Disclosure-on-Demand (ZK Payment Disclosure Proof) ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Ship a working "disclosure on demand" demo where a sender can produce a **zero-knowledge payment disclosure proof** for a specific shielded output, and an exchange (or regulator) can verify it without learning any extra transaction details. This is the concrete "payment proof" path described in `docs/COMPLIANCE_ARCHITECTURE.md`: targeted disclosure for compliance requests without handing over a full viewing key.

After this work, a user can send a shielded payment to an exchange deposit address (no transparent pool), generate a disclosure package proving "I paid exactly `X` of asset `A` to deposit address `Y`" anchored to an on-chain commitment, and hand that package to a verifier who can validate it and (in the demo) credit a deposit account. The disclosure package must never reveal the note-opening secrets `rho` and `r` (the randomness that makes commitments hiding), while still letting the verifier validate the claim.

## Progress

- [x] (2025-12-18) Draft this ExecPlan (completed: skeleton).
- [x] (2025-12-19 07:23Z) Flesh out compliance scope, package schema, chain identity checks, and documentation requirements.
- [ ] Add `circuits/disclosure` crate with STARK AIR/prover/verifier for note-opening disclosure.
- [ ] Add `wallet payment-proof create` command (generates disclosure package JSON).
- [ ] Add `wallet payment-proof verify` command (verifies package, including anchor check against node).
- [ ] Extend wallet persistence to support "on demand" generation after send (store outgoing note openings and commitments securely).
- [ ] Add demo runbook and a minimal end-to-end automated test (tamper-reject + happy path).
- [ ] Update compliance and privacy docs (`docs/COMPLIANCE_ARCHITECTURE.md`, `docs/USER_PRIVACY_GUIDELINES.md`, `docs/API_REFERENCE.md`, `DESIGN.md`, `METHODS.md`) plus a runbook for the disclosure flow.

## Surprises & Discoveries

- Observation: Wallet commitment history is stored as Poseidon field elements (`u64`), so disclosure tooling must convert with `transaction_core::hashing::felt_to_bytes32` and search by field value before building Merkle paths.
  Evidence: `wallet/src/store.rs` (`commitments: Vec<u64>`).
- Observation: Anchor validation is exposed via the `hegemon_isValidAnchor` RPC in the `hegemon` namespace.
  Evidence: `node/src/substrate/rpc/shielded.rs`.

## Decision Log

- Decision: Implement a dedicated disclosure circuit (`circuits/disclosure`) rather than trying to reuse the transaction circuit.
  Rationale: The transaction circuit proves spend validity and balance; disclosure needs a much smaller statement (knowledge of note-opening randomness) and should be verifiable by exchanges without requiring the whole transaction witness.
  Date/Author: 2025-12-18 / Codex

- Decision: The disclosure package contains (1) a ZK proof binding `commitment -> (value, asset_id, pk_recipient)` and (2) non-ZK "confirmation data" (Merkle inclusion + anchor root) as a separate, explicit artifact.
  Rationale: This matches the "payment proof" model in `docs/COMPLIANCE_ARCHITECTURE.md` and keeps the new STARK circuit smaller while still anchoring the claim to the chain.
  Date/Author: 2025-12-18 / Codex

- Decision: Include chain identity (`genesis_hash`) in the disclosure package and require verifiers to compare it to `chain_getBlockHash(0)` before crediting.
  Rationale: Prevents cross-chain reuse of compliance artifacts and provides stable audit context.
  Date/Author: 2025-12-19 / Codex

- Decision: Include `pk_recipient` in the package and require verifiers to decode `recipient_address` and confirm the derived `pk_recipient` matches.
  Rationale: Binds the proof to a concrete deposit address while keeping the proof's public inputs explicit and verifiable.
  Date/Author: 2025-12-19 / Codex

- Decision: Persist outgoing disclosure records encrypted in the wallet store until explicit purge.
  Rationale: On-demand proofs are often requested after settlement; retention enables compliance without re-crafting transactions.
  Date/Author: 2025-12-19 / Codex

## Outcomes & Retrospective

(Fill in after milestones land.)

## Context and Orientation

This repository implements one shielded pool (no transparent pool). Value moves as encrypted "notes" whose **commitments** are recorded on-chain. The chain stores a Merkle tree of note commitments (append-only), a nullifier set (prevents double spends), and encrypted note ciphertexts (recipients decrypt with ML-KEM + AEAD). The compliance architecture expects "payment proofs" as a targeted disclosure path, which this ExecPlan implements.

Important terms (plain language) that this plan relies on are defined as follows. A "note" is a private UTXO-like record represented by `transaction_circuit::note::NoteData` (value, asset id, recipient key material, and two random 32-byte fields). A "note commitment" is a public 32-byte identifier derived from the note fields; compute it with `transaction_circuit::hashing::note_commitment` / `note_commitment_bytes` (these match `pallets/shielded-pool/src/commitment.rs::circuit_note_commitment`). `rho` and `r` are per-note secrets that open the commitment, so the disclosure package must not reveal them. An "anchor" is a historical Merkle root accepted by the chain as valid, exposed by the runtime as `is_valid_anchor` and by the RPC method `hegemon_isValidAnchor`. A "disclosure package" is the compliance artifact the user hands to an exchange or regulator; it contains the claim, a ZK proof, and non-ZK confirmation data so a verifier can validate against the chain.

Relevant code you will touch includes `circuits/transaction-core/src/hashing.rs` for canonical note commitment hashing, `state/merkle` plus `wallet/src/store.rs` for local commitment tree construction (`WalletStore::commitment_tree`), `pallets/shielded-pool/src/lib.rs` for `is_valid_anchor`, the `hegemon_walletCommitments` and `hegemon_walletNotes` RPC endpoints in `wallet/src/substrate_rpc.rs`, and `wallet/src/bin/wallet.rs` for CLI integration. The compliance narrative must stay aligned with `docs/COMPLIANCE_ARCHITECTURE.md` and privacy hygiene in `docs/USER_PRIVACY_GUIDELINES.md`.

This work is specifically the "ZK disclosure proof" option: do not reveal `rho` or `r` in the disclosure package; instead, prove in ZK that you know them.

## Plan of Work

### Milestone 1: Define the disclosure package and CLI surface (no cryptography yet)

Add a stable on-disk JSON format for the disclosure package and implement CLI plumbing that can read/write it. The format must include a `version`, a `chain` section with `genesis_hash`, a `claim` with `recipient_address`, `pk_recipient`, `value`, `asset_id`, and the on-chain commitment bytes, a `confirmation` section with the Merkle anchor plus an authentication path, and a `proof` section containing `air_hash` plus base64 proof bytes. All 32-byte fields must be hex-encoded with `0x` prefixes and validated as canonical field encodings (first 24 bytes zero). The verifier must decode `recipient_address` to `pk_recipient` and reject mismatches so the disclosure is tied to a concrete deposit address. If a memo or Travel Rule payload is optionally disclosed, include it as a separate `disclosed_memo` field and label it as non-ZK-bound so verifiers treat it as user-supplied context.

At the end of this milestone, `wallet payment-proof create` can be implemented as "not yet supported" with a clear error, but `wallet payment-proof verify --help` must show the interface we will support, including the mandatory `--ws-url` anchor check and optional `--credit-ledger` logging.

### Milestone 2: Implement the disclosure STARK circuit (`circuits/disclosure`)

Create a new workspace crate at `circuits/disclosure` which proves the following statement and follows the same Winterfell structure as `circuits/transaction` (AIR, prover, verifier, proof bundle, and `compute_air_hash` helpers).

Public (what verifiers learn):

- `value` (u64) and `asset_id` (u64)
- `pk_recipient` (32 bytes) derived from the recipient shielded address
- `commitment` (32 bytes; the on-chain commitment)

Private (what stays hidden):

- `rho` (32 bytes) and `r` (32 bytes)

Statement (in plain language):

> "I know `rho` and `r` such that the note commitment computed from `(value, asset_id, pk_recipient, rho, r)` equals the public `commitment`."

This is a proof of knowledge of the commitment opening randomness for a specific note, without revealing it.

Implementation constraints include: the commitment computation inside the circuit must match the reference implementation in `transaction_core::hashing::note_commitment` including byte-to-field encoding and domain tags; the verifier must reject if the prover changes `value`, `asset_id`, `pk_recipient`, or `commitment`; and proof generation must fail if the public commitment bytes are not canonical (`bytes32_to_felt` returns `None`). Add tamper-reject tests that flip one bit of each public field and ensure verification fails, plus a test that swaps `pk_recipient` for the same value/asset to ensure the proof binds the recipient.

### Milestone 3: Generate "confirmation data" (Merkle inclusion proof) in the wallet

Extend the wallet so it can produce Merkle inclusion data for a given commitment by finding the commitment's leaf index in the locally-synced commitment list and building the authentication path to a chosen anchor root using `WalletStore::commitment_tree`. The disclosure package must include the `anchor` root (32 bytes, canonical encoding) plus a fixed-length list of sibling hashes (depth 32) and a `leaf_index` so the verifier can recompute the root using the same left/right ordering as `transaction_circuit::note::MerklePath::verify`.

This Merkle proof is not ZK. It is "confirmation data" that binds the disclosure claim to an on-chain state snapshot, and it must be validated alongside `hegemon_isValidAnchor(anchor)` during verification.

### Milestone 4: Wallet UX: generate a payment proof "on demand"

Add wallet persistence so the sender can generate a payment proof after the send, not only at the moment of crafting the transaction. When building an outgoing transaction, persist enough data to later generate a disclosure proof for each output: the output `NoteData` (including `rho` and `r`), the output commitment bytes, the recipient address string used at send time, the transaction hash, the output index (including change outputs), a creation timestamp, the optional memo plaintext (for `disclosed_memo`), and the chain genesis hash observed at send time. Store this inside the encrypted wallet store (`wallet/src/store.rs`) so it is protected by the wallet passphrase and retained until an explicit purge.

Add CLI commands that surface this storage. `wallet payment-proof create --store <path> --tx <0x...> --output 0 --out <file> --ws-url <ws://...>` must sync the wallet if needed, locate the stored outgoing output, build Merkle confirmation data, generate the disclosure STARK proof, and write the disclosure package JSON. `wallet payment-proof verify --proof <file> --ws-url <ws://...>` must verify the disclosure STARK proof, verify Merkle inclusion, call `hegemon_isValidAnchor(anchor)` and fail if false, compare the package `genesis_hash` to `chain_getBlockHash(0)`, and reject if any mismatch or non-canonical encoding is detected. If `--credit-ledger <path>` is provided, append a JSONL record for the verified deposit (demo-only exchange ledger) and use the commitment hex as the idempotence key; allow an optional `--case-id` string to include in the ledger record for audit trails. Print a single-line "VERIFIED: paid X asset A to address Y; commitment=...; anchor=...; chain=..." transcript suitable for exchange logs.

### Milestone 5: Demo spec (what we will show working)

The demo must be runnable locally with two "roles":

- Alice (payer): a wallet that holds funds and sends to an exchange deposit address.
- Exchange (verifier): a process that verifies the disclosure package and "credits" a local ledger file (for the demo only).

The demo behavior we require is: start a dev node with mining enabled and mine enough blocks for Alice to have a non-zero balance, generate an Exchange deposit address, have Alice send `1.0` HGM to the Exchange deposit address, generate a disclosure package for that payment, and have the Exchange verify the package and write a `credited_deposits.jsonl` record containing the deposit account id (use the recipient shielded address string), amount, asset id, commitment, anchor, chain genesis hash, verification timestamp, and a unique idempotence key (commitment hex). The tamper test must modify the disclosed `value` in the JSON and show verification fails.

The demo is considered successful only if the verifier does not require any secret keys and can validate purely from the disclosure package file plus access to the node RPC for `isValidAnchor` and `chain_getBlockHash(0)` for chain identity.

### Milestone 6: Documentation and compliance alignment

Update `docs/COMPLIANCE_ARCHITECTURE.md` to include the final disclosure package schema and verification flow, update `docs/USER_PRIVACY_GUIDELINES.md` with disclosure-package hygiene (least disclosure, secure storage, retention/purge guidance), and update `docs/API_REFERENCE.md` with the new `wallet payment-proof` commands and `circuits/disclosure` crate. If this introduces new architecture or testing steps, update `DESIGN.md` and `METHODS.md` to reflect the new circuit and CLI workflows, and add a short runbook under `runbooks/` describing the disclosure-on-demand demo in prose.

## Concrete Steps

All commands below assume the working directory is the repository root.

Build and run prerequisites (fresh clone):

    make setup
    make node
    cargo build --release -p wallet

Start a dev node with mining enabled (Terminal A):

    export ALICE_STORE=/tmp/hegemon-alice.wallet
    export ALICE_PW="alice-pass"
    ./target/release/wallet init --store "$ALICE_STORE" --passphrase "$ALICE_PW"
    export ALICE_ADDR=$(./target/release/wallet status --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --no-sync | grep "Shielded Address" | awk '{print $3}')
    HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS="$ALICE_ADDR" ./target/release/hegemon-node --dev --tmp

Create an Exchange wallet and get a deposit address (Terminal B):

    export EX_STORE=/tmp/hegemon-exchange.wallet
    export EX_PW="exchange-pass"
    ./target/release/wallet init --store "$EX_STORE" --passphrase "$EX_PW"
    export EX_ADDR=$(./target/release/wallet status --store "$EX_STORE" --passphrase "$EX_PW" --ws-url ws://127.0.0.1:9944 --no-sync | grep "Shielded Address" | awk '{print $3}')
    echo "$EX_ADDR"

Wait until Alice has funds (Terminal B):

    ./target/release/wallet status --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944

Create a recipients file for sending 1.0 HGM to Exchange (Terminal B):

    cat > /tmp/recipients_exchange.json <<'EOF'
    [
      {
        "address": "__REPLACE_WITH_EX_ADDR__",
        "value": 100000000,
        "asset_id": 0,
        "memo": "deposit"
      }
    ]
    EOF
    python3 - <<'PY'
    import json, os
    path = "/tmp/recipients_exchange.json"
    ex_addr = os.environ["EX_ADDR"]
    data = json.load(open(path, "r", encoding="utf-8"))
    data[0]["address"] = ex_addr
    json.dump(data, open(path, "w", encoding="utf-8"), indent=2)
    print("wrote", path)
    PY

Send the payment and capture the tx hash (Terminal B):

    ./target/release/wallet substrate-send --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --recipients /tmp/recipients_exchange.json --fee 0

Expected output includes a line like:

    OK Transaction submitted successfully!
      TX Hash: 0x<hex>

Generate the disclosure package (Terminal B):

    export TX_HASH=0x__REPLACE_WITH_TX_HASH__
    ./target/release/wallet payment-proof create --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --tx "$TX_HASH" --output 0 --out /tmp/payment_proof.json

Verify the disclosure package as the exchange (Terminal B):

    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof.json --ws-url ws://127.0.0.1:9944 --credit-ledger /tmp/credited_deposits.jsonl --case-id DEMO-001

Expected output (shape; exact formatting may differ):

    VERIFIED paid value=100000000 asset_id=0 to=shca1... commitment=0x... anchor=0x... chain=0x...

Tamper test (Terminal B):

    python3 - <<'PY'
    import json
    src = "/tmp/payment_proof.json"
    dst = "/tmp/payment_proof_tampered.json"
    data = json.load(open(src, "r", encoding="utf-8"))
    data["claim"]["value"] = 999
    json.dump(data, open(dst, "w", encoding="utf-8"), indent=2)
    print("wrote", dst)
    PY
    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof_tampered.json --ws-url ws://127.0.0.1:9944

Expected output contains "verification failed" and exits non-zero.

## Validation and Acceptance

Acceptance is defined as observable behavior:

- A verifier without wallet secrets can run `wallet payment-proof verify` and get a positive verification result for a genuine payment proof package produced by the sender.
- The verifier rejects if any of these are modified:
  - `value`
  - `asset_id`
  - `recipient_address` (or its decoded `pk_recipient`)
  - `commitment`
  - `anchor` or Merkle path
  - the STARK proof bytes
- The verifier rejects if `genesis_hash` does not match `chain_getBlockHash(0)` or if any 32-byte field fails canonical encoding checks.
- The disclosure package must not contain `rho` or `r` in plaintext.
- The verifier must check `hegemon_isValidAnchor(anchor)` and reject if false.
- When `--credit-ledger` is enabled, the verifier appends exactly one JSON object per verified proof and refuses to credit the same commitment twice (idempotence by commitment).

Test expectations:

- Add unit tests in `circuits/disclosure`:
  - "roundtrip verifies"
  - "tamper reject" for each public field
  - "reject non-canonical commitment bytes"
- Add a wallet-level test (can be ignored/heavy if needed) that exercises create+verify using the CLI with a local dev node.

## Idempotence and Recovery

This work will touch wallet persistence. Provide safe recovery steps:

- If a wallet store schema changes, include a version bump and a migration path so existing stores fail with a clear message rather than silently corrupting state.
- All demo steps should be repeatable by deleting `/tmp/hegemon-*.wallet`, restarting the node with `--tmp`, and re-running the commands.
- If chain state is reset, the wallet should detect mismatch (genesis hash) and instruct the user to resync or reset sync state.
- Provide an explicit purge path for stored outgoing disclosure records so operators can align retention with their compliance policy.

## Artifacts and Notes

Disclosure package example (structure only, not exact fields):

    {
      "version": 1,
      "chain": {
        "genesis_hash": "0x..."
      },
      "claim": {
        "recipient_address": "shca1...",
        "pk_recipient": "0x...",
        "value": 100000000,
        "asset_id": 0,
        "commitment": "0x..."
      },
      "confirmation": {
        "anchor": "0x...",
        "leaf_index": 123,
        "siblings": ["0x...", "..."]
      },
      "proof": {
        "air_hash": "0x...",
        "bytes": "base64..."
      },
      "disclosed_memo": null
    }

The important property for this ExecPlan: the package must not include `rho` or `r`.

## Interfaces and Dependencies

Create a new crate `circuits/disclosure` with a minimal, stable API that the wallet can call.

In `circuits/disclosure/src/lib.rs`, export:

    pub struct PaymentDisclosureClaim {
        pub value: u64,
        pub asset_id: u64,
        pub pk_recipient: [u8; 32],
        pub commitment: [u8; 32],
    }

    pub struct PaymentDisclosureWitness {
        pub rho: [u8; 32],
        pub r: [u8; 32],
    }

    pub struct PaymentDisclosureProofBundle {
        pub claim: PaymentDisclosureClaim,
        pub proof_bytes: Vec<u8>,
        pub air_hash: [u8; 32],
    }

    pub fn prove_payment_disclosure(
        claim: &PaymentDisclosureClaim,
        witness: &PaymentDisclosureWitness,
    ) -> Result<PaymentDisclosureProofBundle, DisclosureCircuitError>;

    pub fn verify_payment_disclosure(
        bundle: &PaymentDisclosureProofBundle,
    ) -> Result<(), DisclosureVerifyError>;

The disclosure circuit must embed an AIR hash similar to `transaction_circuit::compute_air_hash` so verifiers can reject mismatched constraint systems. Reuse `transaction_core::hashing::{note_commitment, note_commitment_bytes, bytes32_to_felt, felt_to_bytes32, is_canonical_bytes32}` to keep commitment encodings identical to the transaction circuit and pallet.

In `wallet/src/store.rs`, add an encrypted outgoing record type that can be queried later:

    pub struct OutgoingDisclosureRecord {
        pub tx_id: [u8; 32],
        pub output_index: u32,
        pub recipient_address: String,
        pub note: transaction_circuit::note::NoteData,
        pub commitment: [u8; 32],
        pub memo: Option<wallet::notes::MemoPlaintext>,
        pub genesis_hash: [u8; 32],
        pub created_at: u64,
    }

In `wallet`, define a JSON-serializable "package" type that combines:

- `PaymentDisclosureProofBundle` (ZK part)
- Merkle inclusion proof (non-ZK confirmation data)
- Recipient address string (for UX + decoding check)
- Anchor root (for `isValidAnchor`)
- Chain metadata (genesis hash) and optional `disclosed_memo`

Add wallet CLI subcommands that call these functions and print deterministic transcripts.

At the end of implementation, the only "exchange integration" required for the demo is running `wallet payment-proof verify` and persisting a JSONL credit record; no custom exchange keys or chain-indexing infrastructure is allowed in the demo.

Plan update note: 2025-12-19 - Expanded the ExecPlan to align with compliance architecture by adding chain identity checks, disclosure package schema details, retention guidance, and documentation deliverables.
