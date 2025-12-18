# Disclosure-on-Demand (ZK Payment Disclosure Proof) ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Ship a working “disclosure on demand” demo where a sender can produce a **zero-knowledge payment disclosure proof** for a specific shielded output, and an exchange (or regulator) can verify it without learning any extra transaction details.

After this work, a user can:

1. Send a shielded payment to an exchange deposit address (no transparent pool).
2. Generate a disclosure package proving: “I paid exactly `X` of asset `A` to deposit address `Y`”, anchored to an on-chain commitment.
3. Hand that package to a verifier, who can validate it and (in the demo) “credit” a deposit account.

The key property of the ZK option is: the disclosure package does **not** reveal the note opening secrets `rho` and `r` (the randomness that makes commitments hiding), while still letting the verifier validate the claim.

## Progress

- [ ] (2025-12-18) Draft this ExecPlan (completed: skeleton; remaining: finalize interfaces + demo transcripts).
- [ ] Add `circuits/disclosure` crate with STARK AIR/prover/verifier for note-opening disclosure.
- [ ] Add `wallet payment-proof create` command (generates disclosure package JSON).
- [ ] Add `wallet payment-proof verify` command (verifies package; optional anchor check against node).
- [ ] Extend wallet persistence to support “on demand” generation after send (store outgoing note openings and commitments securely).
- [ ] Add demo runbook and a minimal end-to-end automated test (tamper-reject + happy path).

## Surprises & Discoveries

- Observation: (none yet)
  Evidence: (none yet)

## Decision Log

- Decision: Implement a dedicated disclosure circuit (`circuits/disclosure`) rather than trying to reuse the transaction circuit.
  Rationale: The transaction circuit proves spend validity and balance; disclosure needs a much smaller statement (knowledge of note-opening randomness) and should be verifiable by exchanges without requiring the whole transaction witness.
  Date/Author: 2025-12-18 / Codex

- Decision: The disclosure package contains (1) a ZK proof binding `commitment -> (value, asset_id, pk_recipient)` and (2) non-ZK “confirmation data” (Merkle inclusion + anchor root) as a separate, explicit artifact.
  Rationale: This matches the “payment proof” model in `docs/COMPLIANCE_ARCHITECTURE.md` and keeps the new STARK circuit smaller while still anchoring the claim to the chain.
  Date/Author: 2025-12-18 / Codex

## Outcomes & Retrospective

(Fill in after milestones land.)

## Context and Orientation

This repository implements one shielded pool (no transparent pool). Value moves as encrypted “notes” whose **commitments** are recorded on-chain. The chain stores:

- A Merkle tree of note commitments (append-only).
- A nullifier set (prevents double spends).
- Encrypted note ciphertexts (recipients decrypt with ML‑KEM + AEAD).

Important terms (plain language):

- A “note” is a private UTXO-like record. In code it is represented by `transaction_circuit::note::NoteData` (value, asset id, recipient key material, and two random 32-byte fields).
- A “note commitment” is a public 32-byte identifier derived from the note fields. In code this is computed by `transaction_circuit::hashing::note_commitment` / `note_commitment_bytes`.
- `rho` and `r` are 32-byte per-note secrets. Knowing them lets you open the commitment. In the “fast demo” approach you reveal them; in this ZK approach you keep them hidden.
- An “anchor” is a historical Merkle root accepted by the chain as valid. The runtime exposes `is_valid_anchor`; the Substrate RPC exposes `hegemon_isValidAnchor`.
- A “disclosure package” (this feature) is what the user hands to an exchange/regulator: it contains the claim + ZK proof + confirmation data so the verifier can validate against the chain.

Relevant code you will touch:

- `circuits/transaction/src/hashing.rs` defines the reference `note_commitment` function used throughout the system.
- `state/merkle` and `wallet/src/store.rs` build a local commitment tree (`WalletStore::commitment_tree`) used to compute Merkle inclusion proofs.
- `pallets/shielded-pool/src/lib.rs` stores historical Merkle roots and exposes `is_valid_anchor`.
- `wallet/src/bin/wallet.rs` is the CLI entry point we will extend with new commands.

This work is specifically the “ZK disclosure proof” option: do not reveal `rho`/`r` in the disclosure package; instead, prove in ZK that you know them.

## Plan of Work

### Milestone 1: Define the disclosure package and CLI surface (no cryptography yet)

Add a stable on-disk JSON format for the disclosure package and implement CLI plumbing that can read/write it.

The format must include:

- The **claim**: recipient address, asset id, value, and the on-chain commitment bytes.
- The **confirmation data**: a Merkle root (anchor) plus a Merkle authentication path showing the commitment is in the tree rooted at that anchor.
- The **ZK proof bytes**: base64-encoded.
- An explicit `version` and `air_hash` so verifiers can reject proofs for the wrong circuit.

At the end of this milestone, `wallet payment-proof create` can be implemented as “not yet supported” with a clear error, but `wallet payment-proof verify --help` must show the interface we will support.

### Milestone 2: Implement the disclosure STARK circuit (`circuits/disclosure`)

Create a new workspace crate at `circuits/disclosure` which proves the following statement:

Public (what verifiers learn):

- `value` (u64) and `asset_id` (u64)
- `pk_recipient` (32 bytes) derived from the recipient shielded address
- `commitment` (32 bytes; the on-chain commitment)

Private (what stays hidden):

- `rho` (32 bytes) and `r` (32 bytes)

Statement (in plain language):

> “I know `rho` and `r` such that the note commitment computed from `(value, asset_id, pk_recipient, rho, r)` equals the public `commitment`.”

This is a proof of knowledge of the commitment opening randomness for a specific note, without revealing it.

Implementation constraints:

- The commitment computation inside the circuit must match the reference implementation used elsewhere (`transaction_circuit::hashing::note_commitment`), including byte-to-field encoding and domain tags.
- The verifier must reject if the prover changes `value`, `asset_id`, `pk_recipient`, or `commitment`.
- Add tamper-reject tests that flip 1 bit of each public field and ensure verification fails.

### Milestone 3: Generate “confirmation data” (Merkle inclusion proof) in the wallet

Extend the wallet so it can produce Merkle inclusion data for a given commitment:

- Find the commitment’s leaf index in the locally-synced commitment list.
- Build the Merkle authentication path to a chosen anchor root.

The disclosure package must include:

- `anchor` root (32 bytes) that the verifier can check with `hegemon_isValidAnchor`.
- `path.siblings` (a fixed-length list for depth 32) and `path.position_bits` (left/right flags) so the verifier can recompute the root from the leaf commitment.

This Merkle proof is not ZK. It is “confirmation data” that binds the disclosure claim to an on-chain state snapshot.

### Milestone 4: Wallet UX: generate a payment proof “on demand”

Add wallet persistence so the sender can generate a payment proof after the send, not only at the moment of crafting the transaction.

Concretely:

- When building an outgoing transaction, persist enough data to later generate a disclosure proof for each output:
  - output `NoteData` (including `rho` and `r`)
  - output commitment bytes
  - recipient address string used at send time
  - tx hash (so the user can reference it)
- Store this inside the encrypted wallet store (`wallet/src/store.rs`) so it is protected by the wallet passphrase.

Add CLI commands:

- `wallet payment-proof create --store <path> --tx <0x…> --output 0 --out <file> --ws-url <ws://…>`
  - Syncs wallet if needed, finds the stored outgoing output, builds Merkle confirmation data, generates the disclosure STARK proof, and writes the disclosure package JSON.
- `wallet payment-proof verify --proof <file> --ws-url <ws://…>`
  - Verifies the disclosure STARK proof.
  - Verifies Merkle inclusion (recompute root from leaf and path).
  - Calls `hegemon_isValidAnchor(anchor)` and fails if false.
  - If `--credit-ledger <path>` is provided, appends a JSONL record for the verified deposit (demo-only exchange ledger).
  - Prints a single-line “VERIFIED: paid X asset A to address Y; commitment=…; anchor=…” transcript suitable for exchange logs.

### Milestone 5: Demo spec (what we will show working)

The demo must be runnable locally with two “roles”:

- Alice (payer): a wallet that holds funds and sends to an exchange deposit address.
- Exchange (verifier): a process that verifies the disclosure package and “credits” a local ledger file (for the demo only).

The demo behavior we require:

1. Start a dev node with mining enabled and mine enough blocks for Alice to have a non-zero balance.
2. Generate an Exchange deposit address.
3. Alice sends `1.0` HGM to the Exchange deposit address.
4. Alice generates a disclosure package for that payment.
5. Exchange verifies the package and writes a `credited_deposits.jsonl` record containing:
   - deposit account id (demo: use the recipient shielded address string)
   - amount, asset id
   - commitment and anchor
   - verification timestamp
   - a unique key so the same commitment is not credited twice (demo: use commitment hex as the idempotence key)
6. Tamper test: modify the disclosed `value` in the JSON and show verification fails.

The demo is considered successful only if the verifier does not require any secret keys and can validate purely from:

- the disclosure package file
- access to the node RPC for `isValidAnchor` (and optionally chain height for logging)

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
    python - <<'PY'
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

    ✓ Transaction submitted successfully!
      TX Hash: 0x<hex>

Generate the disclosure package (Terminal B):

    export TX_HASH=0x__REPLACE_WITH_TX_HASH__
    ./target/release/wallet payment-proof create --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --tx "$TX_HASH" --output 0 --out /tmp/payment_proof.json

Verify the disclosure package as the exchange (Terminal B):

    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof.json --ws-url ws://127.0.0.1:9944 --credit-ledger /tmp/credited_deposits.jsonl

Expected output (shape; exact formatting may differ):

    VERIFIED paid value=100000000 asset_id=0 to=shca1... commitment=0x... anchor=0x...

Tamper test (Terminal B):

    python - <<'PY'
    import json
    src = "/tmp/payment_proof.json"
    dst = "/tmp/payment_proof_tampered.json"
    data = json.load(open(src, "r", encoding="utf-8"))
    data["claim"]["value"] = 999
    json.dump(data, open(dst, "w", encoding="utf-8"), indent=2)
    print("wrote", dst)
    PY
    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof_tampered.json --ws-url ws://127.0.0.1:9944

Expected output contains “verification failed” and exits non-zero.

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
- The disclosure package must not contain `rho` or `r` in plaintext.
- The verifier must check `hegemon_isValidAnchor(anchor)` and reject if false.
- When `--credit-ledger` is enabled, the verifier appends exactly one JSON object per verified proof and refuses to credit the same commitment twice (idempotence by commitment).

Test expectations:

- Add unit tests in `circuits/disclosure`:
  - “roundtrip verifies”
  - “tamper reject” for each public field
- Add a wallet-level test (can be ignored/heavy if needed) that exercises create+verify using the CLI with a local dev node.

## Idempotence and Recovery

This work will touch wallet persistence. Provide safe recovery steps:

- If a wallet store schema changes, include a version bump and a migration path so existing stores fail with a clear message rather than silently corrupting state.
- All demo steps should be repeatable by deleting `/tmp/hegemon-*.wallet`, restarting the node with `--tmp`, and re-running the commands.
- If chain state is reset, the wallet should detect mismatch (genesis hash) and instruct the user to resync or reset sync state.

## Artifacts and Notes

Disclosure package example (structure only, not exact fields):

    {
      "version": 1,
      "claim": {
        "recipient_address": "shca1...",
        "value": 100000000,
        "asset_id": 0,
        "commitment": "0x...",
        "anchor": "0x..."
      },
      "merkle_proof": {
        "leaf_index": 123,
        "siblings": ["0x...", "..."],
        "path_bits": [true, false, ...]
      },
      "air_hash": "0x...",
      "proof": "base64..."
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

The disclosure circuit must embed an AIR hash similar to `transaction-circuit` so verifiers can reject mismatched constraint systems.

In `wallet`, define a JSON-serializable “package” type that combines:

- `PaymentDisclosureProofBundle` (ZK part)
- Merkle inclusion proof (non-ZK confirmation data)
- Recipient address string (for UX + decoding check)
- Anchor root (for `isValidAnchor`)

Add wallet CLI subcommands that call these functions and print deterministic transcripts.

At the end of implementation, the only “exchange integration” required for the demo is running `wallet payment-proof verify` and persisting a JSONL credit record; no custom exchange keys or chain-indexing infrastructure is allowed in the demo.
