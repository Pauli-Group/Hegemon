# Disclosure-on-Demand (Payment Proof) Runbook

This runbook demonstrates a full payment-proof flow: a sender generates a disclosure package for a specific shielded output, and a verifier validates it without any secret keys.

## Prereqs

Run these once on a fresh clone (repo root):

    make setup
    make node
    cargo build --release -p wallet

## Demo steps

Terminal A (start the dev node with mining enabled):

    export ALICE_STORE=/tmp/hegemon-alice.wallet
    export ALICE_PW="alice-pass"
    ./target/release/wallet init --store "$ALICE_STORE" --passphrase "$ALICE_PW"
    export ALICE_ADDR=$(./target/release/wallet status --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --no-sync | awk '/Shielded Address/ {print $3}')
    HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS="$ALICE_ADDR" ./target/release/hegemon-node --dev --tmp

Terminal B (create an exchange wallet and address):

    export EX_STORE=/tmp/hegemon-exchange.wallet
    export EX_PW="exchange-pass"
    ./target/release/wallet init --store "$EX_STORE" --passphrase "$EX_PW"
    export EX_ADDR=$(./target/release/wallet status --store "$EX_STORE" --passphrase "$EX_PW" --ws-url ws://127.0.0.1:9944 --no-sync | awk '/Shielded Address/ {print $3}')
    echo "$EX_ADDR"

Wait until Alice has funds (Terminal B):

    ./target/release/wallet status --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944

Send 1.0 HGM to the exchange address (Terminal B):

    cat > /tmp/recipients_exchange.json <<'JSON'
    [
      {
        "address": "REPLACE_WITH_EX_ADDR",
        "value": 100000000,
        "asset_id": 0,
        "memo": "deposit"
      }
    ]
    JSON
    python3 - <<'PY'
    import json, os
    path = "/tmp/recipients_exchange.json"
    ex_addr = os.environ["EX_ADDR"]
    data = json.load(open(path, "r", encoding="utf-8"))
    data[0]["address"] = ex_addr
    json.dump(data, open(path, "w", encoding="utf-8"), indent=2)
    print("wrote", path)
    PY
    ./target/release/wallet substrate-send --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --recipients /tmp/recipients_exchange.json --fee 0

Capture the transaction hash from the output (line starting with `TX Hash:`), then generate the disclosure package:

    export TX_HASH=0xREPLACE_WITH_TX_HASH
    ./target/release/wallet payment-proof create --store "$ALICE_STORE" --passphrase "$ALICE_PW" --ws-url ws://127.0.0.1:9944 --tx "$TX_HASH" --output 0 --out /tmp/payment_proof.json

Verify as the exchange (Terminal B):

    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof.json --ws-url ws://127.0.0.1:9944 --credit-ledger /tmp/credited_deposits.jsonl --case-id DEMO-001

Expected output includes a line like:

    VERIFIED paid value=100000000 asset_id=0 to=shca1... commitment=0x... anchor=0x... chain=0x...

Tamper test (edit the value and verify failure):

    python3 - <<'PY'
    import json
    path = "/tmp/payment_proof.json"
    data = json.load(open(path, "r", encoding="utf-8"))
    data["claim"]["value"] += 1
    json.dump(data, open(path, "w", encoding="utf-8"), indent=2)
    print("tampered", path)
    PY
    ./target/release/wallet payment-proof verify --proof /tmp/payment_proof.json --ws-url ws://127.0.0.1:9944

Optional cleanup (purge stored disclosure records):

    ./target/release/wallet payment-proof purge --store "$ALICE_STORE" --passphrase "$ALICE_PW" --all
