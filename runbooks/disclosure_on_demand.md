# Disclosure-on-Demand (Payment Proof) Runbook

This runbook demonstrates a full payment-proof flow: a sender generates a disclosure package for a specific shielded output, and a verifier validates it without any secret keys.

## Prereqs

Run these once on a fresh clone (repo root):

    make setup
    make node
    cargo build --release -p walletd

## Demo steps

Terminal A (start the dev node with mining enabled):

    export ALICE_STORE=/tmp/hegemon-alice.wallet
    export ALICE_PW="alice-pass"
    export ALICE_ADDR=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "$ALICE_PW" \
      | ./target/release/walletd --store "$ALICE_STORE" --mode create \
      | jq -r '.result.primaryAddress')
    HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS="$ALICE_ADDR" ./target/release/hegemon-node --dev --tmp

Terminal B (create an exchange wallet and address):

    export EX_STORE=/tmp/hegemon-exchange.wallet
    export EX_PW="exchange-pass"
    export EX_ADDR=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "$EX_PW" \
      | ./target/release/walletd --store "$EX_STORE" --mode create \
      | jq -r '.result.primaryAddress')
    echo "$EX_ADDR"

Wait until Alice has funds (Terminal B):

    printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "$ALICE_PW" \
      | ./target/release/walletd --store "$ALICE_STORE" --mode open \
      | jq '.result'

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
    REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --argjson recipients "$(jq -c '.' /tmp/recipients_exchange.json)" \
      '{id:1,method:"tx.send",params:{ws_url:$ws,recipients:$recipients,fee:0,auto_consolidate:true}}')
    export TX_HASH=$(printf '%s\n%s\n' "$ALICE_PW" "$REQ" \
      | ./target/release/walletd --store "$ALICE_STORE" --mode open \
      | jq -r '.result.txHash')

Generate the disclosure package:

    DISCLOSURE_REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --arg tx "$TX_HASH" \
      '{id:1,method:"disclosure.create",params:{ws_url:$ws,tx_id:$tx,output:0}}')
    printf '%s\n%s\n' "$ALICE_PW" "$DISCLOSURE_REQ" \
      | ./target/release/walletd --store "$ALICE_STORE" --mode open \
      | jq '.result' > /tmp/payment_proof.json

Verify as the exchange (Terminal B):

    VERIFY_REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --slurpfile pkg /tmp/payment_proof.json \
      '{id:1,method:"disclosure.verify",params:{ws_url:$ws,package:$pkg[0]}}')
    printf '%s\n%s\n' "$EX_PW" "$VERIFY_REQ" \
      | ./target/release/walletd --store "$EX_STORE" --mode open

Expected output includes a line like:

    "verified": true, "recipientAddress": "shca1...", "value": 100000000, "assetId": 0

Tamper test (edit the value and verify failure):

    python3 - <<'PY'
    import json
    path = "/tmp/payment_proof.json"
    data = json.load(open(path, "r", encoding="utf-8"))
    data["claim"]["value"] += 1
    json.dump(data, open(path, "w", encoding="utf-8"), indent=2)
    print("tampered", path)
    PY
    VERIFY_REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --slurpfile pkg /tmp/payment_proof.json \
      '{id:1,method:"disclosure.verify",params:{ws_url:$ws,package:$pkg[0]}}')
    printf '%s\n%s\n' "$EX_PW" "$VERIFY_REQ" \
      | ./target/release/walletd --store "$EX_STORE" --mode open

Optional cleanup (purge stored disclosure records):

walletd does not expose purge yet. Delete the store or use `wallet payment-proof purge`.
