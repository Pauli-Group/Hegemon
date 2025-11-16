#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<USAGE
Usage: $0 [--out <dir>] [--value <amount>] [--asset <asset_id>]

Bootstraps a throwaway wallet, crafts a sample transaction targeting the first
shielded address, and scans the resulting ciphertexts to produce a balance
report. Use --out to retain the generated artifacts.
USAGE
}

DEST_DIR=""
VALUE=42
ASSET_ID=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)
            DEST_DIR="$2"
            shift 2
            ;;
        --value)
            VALUE="$2"
            shift 2
            ;;
        --asset)
            ASSET_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required (run scripts/dev-setup.sh)" >&2
    exit 1
fi

TMP=$(mktemp -d)
cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

cargo run -p wallet --bin wallet -- generate --count 1 --out "$TMP/export.json" >/dev/null
ROOT=$(jq -r '.root_secret' "$TMP/export.json")
ADDRESS=$(jq -r '.addresses[0].address' "$TMP/export.json")
jq '.incoming_viewing_key' "$TMP/export.json" > "$TMP/ivk.json"

echo '[]' > "$TMP/inputs.json"
cat > "$TMP/recipients.json" <<JSON
[
  {
    "address": "$ADDRESS",
    "value": $VALUE,
    "asset_id": $ASSET_ID,
    "memo": null
  }
]
JSON

cargo run -p wallet --bin wallet -- tx-craft \
    --root "$ROOT" \
    --inputs "$TMP/inputs.json" \
    --recipients "$TMP/recipients.json" \
    --merkle-root 0 \
    --fee 0 \
    --witness-out "$TMP/witness.json" \
    --ciphertext-out "$TMP/ledger.json" >/dev/null

cargo run -p wallet --bin wallet -- scan \
    --ivk "$TMP/ivk.json" \
    --ledger "$TMP/ledger.json" \
    --out "$TMP/report.json" >/dev/null

if [[ -n "$DEST_DIR" ]]; then
    mkdir -p "$DEST_DIR"
    cp "$TMP"/*.json "$DEST_DIR"/
    echo "Artifacts written to $DEST_DIR"
else
    echo "Wallet demo complete. Balance report:"
    cat "$TMP/report.json"
fi
