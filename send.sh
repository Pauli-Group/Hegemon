
#!/usr/bin/env bash
set -euo pipefail

PASSWORD="${1:-}"
RECIPIENTS_FILE="${2:-}"

if [ -z "$PASSWORD" ] || [ -z "$RECIPIENTS_FILE" ]; then
  echo "Usage: $0 <wallet-passphrase> <recipients-file>"
  exit 1
fi

./target/release/wallet substrate-send \
  --store ~/.hegemon-wallet \
  --passphrase "$PASSWORD" \
  --recipients "$RECIPIENTS_FILE" \
  --ws-url ws://127.0.0.1:9944