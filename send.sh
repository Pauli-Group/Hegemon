
#!/usr/bin/env bash
set -euo pipefail

RECIPIENTS_FILE="${1:-}"

if [ "$#" -ne 1 ] || [ -z "$RECIPIENTS_FILE" ]; then
  echo "Usage: $0 <recipients-file>" >&2
  echo "The wallet binary will prompt for the passphrase securely." >&2
  exit 1
fi

./target/release/wallet node-send \
  --store ~/.hegemon-wallet \
  --recipients "$RECIPIENTS_FILE" \
  --ws-url ws://127.0.0.1:9944
