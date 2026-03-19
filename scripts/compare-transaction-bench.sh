#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tx_json="${TMPDIR:-/tmp}/hegemon-tx-bench.json"
batch_json="${TMPDIR:-/tmp}/hegemon-batch-bench.json"

extract_json_number() {
  local file="$1"
  local key="$2"
  sed -nE "s/.*\"${key}\": ([0-9]+)(,)?/\1/p" "$file" | head -n1
}

extract_json_float() {
  local file="$1"
  local key="$2"
  sed -nE "s/.*\"${key}\": ([0-9]+\\.[0-9]+)(,)?/\1/p" "$file" | head -n1
}

cd "$repo_root"

cargo run -p circuits-bench --release -- --smoke --json >"$tx_json"
cargo run -p circuits-bench --release -- --smoke --json --batch-size 4 --batch-only >"$batch_json"

echo "single_tx proof_bytes_avg=$(extract_json_number "$tx_json" tx_proof_bytes_avg) tx_rows=$(extract_json_number "$tx_json" tx_trace_rows) tx_width=$(extract_json_number "$tx_json" tx_trace_width) tx_schedule_width=$(extract_json_number "$tx_json" tx_schedule_width) prove_ns_per_tx=$(extract_json_number "$tx_json" tx_prove_ns_per_tx) verify_ns_per_tx=$(extract_json_number "$tx_json" tx_verify_ns_per_tx) tx_per_second=$(extract_json_float "$tx_json" transactions_per_second)"
echo "slot_batch size=$(extract_json_number "$batch_json" batch_size) prove_ns_per_tx=$(extract_json_number "$batch_json" batch_prove_ns_per_tx) verify_ns_per_tx=$(extract_json_number "$batch_json" batch_verify_ns_per_tx) tx_per_second=$(extract_json_float "$batch_json" batch_transactions_per_second)"
echo "json saved to $tx_json and $batch_json"
