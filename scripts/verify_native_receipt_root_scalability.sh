#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="$ROOT/target/debug/superneo-bench"

CORPUS_LEAF_COUNT="${HEGEMON_NATIVE_RECEIPT_ROOT_CORPUS_LEAF_COUNT:-128}"
CORPUS_SEED_COUNT="${HEGEMON_NATIVE_RECEIPT_ROOT_CORPUS_SEED_COUNT:-2}"
LEAF_COUNT="${HEGEMON_NATIVE_RECEIPT_ROOT_LEAF_COUNT:-128}"
MINI_ROOT_SIZE="${HEGEMON_NATIVE_RECEIPT_ROOT_MINI_ROOT_SIZE:-8}"
MUTATE_LEAF_INDEX="${HEGEMON_NATIVE_RECEIPT_ROOT_MUTATE_LEAF_INDEX:-17}"
BLOCK_COUNT="${HEGEMON_NATIVE_RECEIPT_ROOT_EPOCH_BLOCK_COUNT:-1024}"
MUTATE_BLOCK_INDEX="${HEGEMON_NATIVE_RECEIPT_ROOT_MUTATE_BLOCK_INDEX:-257}"
WORKERS="${HEGEMON_NATIVE_RECEIPT_ROOT_WORKERS_LIST:-1 16 32}"

MIN_CORPUS_LEAF_COUNT=$((LEAF_COUNT + MUTATE_LEAF_INDEX + 1))
if [ "$CORPUS_LEAF_COUNT" -lt "$MIN_CORPUS_LEAF_COUNT" ]; then
  CORPUS_LEAF_COUNT="$MIN_CORPUS_LEAF_COUNT"
fi

WORKDIR="$(mktemp -d /tmp/hegemon-native-receipt-root-scalability.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

CORPUS_PATH="$WORKDIR/native-leaf-record-corpus.json"
HIERARCHY_JSON="$WORKDIR/hierarchy.json"
EPOCH_JSON="$WORKDIR/epoch.json"

cargo build -p superneo-bench

"$BENCH" \
  --emit-native-leaf-record-corpus "$CORPUS_PATH" \
  --leaf-count "$CORPUS_LEAF_COUNT" \
  --native-leaf-record-corpus-seed-count "$CORPUS_SEED_COUNT"

"$BENCH" \
  --measure-native-receipt-root-hierarchy \
  --leaf-count "$LEAF_COUNT" \
  --mini-root-size "$MINI_ROOT_SIZE" \
  --mutate-leaf-index "$MUTATE_LEAF_INDEX" \
  --native-leaf-record-corpus "$CORPUS_PATH" \
  > "$HIERARCHY_JSON"

"$BENCH" \
  --measure-native-epoch-root-hierarchy \
  --block-count "$BLOCK_COUNT" \
  --mutate-block-index "$MUTATE_BLOCK_INDEX" \
  --native-leaf-record-corpus "$CORPUS_PATH" \
  > "$EPOCH_JSON"

BUILD_JSONS=()
for worker in $WORKERS; do
  build_json="$WORKDIR/build_${worker}.json"
  "$BENCH" \
    --measure-native-receipt-root-build \
    --leaf-count "$LEAF_COUNT" \
    --mini-root-size "$MINI_ROOT_SIZE" \
    --workers "$worker" \
    --warm-repeat 1 \
    --mutate-leaf-index "$MUTATE_LEAF_INDEX" \
    --native-leaf-record-corpus "$CORPUS_PATH" \
    > "$build_json"
  BUILD_JSONS+=("$build_json")
done

python3 - <<'PY' \
  "$CORPUS_PATH" \
  "$HIERARCHY_JSON" \
  "$EPOCH_JSON" \
  "$LEAF_COUNT" \
  "$MINI_ROOT_SIZE" \
  "$BLOCK_COUNT" \
  "$WORKERS" \
  "${BUILD_JSONS[@]}"
import json
import math
from pathlib import Path
import sys

corpus_path = Path(sys.argv[1])
hierarchy_path = Path(sys.argv[2])
epoch_path = Path(sys.argv[3])
leaf_count = int(sys.argv[4])
mini_root_size = int(sys.argv[5])
block_count = int(sys.argv[6])
workers = [int(token) for token in sys.argv[7].split()]
build_paths = [Path(arg) for arg in sys.argv[8:]]

if leaf_count <= 0 or (leaf_count & (leaf_count - 1)) != 0:
    raise SystemExit("leaf count must be a positive power of two")
if mini_root_size <= 0 or (mini_root_size & (mini_root_size - 1)) != 0:
    raise SystemExit("mini-root size must be a positive power of two")
if leaf_count % mini_root_size != 0:
    raise SystemExit("leaf count must be divisible by mini-root size")
if block_count <= 0 or (block_count & (block_count - 1)) != 0:
    raise SystemExit("block count must be a positive power of two")
if len(workers) != len(build_paths):
    raise SystemExit("worker list does not match build report count")

hierarchy = json.loads(hierarchy_path.read_text(encoding="utf-8"))
epoch = json.loads(epoch_path.read_text(encoding="utf-8"))
builds = {
    worker: json.loads(path.read_text(encoding="utf-8"))
    for worker, path in zip(workers, build_paths)
}

record_source = f"corpus:{corpus_path}"
mini_roots_total = leaf_count // mini_root_size
upper_path_len = int(math.log2(mini_roots_total))
expected_mutated_fold_rebuilds = (mini_root_size - 1) + upper_path_len

assert hierarchy["record_source"] == record_source, hierarchy["record_source"]
assert hierarchy["leaf_count"] == leaf_count, hierarchy
assert hierarchy["mini_root_size"] == mini_root_size, hierarchy
assert hierarchy["mini_roots_total"] == mini_roots_total, hierarchy
assert hierarchy["mini_roots_reused"] == mini_roots_total - 1, hierarchy
assert hierarchy["mini_roots_rebuilt"] == 1, hierarchy
assert hierarchy["changed_mini_root_leaf_count"] == mini_root_size, hierarchy
assert hierarchy["block_internal_nodes_touched"] == int(math.log2(leaf_count)), hierarchy
assert hierarchy["flat_internal_nodes_touched"] == leaf_count - 1, hierarchy
assert hierarchy["baseline_root_statement_digest"] != hierarchy["mutated_root_statement_digest"], hierarchy

assert epoch["record_source"] == record_source, epoch["record_source"]
assert epoch["block_count"] == block_count, epoch
assert epoch["epoch_internal_nodes_touched"] == int(math.log2(block_count)), epoch
assert epoch["flat_epoch_internal_nodes"] == block_count - 1, epoch
assert epoch["baseline_epoch_root_statement_digest"] != epoch["mutated_epoch_root_statement_digest"], epoch

for worker, report in builds.items():
    assert report["record_source"] == record_source, report["record_source"]
    assert report["leaf_count"] == leaf_count, report
    assert report["mini_root_size"] == mini_root_size, report
    assert report["workers"] == worker, report

    cold = report["cold"]
    exact = report["exact_repeat"]
    mutated = report["mutated_repeat"]

    assert cold["mini_roots_total"] == mini_roots_total, cold
    assert cold["mini_root_cache_hits"] == 0, cold
    assert cold["mini_root_cache_misses"] == mini_roots_total, cold
    assert cold["upper_tree_cache_hits"] == 0, cold
    assert cold["upper_tree_cache_misses"] == mini_roots_total - 1, cold
    assert cold["internal_fold_nodes_rebuilt"] == leaf_count - 1, cold

    assert exact["mini_roots_total"] == mini_roots_total, exact
    assert exact["mini_root_cache_hits"] == mini_roots_total, exact
    assert exact["mini_root_cache_misses"] == 0, exact
    assert exact["upper_tree_cache_hits"] == mini_roots_total - 1, exact
    assert exact["upper_tree_cache_misses"] == 0, exact
    assert exact["internal_fold_nodes_rebuilt"] == 0, exact

    assert mutated["mini_roots_total"] == mini_roots_total, mutated
    assert mutated["mini_root_cache_hits"] == mini_roots_total - 1, mutated
    assert mutated["mini_root_cache_misses"] == 1, mutated
    assert mutated["upper_tree_cache_hits"] == (mini_roots_total - 1) - upper_path_len, mutated
    assert mutated["upper_tree_cache_misses"] == upper_path_len, mutated
    assert mutated["internal_fold_nodes_rebuilt"] == expected_mutated_fold_rebuilds, mutated

    assert exact["root_statement_digest"] == cold["root_statement_digest"], report
    assert mutated["root_statement_digest"] != cold["root_statement_digest"], report
    assert exact["total_ns"] < cold["total_ns"], report
    assert mutated["total_ns"] < cold["total_ns"], report

baseline_cold = builds[workers[0]]["cold"]["total_ns"]
for worker in workers[1:]:
    worker_cold = builds[worker]["cold"]["total_ns"]
    assert worker_cold < baseline_cold, (worker, worker_cold, baseline_cold)

summary = {
    "record_source": record_source,
    "leaf_count": leaf_count,
    "mini_root_size": mini_root_size,
    "block_count": block_count,
    "hierarchy_nodes_touched": hierarchy["block_internal_nodes_touched"],
    "flat_block_nodes": hierarchy["flat_internal_nodes_touched"],
    "epoch_nodes_touched": epoch["epoch_internal_nodes_touched"],
    "flat_epoch_nodes": epoch["flat_epoch_internal_nodes"],
    "build_cold_ms": {
        str(worker): round(builds[worker]["cold"]["total_ns"] / 1_000_000, 3)
        for worker in workers
    },
    "build_mutated_ms": {
        str(worker): round(builds[worker]["mutated_repeat"]["total_ns"] / 1_000_000, 3)
        for worker in workers
    },
}
print(json.dumps(summary, indent=2))
PY
