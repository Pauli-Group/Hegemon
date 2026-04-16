#!/bin/bash
#
# Hegemon Substrate Integration Test Runner
# 
# Usage:
#   ./scripts/test-substrate.sh [command]
#
# Commands:
#   build       - Build the node binary
#   unit        - Run all unit tests
#   substrate   - Run Substrate-specific tests (9 tests)
#   pq          - Run PQ network tests (19 tests)
#   security    - Run security pipeline tests
#   single-node - Run single node mining test (semi-automated)
#   restart-recovery - Run authoring/follower restart-recovery harness (automated)
#   two-node    - Start two-node test environment (manual)
#   three-node  - Start three-node test environment (manual)
#   partition   - Guide for partition recovery test (manual)
#   all         - Run all automated tests
#   clean       - Clean up test artifacts
#   help        - Show this help message
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Configuration
RPC_PORT_A=9944
RPC_PORT_B=9945
RPC_PORT_C=9946
P2P_PORT_A=30333
P2P_PORT_B=30334
P2P_PORT_C=30335
TIMEOUT_BLOCK_PRODUCTION=60
TIMEOUT_SYNC=30

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=0
    
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Install Rust."
        missing=1
    fi
    
    if ! command -v curl &> /dev/null; then
        log_error "curl not found. Install curl."
        missing=1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq not found. Install jq."
        missing=1
    fi

    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found. Install Python 3."
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Build the node
cmd_build() {
    log_section "Building Hegemon Node"
    
    log_info "Building with Substrate feature..."
    cargo build --release -p hegemon-node --features substrate
    
    if [ -f "target/release/hegemon-node" ]; then
        log_success "Build complete: target/release/hegemon-node"
    elif [ -f "target/release/substrate_node" ]; then
        log_success "Build complete: target/release/substrate_node"
    else
        log_error "Build failed - binary not found"
        exit 1
    fi
}

# Run unit tests
cmd_unit() {
    log_section "Running Unit Tests"
    
    log_info "Running workspace tests (excluding security-tests)..."
    if cargo test --workspace --exclude security-tests; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        exit 1
    fi
}

# Run Substrate-specific tests
cmd_substrate() {
    log_section "Running Substrate Integration Tests"
    
    log_info "Running multi_node_substrate tests..."
    if cargo test -p security-tests --test multi_node_substrate --features substrate -- --nocapture; then
        log_success "Substrate tests passed (9 tests)"
    else
        log_error "Substrate tests failed"
        exit 1
    fi
}

# Run PQ network tests
cmd_pq() {
    log_section "Running PQ Network Tests"
    
    log_info "Running network crate tests..."
    if cargo test -p network -- --nocapture; then
        log_success "PQ network tests passed"
    else
        log_error "PQ network tests failed"
        exit 1
    fi
}

# Run security pipeline tests
cmd_security() {
    log_section "Running Security Pipeline Tests"
    
    export PROPTEST_MAX_CASES=64
    log_info "Running security_pipeline tests (PROPTEST_MAX_CASES=$PROPTEST_MAX_CASES)..."
    
    if cargo test -p security-tests --test security_pipeline -- --nocapture; then
        log_success "Security pipeline tests passed"
    else
        log_error "Security pipeline tests failed"
        exit 1
    fi
}

# Helper: Check if port is in use
port_in_use() {
    lsof -i :"$1" &>/dev/null
}

# Helper: Wait for RPC to be ready
wait_for_rpc() {
    local port=$1
    local timeout=$2
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if curl -s -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
            "http://127.0.0.1:$port" &>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Helper: Get block number from RPC
get_block_number() {
    local port=$1
    local number
    number=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result.number // "null"')
    if [ "$number" = "null" ]; then
        echo "null"
    else
        printf '%d\n' "$number" 2>/dev/null || echo "null"
    fi
}

# Helper: Get block hash from RPC
get_block_hash() {
    local port=$1
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getBlockHash","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result // "null"'
}

# Helper: Get peer count from RPC
get_peer_count() {
    local port=$1
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result | length // 0'
}

# Helper: Wait for a node to mine or import at least one new block
wait_for_block_advance() {
    local port=$1
    local start_block=$2
    local timeout=$3
    local label=$4
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local current_block
        current_block=$(get_block_number "$port")
        if [ "$current_block" != "null" ] && [ "$current_block" -gt "$start_block" ]; then
            log_success "$label advanced from $start_block to $current_block"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "$label did not advance past $start_block within ${timeout}s"
    return 1
}

# Helper: Wait for a node to report the requested peer count
wait_for_min_peers() {
    local port=$1
    local min_peers=$2
    local timeout=$3
    local label=$4
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local peers
        peers=$(get_peer_count "$port")
        if [ "$peers" -ge "$min_peers" ]; then
            log_success "$label reached $peers peer(s)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "$label did not reach $min_peers peer(s) within ${timeout}s"
    return 1
}

# Helper: Wait for two nodes to converge to the same best hash
wait_for_equal_tip() {
    local port_a=$1
    local port_b=$2
    local timeout=$3
    local label_a=$4
    local label_b=$5
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local hash_a
        local hash_b
        hash_a=$(get_block_hash "$port_a")
        hash_b=$(get_block_hash "$port_b")
        if [ "$hash_a" != "null" ] && [ "$hash_a" = "$hash_b" ]; then
            local block_a
            local block_b
            block_a=$(get_block_number "$port_a")
            block_b=$(get_block_number "$port_b")
            log_success "$label_a and $label_b converged at block $block_a/$block_b with hash $hash_a"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "$label_a and $label_b did not converge within ${timeout}s"
    return 1
}

# Helper: Wait for a node to reach at least the requested height
wait_for_min_height() {
    local port=$1
    local target=$2
    local timeout=$3
    local label=$4
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local current
        current=$(get_block_number "$port")
        if [ "$current" != "null" ] && [ "$current" -ge "$target" ]; then
            log_success "$label reached height $current (target: $target)"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "$label did not reach height $target within ${timeout}s"
    return 1
}

# Helper: Control mining through the unsafe RPC surface
set_mining_state() {
    local port=$1
    local action=$2
    local threads=${3:-1}

    local payload
    if [ "$action" = "start" ]; then
        payload=$(jq -n --argjson threads "$threads" \
            '{jsonrpc:"2.0", method:"hegemon_startMining", params:[{threads:$threads}], id:1}')
    else
        payload='{"jsonrpc":"2.0","method":"hegemon_stopMining","params":[{}],"id":1}'
    fi

    local response
    response=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "$payload" \
        "http://127.0.0.1:$port")

    if [ "$(echo "$response" | jq -r '.result.success // false')" != "true" ]; then
        log_error "Failed to ${action} mining on port $port"
        echo "$response"
        return 1
    fi

    return 0
}

# Helper: deterministically solve the current compact job and submit a full-target block
mine_compact_block() {
    local port=$1
    local worker_name=$2
    local label=$3
    local before_block
    before_block=$(get_block_number "$port")

    local job_json=""
    local available="false"
    local elapsed=0
    while [ $elapsed -lt 60 ]; do
        job_json=$(curl -s -X POST -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"hegemon_compactJob","params":[{}],"id":1}' \
            "http://127.0.0.1:$port")
        available=$(echo "$job_json" | jq -r '.result.available // false')
        if [ "$available" = "true" ]; then
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    if [ "$available" != "true" ]; then
        log_error "$label has no compact job available"
        return 1
    fi

    local job_id
    local pre_hash
    local network_bits
    job_id=$(echo "$job_json" | jq -r '.result.job_id')
    pre_hash=$(echo "$job_json" | jq -r '.result.pre_hash')
    network_bits=$(echo "$job_json" | jq -r '.result.network_bits')

    local nonce
    nonce=$(python3 - "$pre_hash" "$network_bits" <<'PY'
import hashlib
import sys

pre_hash = bytes.fromhex(sys.argv[1].removeprefix("0x"))
bits = int(sys.argv[2])

def compact_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x00FFFFFF
    if mantissa == 0:
        raise SystemExit("compact target has zero mantissa")
    if exponent > 32:
        return (1 << 256) - 1
    if exponent > 3:
        return mantissa << (8 * (exponent - 3))
    return mantissa >> (8 * (3 - exponent))

target = compact_to_target(bits)
counter = 0
while True:
    nonce = counter.to_bytes(8, "little") + b"\x00" * 24
    work = hashlib.sha256(hashlib.sha256(pre_hash + nonce).digest()).digest()
    if int.from_bytes(work, "big") <= target:
        print("0x" + nonce.hex())
        break
    counter += 1
PY
)

    local submit_payload
    submit_payload=$(jq -n \
        --arg worker_name "$worker_name" \
        --arg job_id "$job_id" \
        --arg nonce "$nonce" \
        '{jsonrpc:"2.0", method:"hegemon_submitCompactSolution", params:[{worker_name:$worker_name, job_id:$job_id, nonce:$nonce}], id:1}')
    local submit_json
    submit_json=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "$submit_payload" \
        "http://127.0.0.1:$port")

    local accepted
    local block_candidate
    accepted=$(echo "$submit_json" | jq -r '.result.accepted // false')
    block_candidate=$(echo "$submit_json" | jq -r '.result.block_candidate // false')
    if [ "$accepted" != "true" ] || [ "$block_candidate" != "true" ]; then
        log_error "$label full-target compact solution was not accepted"
        echo "$submit_json"
        return 1
    fi

    wait_for_block_advance "$port" "$before_block" 30 "$label after compact solution"
}

# Clean up any running nodes
cleanup_nodes() {
    log_info "Cleaning up any running nodes..."
    pkill -f "hegemon-node" 2>/dev/null || true
    pkill -f "substrate_node" 2>/dev/null || true
    rm -rf /tmp/hegemon-node-* /tmp/node-* 2>/dev/null || true
    sleep 2
}

# Single node mining test (semi-automated)
cmd_single_node() {
    log_section "Single Node Mining Test"
    
    check_prerequisites
    
    # Check ports
    if port_in_use $RPC_PORT_A; then
        log_error "Port $RPC_PORT_A is in use. Run './scripts/test-substrate.sh clean' first."
        exit 1
    fi
    
    log_info "Starting single node with mining enabled..."
    
    # Start node in background
    HEGEMON_MINE=1 HEGEMON_MINE_THREADS=2 \
    cargo run --release -p hegemon-node --features substrate -- \
        --dev \
        --tmp \
        --base-path /tmp/hegemon-node-single \
        --rpc-port $RPC_PORT_A \
        --port $P2P_PORT_A \
        --name "SingleNodeTest" \
        --require-pq &
    
    NODE_PID=$!
    log_info "Node started with PID: $NODE_PID"
    
    # Wait for RPC
    log_info "Waiting for RPC to be ready (timeout: 30s)..."
    if ! wait_for_rpc $RPC_PORT_A 30; then
        log_error "RPC not ready after 30 seconds"
        kill $NODE_PID 2>/dev/null || true
        exit 1
    fi
    log_success "RPC is ready"
    
    # Wait for block production
    log_info "Waiting for block production (timeout: ${TIMEOUT_BLOCK_PRODUCTION}s)..."
    local elapsed=0
    local blocks_mined=false
    
    while [ $elapsed -lt $TIMEOUT_BLOCK_PRODUCTION ]; do
        BLOCK_NUM=$(get_block_number $RPC_PORT_A)
        if [ "$BLOCK_NUM" != "null" ] && [ "$BLOCK_NUM" != "0x0" ]; then
            blocks_mined=true
            break
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        log_info "  Elapsed: ${elapsed}s, Block: $BLOCK_NUM"
    done
    
    # Get final state
    FINAL_BLOCK=$(get_block_number $RPC_PORT_A)
    FINAL_HASH=$(get_block_hash $RPC_PORT_A)
    
    # Cleanup
    log_info "Stopping node..."
    kill $NODE_PID 2>/dev/null || true
    wait $NODE_PID 2>/dev/null || true
    rm -rf /tmp/hegemon-node-single
    
    # Report results
    echo ""
    log_section "Single Node Test Results"
    echo "  Block Number: $FINAL_BLOCK"
    echo "  Block Hash:   $FINAL_HASH"
    echo ""
    
    if [ "$blocks_mined" = true ]; then
        log_success "SINGLE NODE MINING TEST PASSED"
        return 0
    else
        log_error "SINGLE NODE MINING TEST FAILED - No blocks mined"
        return 1
    fi
}

# Automated authoring/follower restart-recovery harness
cmd_restart_recovery() {
    log_section "Authoring/Follower Restart-Recovery Harness"

    check_prerequisites

    local node_bin="target/release/hegemon-node"
    if [ ! -x "$node_bin" ]; then
        log_info "Release binaries missing; building hegemon-node package..."
        cargo build --release -p hegemon-node --features substrate
    fi

    if [ ! -x "$node_bin" ]; then
        log_error "Required binaries not found after build"
        exit 1
    fi

    local author_rpc_port=19944
    local follower_rpc_port=19945
    local author_p2p_port=39333
    local follower_p2p_port=39334
    local tmp_root
    tmp_root=$(mktemp -d /tmp/hegemon-restart-harness.XXXXXX)
    local author_log="$tmp_root/author.log"
    local follower_log="$tmp_root/follower.log"
    local harness_spec="$tmp_root/restart-harness-chainspec.json"
    local author_base="$tmp_root/author-base"
    local follower_base="$tmp_root/follower-base"
    local author_pid=""
    local follower_pid=""
    local difficulty_bits_key="0x7d15dd66fbf0cbda1d3a651b5e606df2fbc97b050ba98067c6d1bdd855ff03b8"
    local difficulty_value_key="0x7d15dd66fbf0cbda1d3a651b5e606df27d15dd66fbf0cbda1d3a651b5e606df2"
    local payout_address=""

    cleanup_restart_recovery() {
        for pid in "$follower_pid" "$author_pid"; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
            fi
        done
        rm -rf "$tmp_root"
    }

    trap cleanup_restart_recovery EXIT

    if [ -f "config/testnet-config" ]; then
        # shellcheck disable=SC1091
        source "config/testnet-config"
        payout_address="${HEGEMON_BOOT_ADDRESS:-}"
    fi

    jq --arg bits_key "$difficulty_bits_key" \
        --arg value_key "$difficulty_value_key" \
        '.name = "Hegemon Restart Harness"
        | .id = "hegemon-restart-harness"
        | .chainType = "Development"
        | .bootNodes = []
        | .genesis.raw.top[$bits_key] = "0xffff0021"
        | .genesis.raw.top[$value_key] = "0x0100000000000000000000000000000000000000000000000000000000000000"' \
        config/dev-chainspec.json > "$harness_spec"

    for port in "$author_rpc_port" "$follower_rpc_port" "$author_p2p_port" "$follower_p2p_port"; do
        if port_in_use "$port"; then
            log_error "Harness port $port is already in use"
            exit 1
        fi
    done

    log_info "Starting authoring node on 127.0.0.1:$author_rpc_port / $author_p2p_port"
    HEGEMON_MINE=1 \
    HEGEMON_MINE_THREADS=1 \
    HEGEMON_MINER_ADDRESS="$payout_address" \
    HEGEMON_PROVER_REWARD_ADDRESS="$payout_address" \
    HEGEMON_PROVER_WORKERS=0 \
    HEGEMON_BATCH_VERIFY_PREWARM_TXS=0 \
    HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
    "$node_bin" \
        --dev \
        --chain "$harness_spec" \
        --base-path "$author_base" \
        --rpc-port "$author_rpc_port" \
        --port "$author_p2p_port" \
        --rpc-methods unsafe \
        --name "RestartHarnessAuthor" \
        >"$author_log" 2>&1 &
    author_pid=$!

    if ! wait_for_rpc "$author_rpc_port" 60; then
        log_error "Authoring node RPC failed to start"
        exit 1
    fi
    if ! set_mining_state "$author_rpc_port" start 1; then
        exit 1
    fi
    if ! wait_for_block_advance "$author_rpc_port" 0 60 "Authoring node"; then
        exit 1
    fi
    if ! set_mining_state "$author_rpc_port" stop; then
        exit 1
    fi

    log_info "Starting follower node on 127.0.0.1:$follower_rpc_port / $follower_p2p_port"
    HEGEMON_MINE=0 \
    HEGEMON_MINER_ADDRESS="$payout_address" \
    HEGEMON_PROVER_REWARD_ADDRESS="$payout_address" \
    HEGEMON_PROVER_WORKERS=0 \
    HEGEMON_BATCH_VERIFY_PREWARM_TXS=0 \
    HEGEMON_SEEDS="127.0.0.1:$author_p2p_port" \
    HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
    "$node_bin" \
        --dev \
        --chain "$harness_spec" \
        --base-path "$follower_base" \
        --rpc-port "$follower_rpc_port" \
        --port "$follower_p2p_port" \
        --rpc-methods safe \
        --name "RestartHarnessFollower" \
        >"$follower_log" 2>&1 &
    follower_pid=$!

    if ! wait_for_rpc "$follower_rpc_port" 60; then
        log_error "Follower node RPC failed to start"
        exit 1
    fi
    if ! wait_for_equal_tip "$author_rpc_port" "$follower_rpc_port" 120 "Authoring node" "Follower node"; then
        exit 1
    fi

    local before_shutdown_block
    before_shutdown_block=$(get_block_number "$author_rpc_port")
    log_info "Stopping follower node at authoring height $before_shutdown_block"
    kill "$follower_pid" 2>/dev/null || true
    wait "$follower_pid" 2>/dev/null || true
    follower_pid=""

    if ! set_mining_state "$author_rpc_port" start 1; then
        exit 1
    fi
    if ! wait_for_block_advance "$author_rpc_port" "$before_shutdown_block" 60 "Authoring node while follower is down"; then
        exit 1
    fi
    if ! set_mining_state "$author_rpc_port" stop; then
        exit 1
    fi

    log_info "Restarting follower node"
    HEGEMON_MINE=0 \
    HEGEMON_MINER_ADDRESS="$payout_address" \
    HEGEMON_PROVER_REWARD_ADDRESS="$payout_address" \
    HEGEMON_PROVER_WORKERS=0 \
    HEGEMON_BATCH_VERIFY_PREWARM_TXS=0 \
    HEGEMON_SEEDS="127.0.0.1:$author_p2p_port" \
    HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
    "$node_bin" \
        --dev \
        --chain "$harness_spec" \
        --base-path "$follower_base" \
        --rpc-port "$follower_rpc_port" \
        --port "$follower_p2p_port" \
        --rpc-methods safe \
        --name "RestartHarnessFollower" \
        >>"$follower_log" 2>&1 &
    follower_pid=$!

    if ! wait_for_rpc "$follower_rpc_port" 60; then
        log_error "Restarted follower node RPC failed to start"
        exit 1
    fi

    if ! wait_for_equal_tip "$author_rpc_port" "$follower_rpc_port" 120 "Authoring node" "Restarted follower node"; then
        exit 1
    fi

    local resumed_author_block
    resumed_author_block=$(get_block_number "$author_rpc_port")
    if [ "$resumed_author_block" = "null" ]; then
        log_error "Authoring node did not report a height before resumed mining check"
        exit 1
    fi
    if ! set_mining_state "$author_rpc_port" start 1; then
        exit 1
    fi
    if ! wait_for_block_advance "$author_rpc_port" "$resumed_author_block" 60 "Authoring node after follower restart"; then
        exit 1
    fi
    if ! set_mining_state "$author_rpc_port" stop; then
        exit 1
    fi
    if ! wait_for_equal_tip "$author_rpc_port" "$follower_rpc_port" 120 "Authoring node" "Follower node after resumed mining"; then
        exit 1
    fi

    cleanup_restart_recovery
    trap - EXIT
    log_success "RESTART-RECOVERY HARNESS PASSED"
}

# Two node sync test (manual setup helper)
cmd_two_node() {
    log_section "Two Node Sync Test - Manual Setup Required"
    
    check_prerequisites
    cleanup_nodes
    
    echo ""
    echo -e "${YELLOW}This test requires 3 terminal windows.${NC}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 1 - Node A (Miner):${NC}"
    echo ""
    echo "  cd $PROJECT_ROOT"
    echo ""
    echo "  HEGEMON_MINE=1 HEGEMON_MINE_THREADS=2 \\"
    echo "  cargo run --release -p hegemon-node --features substrate -- \\"
    echo "    --dev --tmp --base-path /tmp/hegemon-node-a \\"
    echo "    --rpc-port $RPC_PORT_A --port $P2P_PORT_A \\"
    echo "    --name \"NodeA\" --require-pq --pq-verbose"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 2 - Node B (Syncing):${NC}"
    echo ""
    echo "  cd $PROJECT_ROOT"
    echo ""
    echo "  cargo run --release -p hegemon-node --features substrate -- \\"
    echo "    --dev --tmp --base-path /tmp/hegemon-node-b \\"
    echo "    --rpc-port $RPC_PORT_B --port $P2P_PORT_B \\"
    echo "    --name \"NodeB\" --require-pq \\"
    echo "    --bootnodes /ip4/127.0.0.1/tcp/$P2P_PORT_A"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 3 - Verification:${NC}"
    echo ""
    echo "  # Run this after both nodes are running (wait ~30s):"
    echo "  ./scripts/test-substrate.sh verify-two-node"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${GREEN}Success Criteria:${NC}"
    echo "  - Both nodes show 'PQ peer connected' in logs"
    echo "  - Both nodes have same block hash"
    echo "  - Each node reports 1 peer"
    echo ""
}

# Verify two-node setup
cmd_verify_two_node() {
    log_section "Verifying Two Node Setup"
    
    echo ""
    echo "=== Node A (Port $RPC_PORT_A) ==="
    local block_a=$(get_block_number $RPC_PORT_A)
    local hash_a=$(get_block_hash $RPC_PORT_A)
    local peers_a=$(get_peer_count $RPC_PORT_A)
    echo "  Block: $block_a"
    echo "  Hash:  $hash_a"
    echo "  Peers: $peers_a"
    
    echo ""
    echo "=== Node B (Port $RPC_PORT_B) ==="
    local block_b=$(get_block_number $RPC_PORT_B)
    local hash_b=$(get_block_hash $RPC_PORT_B)
    local peers_b=$(get_peer_count $RPC_PORT_B)
    echo "  Block: $block_b"
    echo "  Hash:  $hash_b"
    echo "  Peers: $peers_b"
    
    echo ""
    
    # Check results
    local passed=true
    
    if [ "$peers_a" -lt 1 ] || [ "$peers_b" -lt 1 ]; then
        log_error "Nodes not connected (peers: A=$peers_a, B=$peers_b)"
        passed=false
    fi
    
    if [ "$hash_a" != "$hash_b" ] && [ "$hash_a" != "null" ] && [ "$hash_b" != "null" ]; then
        log_warn "Block hashes differ - nodes may still be syncing"
        log_info "  Node A: $hash_a"
        log_info "  Node B: $hash_b"
    elif [ "$hash_a" = "$hash_b" ] && [ "$hash_a" != "null" ]; then
        log_success "Block hashes match!"
    fi
    
    if [ "$passed" = true ]; then
        log_success "TWO NODE VERIFICATION PASSED"
    else
        log_error "TWO NODE VERIFICATION FAILED"
    fi
}

# Three node consensus test (manual setup helper)
cmd_three_node() {
    log_section "Three Node Consensus Test - Manual Setup Required"
    
    check_prerequisites
    cleanup_nodes
    
    echo ""
    echo -e "${YELLOW}This test requires 4 terminal windows.${NC}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 1 - Node A:${NC}"
    echo ""
    echo "  HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \\"
    echo "  cargo run --release -p hegemon-node --features substrate -- \\"
    echo "    --dev --tmp --base-path /tmp/node-a \\"
    echo "    --rpc-port $RPC_PORT_A --port $P2P_PORT_A --name \"NodeA\" --require-pq"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 2 - Node B:${NC}"
    echo ""
    echo "  HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \\"
    echo "  cargo run --release -p hegemon-node --features substrate -- \\"
    echo "    --dev --tmp --base-path /tmp/node-b \\"
    echo "    --rpc-port $RPC_PORT_B --port $P2P_PORT_B --name \"NodeB\" --require-pq \\"
    echo "    --bootnodes /ip4/127.0.0.1/tcp/$P2P_PORT_A"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 3 - Node C:${NC}"
    echo ""
    echo "  HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \\"
    echo "  cargo run --release -p hegemon-node --features substrate -- \\"
    echo "    --dev --tmp --base-path /tmp/node-c \\"
    echo "    --rpc-port $RPC_PORT_C --port $P2P_PORT_C --name \"NodeC\" --require-pq \\"
    echo "    --bootnodes /ip4/127.0.0.1/tcp/$P2P_PORT_A \\"
    echo "    --bootnodes /ip4/127.0.0.1/tcp/$P2P_PORT_B"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}TERMINAL 4 - Monitor:${NC}"
    echo ""
    echo "  # Run this after all nodes are running:"
    echo "  ./scripts/test-substrate.sh monitor-three-node"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${GREEN}Success Criteria:${NC}"
    echo "  - All three nodes eventually show same block hash"
    echo "  - Each node shows 2 peers"
    echo "  - Block height increases over time"
    echo ""
}

# Monitor three-node setup
cmd_monitor_three_node() {
    log_section "Monitoring Three Node Consensus"
    
    echo "Press Ctrl+C to stop monitoring"
    echo ""
    
    while true; do
        clear
        echo "═══════════════════════════════════════════════════════════════"
        echo "  THREE NODE CONSENSUS STATUS - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        
        for port in $RPC_PORT_A $RPC_PORT_B $RPC_PORT_C; do
            local name=""
            case $port in
                $RPC_PORT_A) name="A" ;;
                $RPC_PORT_B) name="B" ;;
                $RPC_PORT_C) name="C" ;;
            esac
            
            local block=$(get_block_number $port)
            local hash=$(get_block_hash $port)
            local peers=$(get_peer_count $port)
            
            if [ "$block" = "null" ]; then
                echo -e "  Node $name (port $port): ${RED}OFFLINE${NC}"
            else
                local short_hash="${hash:0:18}"
                echo "  Node $name (port $port): Block $block | Hash: ${short_hash}... | Peers: $peers"
            fi
        done
        
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        
        sleep 5
    done
}

# Partition recovery test guide
cmd_partition() {
    log_section "Network Partition Recovery Test - Manual Guide"
    
    echo ""
    echo -e "${YELLOW}This test requires the three-node setup from 'three-node' command.${NC}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 1: Start three nodes${NC}"
    echo ""
    echo "  ./scripts/test-substrate.sh three-node"
    echo "  # Follow the instructions to start all three nodes"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 2: Wait for baseline sync (2 minutes)${NC}"
    echo ""
    echo "  sleep 120"
    echo "  ./scripts/test-substrate.sh verify-three-node"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 3: Create partition (stop Node B)${NC}"
    echo ""
    echo "  # In Terminal 2: Press Ctrl+C to stop Node B"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 4: Let chains diverge (2 minutes)${NC}"
    echo ""
    echo "  sleep 120"
    echo "  # Observe Node A and C continuing to mine"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 5: Heal partition (restart Node B)${NC}"
    echo ""
    echo "  # In Terminal 2, restart with the same command from Step 1"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BLUE}STEP 6: Verify recovery${NC}"
    echo ""
    echo "  sleep 60"
    echo "  ./scripts/test-substrate.sh verify-three-node"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${GREEN}Success Criteria:${NC}"
    echo "  - After partition heals, all nodes converge to same block hash"
    echo "  - The converged chain is the longest chain"
    echo "  - Logs may show 'Reorganization' or 'Best block changed'"
    echo ""
}

# Verify three-node setup
cmd_verify_three_node() {
    log_section "Verifying Three Node Consensus"
    
    local hashes=""
    local all_same=true
    local all_online=true
    
    echo ""
    for port in $RPC_PORT_A $RPC_PORT_B $RPC_PORT_C; do
        local name=""
        case $port in
            $RPC_PORT_A) name="A" ;;
            $RPC_PORT_B) name="B" ;;
            $RPC_PORT_C) name="C" ;;
        esac
        
        local block=$(get_block_number $port)
        local hash=$(get_block_hash $port)
        local peers=$(get_peer_count $port)
        
        echo "=== Node $name (Port $port) ==="
        echo "  Block: $block"
        echo "  Hash:  $hash"
        echo "  Peers: $peers"
        echo ""
        
        if [ "$block" = "null" ]; then
            all_online=false
        else
            if [ -z "$hashes" ]; then
                hashes="$hash"
            elif [ "$hashes" != "$hash" ]; then
                all_same=false
            fi
        fi
    done
    
    if [ "$all_online" = false ]; then
        log_warn "Not all nodes are online"
    fi
    
    if [ "$all_same" = true ] && [ "$all_online" = true ]; then
        log_success "THREE NODE CONSENSUS VERIFIED - All nodes on same chain"
    elif [ "$all_same" = false ]; then
        log_warn "Nodes have different block hashes - may still be syncing or forked"
    fi
}

# Run all automated tests
cmd_all() {
    log_section "Running All Automated Tests"
    
    check_prerequisites
    
    local start_time=$(date +%s)
    local failed=0
    
    # Build first
    if ! cmd_build; then
        log_error "Build failed, aborting tests"
        exit 1
    fi
    
    # Run each test suite
    log_info "Running Substrate tests..."
    if cmd_substrate; then
        log_success "Substrate tests: PASSED"
    else
        log_error "Substrate tests: FAILED"
        failed=$((failed + 1))
    fi
    
    log_info "Running PQ network tests..."
    if cmd_pq; then
        log_success "PQ network tests: PASSED"
    else
        log_error "PQ network tests: FAILED"
        failed=$((failed + 1))
    fi
    
    log_info "Running security pipeline tests..."
    if cmd_security; then
        log_success "Security pipeline tests: PASSED"
    else
        log_error "Security pipeline tests: FAILED"
        failed=$((failed + 1))
    fi
    
    log_info "Running single node test..."
    if cmd_single_node; then
        log_success "Single node test: PASSED"
    else
        log_error "Single node test: FAILED"
        failed=$((failed + 1))
    fi

    log_info "Running restart-recovery harness..."
    if cmd_restart_recovery; then
        log_success "Restart-recovery harness: PASSED"
    else
        log_error "Restart-recovery harness: FAILED"
        failed=$((failed + 1))
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Summary
    log_section "Test Summary"
    echo "  Duration: ${duration}s"
    echo "  Failed:   $failed"
    echo ""
    
    if [ $failed -eq 0 ]; then
        log_success "ALL AUTOMATED TESTS PASSED"
        echo ""
        echo -e "${YELLOW}Manual tests still required:${NC}"
        echo "  - Two node sync:        ./scripts/test-substrate.sh two-node"
        echo "  - Three node consensus: ./scripts/test-substrate.sh three-node"
        echo "  - Partition recovery:   ./scripts/test-substrate.sh partition"
        return 0
    else
        log_error "$failed TEST SUITE(S) FAILED"
        return 1
    fi
}

# Clean up test artifacts
cmd_clean() {
    log_section "Cleaning Up"
    
    log_info "Killing any running nodes..."
    pkill -f "hegemon-node" 2>/dev/null || true
    pkill -f "substrate_node" 2>/dev/null || true
    
    log_info "Removing test directories..."
    rm -rf /tmp/hegemon-node-* /tmp/node-* 2>/dev/null || true
    
    log_info "Checking ports..."
    for port in $RPC_PORT_A $RPC_PORT_B $RPC_PORT_C $P2P_PORT_A $P2P_PORT_B $P2P_PORT_C; do
        if port_in_use $port; then
            log_warn "Port $port still in use"
        fi
    done
    
    log_success "Cleanup complete"
}

# Show help
cmd_help() {
    echo ""
    echo "Hegemon Substrate Integration Test Runner"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build              Build the node binary"
    echo "  unit               Run all unit tests"
    echo "  substrate          Run Substrate-specific tests (9 tests)"
    echo "  pq                 Run PQ network tests (19 tests)"
    echo "  security           Run security pipeline tests"
    echo "  single-node        Run single node mining test (semi-automated)"
    echo "  restart-recovery   Run authoring/follower restart-recovery harness"
    echo "  two-node           Setup instructions for two-node test (manual)"
    echo "  three-node         Setup instructions for three-node test (manual)"
    echo "  partition          Guide for partition recovery test (manual)"
    echo "  all                Run all automated tests"
    echo "  clean              Clean up test artifacts"
    echo ""
    echo "Verification helpers:"
    echo "  verify-two-node    Verify two-node setup is working"
    echo "  verify-three-node  Verify three-node consensus"
    echo "  monitor-three-node Live monitor for three-node setup"
    echo ""
    echo "Examples:"
    echo "  $0 all             # Run all automated tests"
    echo "  $0 single-node     # Run single node mining test"
    echo "  $0 two-node        # Get instructions for two-node test"
    echo ""
}

# Main entry point
main() {
    case "${1:-help}" in
        build)
            cmd_build
            ;;
        unit)
            cmd_unit
            ;;
        substrate)
            cmd_substrate
            ;;
        pq)
            cmd_pq
            ;;
        security)
            cmd_security
            ;;
        single-node)
            cmd_single_node
            ;;
        restart-recovery)
            cmd_restart_recovery
            ;;
        two-node)
            cmd_two_node
            ;;
        three-node)
            cmd_three_node
            ;;
        partition)
            cmd_partition
            ;;
        verify-two-node)
            cmd_verify_two_node
            ;;
        verify-three-node)
            cmd_verify_three_node
            ;;
        monitor-three-node)
            cmd_monitor_three_node
            ;;
        all)
            cmd_all
            ;;
        clean)
            cmd_clean
            ;;
        help|--help|-h)
            cmd_help
            ;;
        *)
            log_error "Unknown command: $1"
            cmd_help
            exit 1
            ;;
    esac
}

main "$@"
