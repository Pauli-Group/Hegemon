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
    
    log_info "Running pq_network_integration tests..."
    if cargo test -p security-tests --test pq_network_integration -- --nocapture; then
        log_success "PQ network tests passed (19 tests)"
    else
        log_error "PQ network tests failed"
        exit 1
    fi
    
    log_info "Running p2p_pq tests..."
    if cargo test -p security-tests --test p2p_pq -- --nocapture; then
        log_success "P2P PQ tests passed"
    else
        log_error "P2P PQ tests failed"
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
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result.number // "null"'
}

# Helper: Get block hash from RPC
get_block_hash() {
    local port=$1
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result.hash // "null"'
}

# Helper: Get peer count from RPC
get_peer_count() {
    local port=$1
    curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
        "http://127.0.0.1:$port" 2>/dev/null | jq -r '.result | length // 0'
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
