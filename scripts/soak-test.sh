#!/bin/bash
# Hegemon Testnet Soak Test
#
# This script performs a long-duration soak test on the testnet to verify:
# - Continuous block production
# - Network stability
# - Memory stability (no leaks)
# - Fork resolution
#
# Usage:
#   ./scripts/soak-test.sh [DURATION_HOURS]
#
# Example:
#   ./scripts/soak-test.sh 168  # 7-day soak test
#
# Prerequisites:
#   - jq installed
#   - curl installed
#   - Testnet running (docker-compose.testnet.yml)

set -euo pipefail

# Configuration
DURATION_HOURS=${1:-168}  # Default 7 days
RPC_ENDPOINT=${RPC_ENDPOINT:-"http://localhost:9944"}
CHECK_INTERVAL=${CHECK_INTERVAL:-60}  # seconds between checks
STALL_THRESHOLD=${STALL_THRESHOLD:-120}  # seconds without new block = stall
MEMORY_THRESHOLD_MB=${MEMORY_THRESHOLD_MB:-4096}  # Alert if memory exceeds this

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="soak-test-$(date +%Y%m%d-%H%M%S).log"

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "${GREEN}$*${NC}"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_metric() { log "METRIC" "${BLUE}$*${NC}"; }

# RPC call helper
rpc_call() {
    local method=$1
    local params=${2:-"[]"}
    curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        "$RPC_ENDPOINT" 2>/dev/null
}

# Get current block number
get_block_number() {
    local result=$(rpc_call "chain_getHeader")
    echo "$result" | jq -r '.result.number // "0x0"' | xargs printf "%d" 2>/dev/null || echo "0"
}

# Get peer count
get_peer_count() {
    local result=$(rpc_call "system_peers")
    echo "$result" | jq '.result | length' 2>/dev/null || echo "0"
}

# Get sync state
get_sync_state() {
    local result=$(rpc_call "system_health")
    echo "$result" | jq -r '.result.isSyncing' 2>/dev/null || echo "true"
}

# Get best block hash
get_best_hash() {
    local result=$(rpc_call "chain_getHeader")
    echo "$result" | jq -r '.result.parentHash // ""' 2>/dev/null
}

# Get memory usage from docker
get_memory_mb() {
    local container=${1:-"hegemon-boot1"}
    docker stats --no-stream --format "{{.MemUsage}}" "$container" 2>/dev/null | \
        awk -F/ '{gsub(/[^0-9.]/,"",$1); print int($1)}' || echo "0"
}

# Check for forks by comparing block hashes across nodes
check_for_forks() {
    local boot1_hash=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://localhost:9944" | jq -r '.result.hash // ""')
    
    local boot2_hash=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://localhost:9945" | jq -r '.result.hash // ""')
    
    local boot3_hash=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
        "http://localhost:9946" | jq -r '.result.hash // ""')
    
    if [[ "$boot1_hash" != "$boot2_hash" ]] || [[ "$boot2_hash" != "$boot3_hash" ]]; then
        echo "diverged"
    else
        echo "synced"
    fi
}

# Main test loop
main() {
    log_info "Starting Hegemon Testnet Soak Test"
    log_info "Duration: ${DURATION_HOURS} hours"
    log_info "RPC Endpoint: ${RPC_ENDPOINT}"
    log_info "Log file: ${LOG_FILE}"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION_HOURS * 3600))
    
    local last_block=0
    local last_block_time=$(date +%s)
    local stall_count=0
    local fork_count=0
    local max_memory=0
    local total_checks=0
    
    # Initial state
    local initial_block=$(get_block_number)
    log_info "Initial block height: $initial_block"
    
    while [ $(date +%s) -lt $end_time ]; do
        total_checks=$((total_checks + 1))
        local current_time=$(date +%s)
        local elapsed_hours=$(( (current_time - start_time) / 3600 ))
        
        # Check block production
        local current_block=$(get_block_number)
        if [ "$current_block" -gt "$last_block" ]; then
            local blocks_produced=$((current_block - last_block))
            local time_diff=$((current_time - last_block_time))
            local blocks_per_min=$(echo "scale=2; $blocks_produced * 60 / $time_diff" | bc 2>/dev/null || echo "0")
            
            log_metric "Block $current_block (+$blocks_produced, $blocks_per_min blocks/min)"
            last_block=$current_block
            last_block_time=$current_time
        else
            local time_since_block=$((current_time - last_block_time))
            if [ "$time_since_block" -gt "$STALL_THRESHOLD" ]; then
                stall_count=$((stall_count + 1))
                log_error "STALL DETECTED: No new blocks for ${time_since_block}s (count: $stall_count)"
            else
                log_warn "Waiting for new block (${time_since_block}s since last)"
            fi
        fi
        
        # Check peer connections
        local peers=$(get_peer_count)
        log_metric "Connected peers: $peers"
        if [ "$peers" -lt 2 ]; then
            log_warn "Low peer count: $peers"
        fi
        
        # Check sync state
        local syncing=$(get_sync_state)
        if [ "$syncing" = "true" ]; then
            log_warn "Node is syncing"
        fi
        
        # Check for forks
        local fork_state=$(check_for_forks)
        if [ "$fork_state" = "diverged" ]; then
            fork_count=$((fork_count + 1))
            log_warn "Chain divergence detected (count: $fork_count)"
        fi
        
        # Check memory usage
        local memory=$(get_memory_mb "hegemon-boot1")
        if [ "$memory" -gt "$max_memory" ]; then
            max_memory=$memory
        fi
        log_metric "Memory: ${memory}MB (max: ${max_memory}MB)"
        
        if [ "$memory" -gt "$MEMORY_THRESHOLD_MB" ]; then
            log_error "Memory exceeds threshold: ${memory}MB > ${MEMORY_THRESHOLD_MB}MB"
        fi
        
        # Progress update
        local remaining_hours=$(( (end_time - current_time) / 3600 ))
        if [ $((total_checks % 10)) -eq 0 ]; then
            log_info "Progress: ${elapsed_hours}h elapsed, ${remaining_hours}h remaining"
            log_info "Blocks produced: $((current_block - initial_block))"
        fi
        
        sleep "$CHECK_INTERVAL"
    done
    
    # Final report
    local final_block=$(get_block_number)
    local total_blocks=$((final_block - initial_block))
    local duration_secs=$((DURATION_HOURS * 3600))
    local avg_block_time=$(echo "scale=2; $duration_secs / $total_blocks" | bc 2>/dev/null || echo "N/A")
    
    log_info "======================================"
    log_info "        SOAK TEST COMPLETE"
    log_info "======================================"
    log_info "Duration: ${DURATION_HOURS} hours"
    log_info "Total blocks produced: $total_blocks"
    log_info "Average block time: ${avg_block_time}s"
    log_info "Stall events: $stall_count"
    log_info "Fork events: $fork_count"
    log_info "Max memory usage: ${max_memory}MB"
    log_info "Final block height: $final_block"
    
    # Exit status
    if [ "$stall_count" -gt 0 ] || [ "$fork_count" -gt 10 ] || [ "$max_memory" -gt "$MEMORY_THRESHOLD_MB" ]; then
        log_error "SOAK TEST FAILED - Issues detected"
        exit 1
    else
        log_info "SOAK TEST PASSED"
        exit 0
    fi
}

# Trap for clean exit
cleanup() {
    log_info "Soak test interrupted, generating partial report..."
    exit 130
}
trap cleanup SIGINT SIGTERM

# Run
main "$@"
