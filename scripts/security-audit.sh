#!/bin/bash
# scripts/security-audit.sh
#
# PQ Security Audit Script - Phase 15.1.1
# Scans the codebase for forbidden classical cryptographic primitives.
#
# This script ensures the codebase contains ZERO elliptic curve, RSA, pairing,
# Groth16/PLONK/Halo2, or trusted-setup implementations, as mandated by the
# PQ-ONLY security policy.
#
# Usage:
#   ./scripts/security-audit.sh           # Full audit
#   ./scripts/security-audit.sh --quick   # Skip cargo.lock (faster)
#   ./scripts/security-audit.sh --fix     # Show suggested fixes
#   ./scripts/security-audit.sh --require-binary --node-bin target/release/hegemon-node
#
# Exit codes:
#   0 - Audit passed (no forbidden primitives)
#   1 - Audit failed (forbidden primitives found)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
QUICK=false
FIX=false
REQUIRE_BINARY=false
NODE_BIN=""

usage() {
    cat <<'USAGE'
usage: scripts/security-audit.sh [--quick] [--fix] [--require-binary] [--node-bin PATH]
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --quick)
            QUICK=true
            shift
            ;;
        --fix)
            FIX=true
            shift
            ;;
        --require-binary)
            REQUIRE_BINARY=true
            shift
            ;;
        --node-bin)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                usage >&2
                exit 2
            fi
            NODE_BIN="$2"
            shift 2
            ;;
        --node-bin=*)
            NODE_BIN="${1#*=}"
            if [ -z "$NODE_BIN" ]; then
                usage >&2
                exit 2
            fi
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$NODE_BIN" ]; then
    NODE_BIN="$PROJECT_ROOT/target/release/hegemon-node"
elif [[ "$NODE_BIN" != /* ]]; then
    NODE_BIN="$PROJECT_ROOT/$NODE_BIN"
fi

cd "$PROJECT_ROOT"

echo "========================================"
echo "   PQ Security Audit: Hegemon v0.1.0"
echo "========================================"
echo ""
echo "Scanning for forbidden classical cryptographic primitives..."
echo "Target: ZERO ECC, ZERO RSA, ZERO pairings, ZERO trusted-setup SNARKs"
echo ""

VIOLATIONS=0
WARNINGS=0

if [ -n "${HEGEMON_LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS:-}" ]; then
    echo "=== Step 0: Lean Release PQ Binary Policy Vector Check ==="
    echo ""
    python3 "$PROJECT_ROOT/scripts/check_release_pq_binary_policy_vectors.py" \
        "$HEGEMON_LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS"
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 1: Grep scan for forbidden primitive names in source code
# ---------------------------------------------------------------------------

echo "=== Step 1: Source Code Pattern Scan ==="
echo ""

# Some trust-boundary code has to name a forbidden primitive in order to reject
# it explicitly. Keep those branches auditable without letting real use sites
# disappear from the report.
filter_reject_only_matches() {
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        if [[ "$match" =~ ^(.+):([0-9]+):(.*)$ ]]; then
            local file="${BASH_REMATCH[1]}"
            local line="${BASH_REMATCH[2]}"
            local start=$((line > 3 ? line - 3 : 1))
            local end=$((line + 4))
            local context
            context="$(sed -n "${start},${end}p" "$file" 2>/dev/null || true)"
            local source_line="${BASH_REMATCH[3]}"
            if printf '%s\n' "$source_line" | grep -Eiq 'not accepted|not allowed|reject|unsupported|forbidden'; then
                continue
            fi
            if printf '%s\n' "$source_line" | grep -Eq '=>[[:space:]]*[{]?' && \
               printf '%s\n' "$context" | grep -Eiq 'return[[:space:]]+Err|Err[[:space:]]*\(' && \
               printf '%s\n' "$context" | grep -Eiq 'not accepted|not allowed|reject|unsupported|forbidden'; then
                continue
            fi
        fi
        printf '%s\n' "$match"
    done
}

# Function to check a single pattern
check_pattern() {
    local pattern="$1"
    local description="$2"
    
    printf "Checking for '%s'... " "$pattern"
    
    # Search in Rust files, excluding target/, .git/, comments, test output, and this audit script
    raw_matches=$(grep -rniE "$pattern" \
        --include="*.rs" --include="*.toml" \
        "$PROJECT_ROOT" 2>/dev/null \
        | grep -v "target/" \
        | grep -v ".git/" \
        | grep -v "security-audit.sh" \
        | grep -v "FORBIDDEN" \
        | grep -v "# VIOLATION" \
        | grep -v "// FORBIDDEN" \
        | grep -v "//!" \
        | grep -v "/// " \
        | grep -v "execplan" \
        | grep -v "THREAT_MODEL" \
        | grep -v "METHODS.md" \
        | grep -v "README.md" \
        | grep -v "DESIGN.md" \
        | grep -v "pq_params_audit.rs" \
        | grep -v "stark_soundness.rs" \
        | grep -v "println!" \
        | grep -v "keywords =" \
        | grep -v "// " \
        || true)
    matches=$(printf '%s\n' "$raw_matches" | filter_reject_only_matches)
    
    if [ -n "$matches" ]; then
        printf "${RED}❌ FOUND${NC}\n"
        echo "  Reason: $description"
        echo "  Matches:"
        echo "$matches" | head -10 | sed 's/^/    /'
        match_count=$(echo "$matches" | wc -l | tr -d ' ')
        if [ "$match_count" -gt 10 ]; then
            echo "    ... and $((match_count - 10)) more"
        fi
        echo ""
        return 1
    else
        printf "${GREEN}✅ Clean${NC}\n"
        return 0
    fi
}

# Check all forbidden patterns
check_pattern "groth16" "Pairing-based SNARK (BLS12-381), quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "(^|[^[:alnum:]_])rsa([^[:alnum:]_]|$)" "RSA signature/encryption, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "ed25519" "Elliptic curve signature (Curve25519), Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "x25519" "Elliptic curve ECDH (Curve25519), Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "ecdh" "Elliptic curve Diffie-Hellman, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "ecdsa" "Elliptic curve signature, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "secp256k1" "Bitcoin curve, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "secp256r1" "NIST P-256 curve, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "p256" "NIST P-256 curve, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "bls12" "Pairing-friendly curve (Groth16), quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "bn254" "Pairing-friendly curve, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "jubjub" "Embedded curve for SNARKs, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "babyjubjub" "Embedded curve for SNARKs, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "(^|[^[:alnum:]_])pallas([^[:alnum:]_]|$)" "Halo2 curve, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "(^|[^[:alnum:]_])vesta([^[:alnum:]_]|$)" "Halo2 curve, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "curve25519" "Elliptic curve, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "dalek" "Curve25519 library, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "ristretto" "Curve25519 variant, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "halo2" "ECC-based zkSNARK, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "(^|[^[:alnum:]_])plonk([^[:alnum:]_y]|$)" "Polynomial commitment SNARK (often ECC), check dependencies" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "trusted[[:space:]_-]*setup" "Trusted-setup proof system artifact, not PQ-clean release policy" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "powers[[:space:]_-]*of[[:space:]_-]*tau" "Trusted-setup ceremony artifact, not PQ-clean release policy" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "(^|[^[:alnum:]_])kzg([^[:alnum:]_]|$)" "Pairing-based polynomial commitment, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))

echo ""

# ---------------------------------------------------------------------------
# Step 2: Check Cargo.lock for ECC crate dependencies
# ---------------------------------------------------------------------------

if [ "$QUICK" = false ]; then
    echo "=== Step 2: Cargo.lock Dependency Scan ==="
    echo ""
    
    if [ ! -f "$PROJECT_ROOT/Cargo.lock" ]; then
        printf "${YELLOW}⚠️  WARNING: Cargo.lock not found, skipping dependency scan${NC}\n"
        WARNINGS=$((WARNINGS + 1))
    else
        # ECC crates that indicate quantum-vulnerable dependencies
        ECC_CRATES="curve25519-dalek ed25519-dalek x25519-dalek k256 p256 secp256k1 rsa ark-ec ark-bls12-381 ark-bn254 ark-poly-commit bellman groth16 halo2_proofs halo2_gadgets pasta_curves plonk kzg"
        
        for crate in $ECC_CRATES; do
            echo -n "Checking for '$crate' in Cargo.lock... "
            if grep -q "name = \"$crate\"" "$PROJECT_ROOT/Cargo.lock"; then
                echo -e "${RED}❌ FOUND${NC}"
                version=$(grep -A1 "name = \"$crate\"" "$PROJECT_ROOT/Cargo.lock" | grep version | head -1)
                echo "  Dependency: $crate ($version)"
                VIOLATIONS=$((VIOLATIONS + 1))
            else
                echo -e "${GREEN}✅ Not present${NC}"
            fi
        done
    fi
    
    echo ""
fi

# ---------------------------------------------------------------------------
# Step 3: Check native node binary for ECC symbols
# ---------------------------------------------------------------------------

echo "=== Step 3: Native Binary Symbol Scan ==="
echo ""

if [ -f "$NODE_BIN" ]; then
    echo "Checking: $NODE_BIN"
    if ! command -v strings >/dev/null 2>&1; then
        echo -e "${RED}❌ CANNOT SCAN${NC}"
        echo "  Required tool not found: strings"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        symbol_matches=$(
            strings "$NODE_BIN" 2>/dev/null \
                | grep -iE "curve25519|secp|ecdsa|ed25519|x25519|bls12|bn254|jubjub|groth16|halo2|trusted[[:space:]_-]*setup|powers[[:space:]_-]*of[[:space:]_-]*tau" \
                || true
            strings "$NODE_BIN" 2>/dev/null \
                | grep -iE "(^|[^[:alnum:]_])pallas([^[:alnum:]_]|$)|(^|[^[:alnum:]_])vesta([^[:alnum:]_]|$)|(^|[^[:alnum:]_])rsa([^[:alnum:]_]|$)|(^|[^[:alnum:]_])plonk([^[:alnum:]_y]|$)|(^|[^[:alnum:]_])kzg([^[:alnum:]_]|$)" \
                || true
        )
        if [ -n "$symbol_matches" ]; then
            echo -e "${RED}❌ FOUND${NC}"
            echo "$symbol_matches" | head -10 | sed 's/^/    /'
            VIOLATIONS=$((VIOLATIONS + 1))
        else
            echo -e "${GREEN}✅ No forbidden ECC symbols${NC}"
        fi
    fi
else
    if [ "$REQUIRE_BINARY" = true ]; then
        echo -e "${RED}❌ FOUND${NC}"
        echo "  Required release node binary not found: $NODE_BIN"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        echo -e "${YELLOW}⚠️  WARNING: release node binary not found; run 'make node' for binary scan${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Step 4: Check critical crypto modules
# ---------------------------------------------------------------------------

echo "=== Step 4: Critical Module Verification ==="
echo ""

# Check pq-noise uses ML-KEM (not X25519)
echo -n "Checking pq-noise uses ML-KEM-1024... "
if grep -q "ml-kem" "$PROJECT_ROOT/pq-noise/Cargo.toml" && \
   grep -q "ML-KEM-1024" "$PROJECT_ROOT/pq-noise/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-KEM-1024${NC}"
elif grep -q "ML-KEM" "$PROJECT_ROOT/crypto/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-KEM via crypto crate${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify ML-KEM usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Check native identity/signing uses ML-DSA (not Ed25519)
echo -n "Checking native signing uses ML-DSA-65... "
if grep -q "ML_DSA\|MlDsa\|ml_dsa" "$PROJECT_ROOT/crypto/src"/*.rs "$PROJECT_ROOT/network/src"/*.rs "$PROJECT_ROOT/node/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-DSA-65${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify ML-DSA usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Check shielded protocol uses STARK (not Groth16)
echo -n "Checking shielded protocol uses STARK proofs... "
if grep -q "STARK\|stark" "$PROJECT_ROOT/circuits/transaction/Cargo.toml" "$PROJECT_ROOT/consensus/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses STARK (Plonky3)${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify STARK usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Step 5: Check approved primitives are in use
# ---------------------------------------------------------------------------

echo "=== Step 5: Approved Primitives Verification ==="
echo ""

APPROVED_FOUND=0

echo -n "Blake3 (PoW, hashing)... "
if grep -q "blake3" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
    echo -e "${GREEN}✅ Present${NC}"
    APPROVED_FOUND=$((APPROVED_FOUND + 1))
else
    echo -e "${YELLOW}⚠️  Not found${NC}"
fi

echo -n "ML-KEM (FIPS 203, key exchange)... "
if grep -q "ml-kem" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
    echo -e "${GREEN}✅ Present${NC}"
    APPROVED_FOUND=$((APPROVED_FOUND + 1))
else
    echo -e "${YELLOW}⚠️  Not found${NC}"
fi

echo -n "ML-DSA (FIPS 204, signatures)... "
if grep -q "ml-dsa" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
    echo -e "${GREEN}✅ Present${NC}"
    APPROVED_FOUND=$((APPROVED_FOUND + 1))
else
    echo -e "${YELLOW}⚠️  Not found${NC}"
fi

echo -n "SLH-DSA/SPHINCS+ (FIPS 205, long-term)... "
if grep -q "slh-dsa\|sphincs" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
    echo -e "${GREEN}✅ Present${NC}"
    APPROVED_FOUND=$((APPROVED_FOUND + 1))
else
    echo -e "${YELLOW}⚠️  Not found (optional)${NC}"
fi

echo -n "Plonky3 (STARK proofs)... "
if grep -q "p3-uni-stark" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
    echo -e "${GREEN}✅ Present${NC}"
    APPROVED_FOUND=$((APPROVED_FOUND + 1))
else
    echo -e "${YELLOW}⚠️  Not found${NC}"
fi

echo ""
echo "Approved primitives found: $APPROVED_FOUND/5"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "========================================"
echo "           AUDIT SUMMARY"
echo "========================================"
echo ""

if [ $VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}✅ AUDIT PASSED${NC}"
    echo ""
    echo "No forbidden cryptographic primitives detected."
    echo "The codebase appears to be PQ-ONLY compliant."
    
    if [ $WARNINGS -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  $WARNINGS warning(s) - manual verification recommended${NC}"
    fi
    
    echo ""
    echo "Approved Primitives:"
    echo "  ✓ Blake3 (PoW, general hashing)"
    echo "  ✓ ML-KEM-1024 (P2P handshake and note encryption)"
    echo "  ✓ ML-DSA-65 (Signatures, identity)"
    echo "  ✓ SLH-DSA (Long-term trust roots)"
    echo "  ✓ STARK/FRI (Zero-knowledge proofs)"
    echo "  ✓ Poseidon (STARK-friendly hashing)"
    
    exit 0
else
    echo -e "${RED}❌ AUDIT FAILED${NC}"
    echo ""
    echo "Found $VIOLATIONS forbidden cryptographic primitive(s)!"
    echo ""
    echo "CRITICAL: This codebase must be PQ-ONLY."
    echo "Remove all elliptic curve, pairing, and Groth16 code."
    
    if [ "$FIX" = true ]; then
        echo ""
        echo "Suggested Fixes:"
        echo "  - Replace Ed25519 → ML-DSA-65"
        echo "  - Replace X25519 → ML-KEM-1024"
        echo "  - Replace Groth16 → STARK (Plonky3)"
        echo "  - Replace ECDSA → ML-DSA-65"
        echo "  - Remove all *-dalek crates"
        echo "  - Remove all ark-* ECC crates"
    fi
    
    exit 1
fi
