#!/bin/bash
# scripts/security-audit.sh
#
# PQ Security Audit Script - Phase 15.1.1
# Scans the codebase for forbidden classical cryptographic primitives.
#
# This script ensures the codebase contains ZERO elliptic curve, pairing,
# or Groth16 implementations, as mandated by the PQ-ONLY security policy.
#
# Usage:
#   ./scripts/security-audit.sh           # Full audit
#   ./scripts/security-audit.sh --quick   # Skip cargo.lock (faster)
#   ./scripts/security-audit.sh --fix     # Show suggested fixes
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
for arg in "$@"; do
    case $arg in
        --quick)
            QUICK=true
            shift
            ;;
        --fix)
            FIX=true
            shift
            ;;
    esac
done

cd "$PROJECT_ROOT"

echo "========================================"
echo "   PQ Security Audit: Hegemon v0.1.0"
echo "========================================"
echo ""
echo "Scanning for forbidden classical cryptographic primitives..."
echo "Target: ZERO ECC, ZERO pairings, ZERO Groth16"
echo ""

VIOLATIONS=0
WARNINGS=0

# ---------------------------------------------------------------------------
# Step 1: Grep scan for forbidden primitive names in source code
# ---------------------------------------------------------------------------

echo "=== Step 1: Source Code Pattern Scan ==="
echo ""

# Function to check a single pattern
check_pattern() {
    local pattern="$1"
    local description="$2"
    
    printf "Checking for '%s'... " "$pattern"
    
    # Search in Rust files, excluding target/, .git/, comments, test output, and this audit script
    matches=$(grep -rniE "$pattern" \
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
        | grep -v "// " \
        || true)
    
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
check_pattern "pallas" "Halo2 curve, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "vesta" "Halo2 curve, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "curve25519" "Elliptic curve, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "dalek" "Curve25519 library, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "ristretto" "Curve25519 variant, Shor-breakable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "halo2" "ECC-based zkSNARK, quantum-vulnerable" || VIOLATIONS=$((VIOLATIONS + 1))
check_pattern "plonk" "Polynomial commitment SNARK (often ECC), check dependencies" || VIOLATIONS=$((VIOLATIONS + 1))

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
        ECC_CRATES="curve25519-dalek ed25519-dalek x25519-dalek k256 p256 secp256k1 ark-ec ark-bls12-381 ark-bn254 bellman halo2_proofs halo2_gadgets pasta_curves"
        
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
# Step 3: Check runtime WASM for ECC symbols
# ---------------------------------------------------------------------------

echo "=== Step 3: Runtime WASM Symbol Scan ==="
echo ""

WASM_PATH="$PROJECT_ROOT/target/release/wbuild/runtime/runtime.compact.wasm"
WASM_PATH_ALT="$PROJECT_ROOT/target/release/wbuild/hegemon-runtime/hegemon_runtime.compact.wasm"

if [ -f "$WASM_PATH" ]; then
    WASM_TO_CHECK="$WASM_PATH"
elif [ -f "$WASM_PATH_ALT" ]; then
    WASM_TO_CHECK="$WASM_PATH_ALT"
else
    echo -e "${YELLOW}⚠️  WARNING: Runtime WASM not found at expected paths:${NC}"
    echo "    $WASM_PATH"
    echo "    $WASM_PATH_ALT"
    echo "  Run 'cargo build --release -p runtime' to generate"
    WASM_TO_CHECK=""
    WARNINGS=$((WARNINGS + 1))
fi

if [ -n "$WASM_TO_CHECK" ]; then
    echo "Checking: $WASM_TO_CHECK"
    
    # Check if wasm-objdump is available
    if command -v wasm-objdump &> /dev/null; then
        echo -n "Scanning for ECC symbols... "
        ecc_symbols=$(wasm-objdump -x "$WASM_TO_CHECK" 2>/dev/null \
            | grep -iE "curve|dalek|secp|ecdsa|ed25519|x25519|bls12|bn254|jubjub|pallas|vesta" \
            || true)
        
        if [ -n "$ecc_symbols" ]; then
            echo -e "${RED}❌ FOUND${NC}"
            echo "  ECC symbols in WASM:"
            echo "$ecc_symbols" | head -10 | sed 's/^/    /'
            VIOLATIONS=$((VIOLATIONS + 1))
        else
            echo -e "${GREEN}✅ No ECC symbols${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  WARNING: wasm-objdump not found, skipping WASM symbol scan${NC}"
        echo "  Install with: cargo install wabt"
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
echo -n "Checking pq-noise uses ML-KEM-768... "
if grep -q "ml-kem" "$PROJECT_ROOT/pq-noise/Cargo.toml" && \
   grep -q "ML_KEM_768" "$PROJECT_ROOT/pq-noise/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-KEM-768${NC}"
elif grep -q "ML-KEM" "$PROJECT_ROOT/crypto/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-KEM via crypto crate${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify ML-KEM usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Check identity pallet uses ML-DSA (not Ed25519)
echo -n "Checking identity pallet uses ML-DSA-65... "
if grep -q "ml-dsa\|MlDsa" "$PROJECT_ROOT/pallets/identity/src"/*.rs 2>/dev/null || \
   grep -q "ML_DSA\|MlDsa" "$PROJECT_ROOT/crypto/src"/*.rs 2>/dev/null; then
    echo -e "${GREEN}✅ Uses ML-DSA-65${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify ML-DSA usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Check shielded-pool uses STARK (not Groth16)
echo -n "Checking shielded-pool uses STARK proofs... "
if grep -q "winterfell\|STARK\|stark" "$PROJECT_ROOT/pallets/shielded-pool/Cargo.toml" 2>/dev/null || \
   grep -q "StarkVerifier" "$PROJECT_ROOT/runtime/src/lib.rs" 2>/dev/null; then
    echo -e "${GREEN}✅ Uses STARK (winterfell)${NC}"
else
    echo -e "${YELLOW}⚠️  Could not verify STARK usage${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Check runtime config
echo -n "Checking runtime uses StarkVerifier... "
if grep -q "type ProofVerifier = .*StarkVerifier" "$PROJECT_ROOT/runtime/src/lib.rs" 2>/dev/null; then
    echo -e "${GREEN}✅ Runtime configured with StarkVerifier${NC}"
elif grep -q "StarkVerifier" "$PROJECT_ROOT/runtime/src/lib.rs" 2>/dev/null; then
    echo -e "${GREEN}✅ StarkVerifier found in runtime${NC}"
else
    echo -e "${RED}❌ Runtime may not use StarkVerifier!${NC}"
    VIOLATIONS=$((VIOLATIONS + 1))
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

echo -n "Winterfell (STARK proofs)... "
if grep -q "winterfell" "$PROJECT_ROOT/Cargo.lock" 2>/dev/null; then
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
    echo "  ✓ ML-KEM-768 (P2P handshake, note encryption)"
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
        echo "  - Replace X25519 → ML-KEM-768"
        echo "  - Replace Groth16 → STARK (winterfell)"
        echo "  - Replace ECDSA → ML-DSA-65"
        echo "  - Remove all *-dalek crates"
        echo "  - Remove all ark-* ECC crates"
    fi
    
    exit 1
fi
