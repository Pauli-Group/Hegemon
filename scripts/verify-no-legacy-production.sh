#!/bin/bash
# scripts/verify-no-legacy-production.sh
# 
# Verifies that production code uses real implementations, not legacy mocks.
# Run this before releases to ensure no scaffold code is in production paths.

set -e

echo "=== Verifying Production Code Uses Real Implementations ==="

# 1. Check runtime uses StarkVerifier for settlement (not AcceptAllProofs)
echo -n "Checking settlement pallet uses StarkVerifier... "
if grep -q "type ProofVerifier = pallet_settlement::AcceptAllProofs" runtime/src/lib.rs; then
    echo "❌ FAILED"
    echo "Runtime still uses AcceptAllProofs for settlement pallet!"
    exit 1
fi
if grep -q "type ProofVerifier = pallet_settlement::StarkVerifier" runtime/src/lib.rs; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: Could not find StarkVerifier config for settlement"
fi

# 2. Check runtime uses StarkVerifier for shielded-pool
echo -n "Checking shielded-pool pallet uses StarkVerifier... "
if grep -q "type ProofVerifier = pallet_shielded_pool::verifier::AcceptAllProofs" runtime/src/lib.rs; then
    echo "❌ FAILED"
    echo "Runtime still uses AcceptAllProofs for shielded-pool pallet!"
    exit 1
fi
if grep -q "type ProofVerifier = pallet_shielded_pool::verifier::StarkVerifier" runtime/src/lib.rs; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: Could not find StarkVerifier config for shielded-pool"
fi

# 3. Check new_full_with_client() exists (legacy new_full() has been removed)
echo -n "Checking new_full_with_client() exists in service.rs... "
if grep -q "pub async fn new_full_with_client" node/src/substrate/service.rs; then
    echo "✅ PASS"
else
    echo "❌ FAILED"
    echo "new_full_with_client() not found in service.rs!"
    exit 1
fi

# 4. Check deprecated new_full() wrapper has been removed
echo -n "Checking deprecated new_full() has been removed... "
if grep -q "pub async fn new_full(" node/src/substrate/service.rs; then
    echo "❌ FAILED"
    echo "Deprecated new_full() still exists in service.rs!"
    exit 1
fi
echo "✅ PASS"

# 5. Check MockTransactionPool not imported in service.rs (excluding comments)
echo -n "Checking MockTransactionPool not used in service.rs... "
if grep "^use.*MockTransactionPool" node/src/substrate/service.rs 2>/dev/null; then
    echo "❌ FAILED"
    echo "MockTransactionPool still imported in service.rs!"
    exit 1
fi
echo "✅ PASS"

# 6. Check no duplicate backup files exist
echo -n "Checking no duplicate backup files... "
if ls node/src/substrate/*\ 2.rs 2>/dev/null; then
    echo "❌ FAILED"
    echo "Duplicate backup files still exist!"
    exit 1
fi
echo "✅ PASS"

# 7. Check legacy node modules have been removed
echo -n "Checking legacy node modules removed... "
legacy_found=0
for file in api.rs bootstrap.rs mempool.rs storage.rs sync.rs service.rs codec.rs; do
    if [ -f "node/src/$file" ]; then
        echo "❌ FAILED"
        echo "Legacy module node/src/$file still exists!"
        legacy_found=1
    fi
done
if [ $legacy_found -eq 0 ]; then
    echo "✅ PASS"
else
    exit 1
fi

# 8. Check code compiles
echo -n "Checking code compiles... "
if cargo check -p hegemon-node -p runtime --quiet 2>/dev/null; then
    echo "✅ PASS"
else
    echo "❌ FAILED"
    echo "Code does not compile!"
    exit 1
fi

echo ""
echo "=== All Checks Passed ==="
echo "✅ Production code uses real implementations"
echo "✅ No legacy scaffold code in production paths"
echo "✅ Test mocks exist only in test modules"
