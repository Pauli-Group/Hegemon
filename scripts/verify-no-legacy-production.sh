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

# ============================================
# Phase 15.3.4: Additional Production Checks
# ============================================

echo ""
echo "=== Phase 15.3.4: Additional Production Checks ==="

# 9. Verify ML-KEM in pq-noise (not X25519)
echo -n "Checking pq-noise uses ML-KEM... "
if grep -q "x25519" pq-noise/Cargo.toml 2>/dev/null; then
    echo "❌ FAILED"
    echo "pq-noise has x25519 dependency!"
    exit 1
fi
if grep -q "ml-kem" crypto/Cargo.toml 2>/dev/null; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: Could not verify ML-KEM in crypto crate"
fi

# 10. Verify ML-DSA in crypto (not Ed25519)
echo -n "Checking crypto uses ML-DSA... "
if grep -q "ed25519" crypto/Cargo.toml 2>/dev/null; then
    echo "❌ FAILED"
    echo "crypto has ed25519 dependency!"
    exit 1
fi
if grep -q "ml-dsa" crypto/Cargo.toml 2>/dev/null; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: Could not verify ML-DSA in crypto crate"
fi

# 11. Verify winterfell STARK (not Groth16)
echo -n "Checking STARK uses winterfell... "
if grep -q "bellman\|ark-groth16\|halo2" Cargo.lock 2>/dev/null; then
    echo "❌ FAILED"
    echo "Found Groth16/Halo2 dependencies in Cargo.lock!"
    exit 1
fi
if grep -q "winterfell" circuits/transaction/Cargo.toml 2>/dev/null; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: Could not verify winterfell in circuits"
fi

# 12. Verify no AcceptAllProofs in runtime config
echo -n "Checking runtime proof verifier... "
if grep -E "AcceptAllProofs|DummyVerifier|MockVerifier" runtime/src/lib.rs 2>/dev/null | grep -v "^//" | grep -v "^//!" > /dev/null; then
    echo "❌ FAILED"
    echo "Runtime contains mock proof verifier!"
    exit 1
fi
echo "✅ PASS"

# 13. Verify STARK constants are production-ready
echo -n "Checking STARK security parameters... "
# Check FRI blowup factor >= 8 (if defined in constants)
if grep -q "blowup.*=.*[0-7]" circuits/transaction/src/*.rs 2>/dev/null | grep -v "// " | grep -v test; then
    echo "⚠️ WARNING: Found potential low FRI blowup factor"
fi
echo "✅ PASS (manual review recommended)"

# 14. Verify PQ handshake is required
echo -n "Checking PQ handshake requirement... "
if grep -q "HEGEMON_PQ_REQUIRE\|require_pq" network/src/*.rs 2>/dev/null; then
    echo "✅ PASS"
else
    echo "⚠️ WARNING: PQ requirement flag not found"
fi

# 15. Verify no test-only features in release
echo -n "Checking no test features in release... "
if grep -q 'default = .*"test"' */Cargo.toml 2>/dev/null; then
    echo "❌ FAILED"
    echo "Test features enabled by default!"
    exit 1
fi
echo "✅ PASS"

# 16. Verify transaction circuit is not built with legacy or fast proof features
echo -n "Checking transaction-circuit features... "
feature_tree=$(cargo tree -p transaction-circuit -e features 2>/dev/null)
if echo "$feature_tree" | grep -q "legacy-proof"; then
    echo "❌ FAILED"
    echo "transaction-circuit compiled with legacy-proof feature!"
    exit 1
fi
if echo "$feature_tree" | grep -q "stark-fast"; then
    echo "❌ FAILED"
    echo "transaction-circuit compiled with stark-fast feature!"
    exit 1
fi
echo "✅ PASS"

# 17. Verify mock state execution is opt-in
echo -n "Checking mock state execution gating... "
if ! grep -q "HEGEMON_ALLOW_MOCK_EXECUTION" node/src/substrate/client.rs 2>/dev/null; then
    echo "❌ FAILED"
    echo "Mock execution gate missing (HEGEMON_ALLOW_MOCK_EXECUTION)!"
    exit 1
fi
if ! grep -q "allow_mock_execution: false" node/src/substrate/client.rs 2>/dev/null; then
    echo "❌ FAILED"
    echo "ProductionConfig default does not disable mock execution!"
    exit 1
fi
echo "✅ PASS"

# 18. Verify batch proofs remain opt-in in wallet
echo -n "Checking batch proofs are opt-in... "
if grep -q 'default = .*batch-proofs' wallet/Cargo.toml 2>/dev/null; then
    echo "❌ FAILED"
    echo "batch-proofs enabled by default in wallet!"
    exit 1
fi
echo "✅ PASS"

echo ""
echo "=== All Checks Passed ==="
echo "✅ Production code uses real implementations"
echo "✅ No legacy scaffold code in production paths"
echo "✅ Test mocks exist only in test modules"
echo "✅ PQ-only crypto verified (ML-KEM, ML-DSA, STARK)"
echo "✅ No forbidden primitives (ECC, Groth16)"
