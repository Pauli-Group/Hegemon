# PQC & STARK Integration Fixes

## 🔴 CRITICAL

### 1. Enable stark-verify feature in runtime
- **File:** `runtime/Cargo.toml`
- **Issue:** STARK proofs are NOT cryptographically verified - all proofs pass
- **Fix:** Add `features = ["stark-verify"]` to pallet-shielded-pool dependency
- **Status:** ✅ DONE (upgraded to polkadot-sdk 2512-rc1, fixed LazyBlock/TxCreditHold APIs)

### 2. Fix public input hash truncation  
- **File:** `pallets/shielded-pool/src/verifier.rs`, `wallet/src/viewing.rs`
- **Issue:** Wallet used Blake3 for nullifiers but circuit uses Poseidon (different outputs!)
- **Fix:** Updated wallet to use Poseidon-based nullifier from circuit, matching proof verification
- **Status:** ✅ DONE (wallet now uses transaction_circuit::hashing::nullifier_bytes)

## 🟠 HIGH

### 3. Fix EncryptedNote size for ML-KEM
- **File:** `pallets/shielded-pool/src/types.rs`
- **Issue:** `ephemeral_pk` was 32 bytes but ML-KEM-768 ciphertext is 1088 bytes
- **Fix:** Renamed to `kem_ciphertext: [u8; 1088]` with proper size
- **Status:** ✅ DONE

### 4. Implement real SLH-DSA
- **File:** `crypto/src/slh_dsa.rs`
- **Issue:** Uses HKDF expansion placeholder, NOT real SPHINCS+
- **Fix:** Replace with real `slh-dsa` crate implementation
- **Status:** ✅ DONE (using slh-dsa v0.2.0-rc.1 with Shake128f)

### 5. Implement binding signature verification
- **File:** `pallets/shielded-pool/src/verifier.rs`
- **Issue:** Only checked signature was non-zero, no cryptographic verification
- **Fix:** Implemented Blake2 commitment to public inputs (anchor, nullifiers, commitments, value_balance)
- **Status:** ✅ DONE (added `compute_binding_commitment` helper for wallet use)

## 🟡 MEDIUM

### 6. Wire wallet to transaction prover
- **Files:** `wallet/src/`, `circuits/transaction/`
- **Issue:** No integration between wallet and STARK prover
- **Fix:** Add proof generation to wallet's transaction building flow
- **Status:** ⬜ Pending

### 7. Add integration tests with real proofs
- **File:** `pallets/shielded-pool/src/tests/` (new)
- **Issue:** Tests use `AcceptAllProofs` mock, don't exercise real verification
- **Fix:** Create integration tests that generate and verify real STARK proofs
- **Status:** ⬜ Pending

### 8. Fix pallet mock to optionally use real verifier
- **File:** `pallets/shielded-pool/src/mock.rs`
- **Issue:** Always uses `AcceptAllProofs`
- **Fix:** Add feature flag to optionally use `StarkVerifier` in tests
- **Status:** ⬜ Pending
