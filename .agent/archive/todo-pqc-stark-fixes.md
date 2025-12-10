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

### 3. Enable stark-verify for settlement pallet
- **File:** `runtime/Cargo.toml`
- **Issue:** Settlement pallet's `verify_stark()` always returned true (stub)
- **Fix:** Add `features = ["stark-verify"]` to pallet-settlement dependency
- **Status:** ✅ DONE

### 4. Add AIR hash validation
- **Files:** `circuits/transaction/src/constants.rs`, `pallets/shielded-pool/src/verifier.rs`
- **Issue:** No validation that proofs were generated with correct circuit version
- **Fix:** Added `CIRCUIT_VERSION`, `compute_air_hash()` and verifier validation
- **Status:** ✅ DONE (Blake2-256 of circuit params, trace width check)

## 🟠 HIGH

### 5. Fix EncryptedNote size for ML-KEM
- **File:** `pallets/shielded-pool/src/types.rs`
- **Issue:** `ephemeral_pk` was 32 bytes but ML-KEM-768 ciphertext is 1088 bytes
- **Fix:** Renamed to `kem_ciphertext: [u8; 1088]` with proper size
- **Status:** ✅ DONE

### 6. Implement real SLH-DSA
- **File:** `crypto/src/slh_dsa.rs`
- **Issue:** Uses HKDF expansion placeholder, NOT real SPHINCS+
- **Fix:** Replace with real `slh-dsa` crate implementation
- **Status:** ✅ DONE (using slh-dsa v0.2.0-rc.1 with Shake128f)

### 7. Implement binding signature verification
- **File:** `pallets/shielded-pool/src/verifier.rs`
- **Issue:** Only checked signature was non-zero, no cryptographic verification
- **Fix:** Implemented Blake2 commitment to public inputs (anchor, nullifiers, commitments, value_balance)
- **Status:** ✅ DONE (added `compute_binding_commitment` helper for wallet use)

## 🟡 MEDIUM

### 8. Wire wallet to transaction prover
- **Files:** `wallet/src/`, `circuits/transaction/`
- **Issue:** No integration between wallet and STARK prover
- **Fix:** Add proof generation to wallet's transaction building flow
- **Status:** ✅ DONE (TransactionBundle with StarkProver, binding signatures)

### 9. Add integration tests with real proofs
- **File:** `pallets/shielded-pool/src/tests/` (new)
- **Issue:** Tests use `AcceptAllProofs` mock, don't exercise real verification
- **Fix:** Create integration tests that generate and verify real STARK proofs
- **Status:** ⬜ Pending

### 10. Fix pallet mock to optionally use real verifier
- **File:** `pallets/shielded-pool/src/mock.rs`
- **Issue:** Always uses `AcceptAllProofs`
- **Fix:** Add feature flag to optionally use `StarkVerifier` in tests
- **Status:** ⬜ Pending

---

## 📋 Future Work (Execplans Created)

### Proof Aggregation
- **Execplan:** `circuits/PROOF_AGGREGATION_EXECPLAN.md`
- **Goal:** Batch N transaction proofs into single aggregate proof for O(1) verification
- **Estimated:** 12-15 days

### Recursive Proofs
- **Execplan:** `circuits/RECURSIVE_PROOFS_EXECPLAN.md`
- **Goal:** Proofs that verify other proofs, enabling epoch-level compression
- **Estimated:** 25-35 days

### Formal Verification
- **Execplan:** `circuits/FORMAL_VERIFICATION_EXECPLAN.md`
- **Goal:** Mathematical proofs of circuit soundness/completeness (Lean 4 + SMT)
- **Estimated:** 26-36 days

---

## 📊 PQC Coverage Summary

| Algorithm | FIPS | Usage | Status |
|-----------|------|-------|--------|
| ML-KEM-768 | 203 | Note encryption, P2P key exchange | ✅ Real (fips203 crate) |
| ML-DSA-65 | 204 | Transaction signatures, block signing | ✅ Real (fips204 crate) |
| SLH-DSA | 205 | Long-term trust roots | ✅ Real (slh-dsa crate) |

⚠️ **Note:** Substrate's sp-core still compiles ECC (ed25519, secp256k1) as transitive dependencies but they are NOT USED for any security-critical operations.

## 📊 STARK Coverage Summary

| Component | Status |
|-----------|--------|
| winterfell 0.13.1 | ✅ Real proofs |
| TransactionProverStark | ✅ Generates real proofs |
| StarkVerifier | ✅ Real verification with stark-verify |
| AIR hash validation | ✅ Circuit version binding |
| Trace width check | ✅ EXPECTED_TRACE_WIDTH = 5 |
| Settlement pallet | ✅ stark-verify enabled |
