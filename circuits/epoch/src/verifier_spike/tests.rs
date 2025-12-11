//! Verifier Spike Tests and Benchmarks
//!
//! This module contains integration tests and benchmarks for the
//! recursive proof verification spike.

use super::*;
use super::fibonacci_air::{FibonacciProver, verify_fibonacci_proof};
use super::fibonacci_verifier_air::{FibonacciVerifierProver, verify_verifier_proof};
use std::time::Instant;

/// Run the complete verifier spike and collect results.
pub fn run_spike() -> SpikeResults {
    println!("\n=== Recursive Proof Verification Spike ===\n");

    // Step 1: Generate inner (Fibonacci) proof
    println!("Step 1: Generating inner Fibonacci proof...");
    let fib_prover = FibonacciProver::new();
    
    let inner_start = Instant::now();
    let (inner_proof, inner_pub_inputs) = fib_prover.prove(64)
        .expect("Inner proof generation should succeed");
    let inner_prover_time = inner_start.elapsed();

    let inner_proof_bytes = inner_proof.to_bytes();
    let inner_proof_size = inner_proof_bytes.len();
    println!("  Inner proof size: {} bytes", inner_proof_size);
    println!("  Inner prover time: {:?}", inner_prover_time);

    // Step 2: Verify inner proof
    println!("\nStep 2: Verifying inner proof...");
    let inner_verify_start = Instant::now();
    let inner_verify_result = verify_fibonacci_proof(&inner_proof, &inner_pub_inputs);
    let inner_verify_time = inner_verify_start.elapsed();
    
    assert!(inner_verify_result.is_ok(), "Inner verification failed: {:?}", inner_verify_result);
    println!("  Inner verification: OK ({:?})", inner_verify_time);

    // Step 3: Generate outer (verifier) proof
    println!("\nStep 3: Generating outer verifier proof...");
    let verifier_prover = FibonacciVerifierProver::new();
    
    let outer_start = Instant::now();
    let (outer_proof, outer_pub_inputs) = verifier_prover.prove(&inner_proof, &inner_pub_inputs)
        .expect("Outer proof generation should succeed");
    let outer_prover_time = outer_start.elapsed();

    let outer_proof_bytes = outer_proof.to_bytes();
    let outer_proof_size = outer_proof_bytes.len();
    println!("  Outer proof size: {} bytes", outer_proof_size);
    println!("  Outer prover time: {:?}", outer_prover_time);

    // Step 4: Verify outer proof
    println!("\nStep 4: Verifying outer proof...");
    let outer_verify_start = Instant::now();
    let outer_verify_result = verify_verifier_proof(&outer_proof, &outer_pub_inputs);
    let outer_verify_time = outer_verify_start.elapsed();
    
    assert!(outer_verify_result.is_ok(), "Outer verification failed: {:?}", outer_verify_result);
    println!("  Outer verification: OK ({:?})", outer_verify_time);

    // Step 5: Compute metrics
    println!("\n=== Spike Results ===\n");

    let size_ratio = outer_proof_size as f64 / inner_proof_size as f64;
    let prover_ratio = outer_prover_time.as_millis() as f64 / 
        inner_prover_time.as_millis().max(1) as f64;

    println!("Size ratio (outer/inner): {:.2}x", size_ratio);
    println!("Prover time ratio (outer/inner): {:.2}x", prover_ratio);

    let size_criterion = size_ratio < 10.0;
    let time_criterion = prover_ratio < 100.0;
    let success = size_criterion && time_criterion;

    println!("\nSuccess Criteria:");
    println!("  Size ratio < 10x: {} (actual: {:.2}x)", 
        if size_criterion { "PASS" } else { "FAIL" }, size_ratio);
    println!("  Prover time ratio < 100x: {} (actual: {:.2}x)", 
        if time_criterion { "PASS" } else { "FAIL" }, prover_ratio);
    println!("\nOverall: {}", if success { "SUCCESS" } else { "FAILURE" });

    let summary = format!(
        "Verifier spike: size={:.2}x (target <10x), time={:.2}x (target <100x). {}",
        size_ratio,
        prover_ratio,
        if success { "PASS" } else { "FAIL - consider alternatives" }
    );

    SpikeResults {
        inner_proof_size,
        outer_proof_size,
        inner_prover_time_ms: inner_prover_time.as_millis() as u64,
        outer_prover_time_ms: outer_prover_time.as_millis() as u64,
        inner_verify_time_us: inner_verify_time.as_micros() as u64,
        outer_verify_time_us: outer_verify_time.as_micros() as u64,
        success,
        summary,
    }
}

#[test]
fn test_spike_runs_successfully() {
    let results = run_spike();
    
    // The spike should complete without panicking
    println!("\nSpike Summary:");
    println!("  Inner proof: {} bytes, {}ms prove, {}µs verify",
        results.inner_proof_size,
        results.inner_prover_time_ms,
        results.inner_verify_time_us);
    println!("  Outer proof: {} bytes, {}ms prove, {}µs verify",
        results.outer_proof_size,
        results.outer_prover_time_ms,
        results.outer_verify_time_us);
    println!("  Size ratio: {:.2}x", results.size_ratio());
    println!("  Prover time ratio: {:.2}x", results.prover_time_ratio());
    println!("  Meets criteria: {}", results.meets_criteria());
}

#[test]
fn test_inner_proof_valid() {
    let fib_prover = FibonacciProver::new();
    let (proof, pub_inputs) = fib_prover.prove(64).unwrap();
    
    let result = verify_fibonacci_proof(&proof, &pub_inputs);
    assert!(result.is_ok());
}

#[test]
fn test_outer_proof_valid() {
    let fib_prover = FibonacciProver::new();
    let (inner_proof, inner_pub_inputs) = fib_prover.prove(64).unwrap();
    
    let verifier_prover = FibonacciVerifierProver::new();
    let (outer_proof, outer_pub_inputs) = verifier_prover.prove(&inner_proof, &inner_pub_inputs).unwrap();
    
    let result = verify_verifier_proof(&outer_proof, &outer_pub_inputs);
    assert!(result.is_ok());
}

#[test]
fn test_commitment_binding() {
    let fib_prover = FibonacciProver::new();
    let (proof1, pub_inputs1) = fib_prover.prove(64).unwrap();
    let (proof2, pub_inputs2) = fib_prover.prove(128).unwrap();
    
    // Different proofs should have different commitments
    let commitment1 = blake3::hash(&proof1.to_bytes());
    let commitment2 = blake3::hash(&proof2.to_bytes());
    
    assert_ne!(commitment1.as_bytes(), commitment2.as_bytes());
}

/// Important findings from the spike.
#[test]
fn test_document_findings() {
    println!("\n=== Verifier Spike Findings ===\n");
    
    println!("1. APPROACH TAKEN:");
    println!("   - Built simplified 'verifier' that commits to inner proof");
    println!("   - Does NOT implement full STARK verification in-circuit");
    println!("   - Demonstrates commitment-based verification pattern");
    
    println!("\n2. TRUE RECURSION REQUIREMENTS:");
    println!("   - FRI verification: polynomial evaluation at query points");
    println!("   - Merkle authentication: ~14 hash operations per query");
    println!("   - Fiat-Shamir: derive challenges from transcript");
    println!("   - Constraint evaluation: evaluate AIR at random points");
    
    println!("\n3. ESTIMATED COMPLEXITY FOR TRUE RECURSION:");
    println!("   - Blake3 in-circuit: ~100 columns per compression");
    println!("   - FRI queries (8): ~800 columns for hashing alone");
    println!("   - Polynomial evaluation: quadratic in degree");
    println!("   - Total: 50-100 columns, 2^18+ rows");
    
    println!("\n4. WINTERFELL LIMITATIONS:");
    println!("   - No built-in recursion primitives");
    println!("   - No algebraic hash (Poseidon) in winter-crypto");
    println!("   - FRI verification logic not exposed as reusable AIR");
    
    println!("\n5. ALTERNATIVES:");
    println!("   - Plonky2: Native Goldilocks recursion support");
    println!("   - Miden VM: STARK-based VM with recursion primitives");
    println!("   - Use epoch accumulator (Phase 1) without true recursion");
    
    println!("\n6. RECOMMENDATION:");
    println!("   Phase 1 (Merkle accumulator) provides practical value.");
    println!("   True recursion requires significant engineering effort.");
    println!("   Consider Plonky2 migration for Phase 2c if needed.");
}
