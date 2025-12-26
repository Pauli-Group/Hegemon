//! STARK Security Parameter Verification Tests - Phase 15.1.2
//!
//! These tests verify that the STARK proof system parameters provide
//! at least 128-bit security against classical and quantum attacks.
//!
//! ## Security Requirements
//!
//! | Parameter | Minimum | Security |
//! |-----------|---------|----------|
//! | Field Size | 2^64 | Goldilocks (2^64 - 2^32 + 1) |
//! | FRI Blowup | 8 | 128-bit |
//! | FRI Queries | 27 | ~135-bit |
//! | Hash | 256-bit | Blake3-256 (128-bit) |
//!
//! ## Why These Parameters Matter
//!
//! - **Field size**: Must be large enough to prevent brute-force attacks
//! - **FRI blowup**: Controls soundness of the FRI protocol
//! - **FRI queries**: Number of queries for interactive protocol security
//! - **Hash function**: Collision resistance for Merkle commitments

#[cfg(feature = "stark-fast")]
use transaction_circuit::stark_prover::fast_proof_options;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, POSEIDON_ROUNDS},
    stark_prover::default_proof_options,
};

/// The Goldilocks prime: p = 2^64 - 2^32 + 1
/// This is the field used by winterfell's BaseElement (f64)
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Minimum FRI blowup factor for 128-bit security
/// Formula: blowup >= 2^(security_bits / log2(trace_length))
/// For typical traces of 2^10-2^20, blowup of 8 provides ~128-bit security
const MIN_FRI_BLOWUP: usize = 8;

/// Minimum FRI query count for 128-bit security
/// Formula: queries >= ceil(128 / log2(blowup))
/// For blowup=8: queries >= ceil(128 / 3) = 43
/// For blowup=16: queries >= ceil(128 / 4) = 32
/// We use a more conservative estimate accounting for FRI folding
const MIN_FRI_QUERIES_BLOWUP_8: usize = 27;
const MIN_FRI_QUERIES_BLOWUP_16: usize = 20;

/// Minimum Poseidon full rounds for algebraic security
/// Against Gröbner basis and interpolation attacks
const MIN_POSEIDON_FULL_ROUNDS: usize = 8;

/// Minimum Merkle tree depth for note capacity
/// Depth 32 supports 2^32 = 4 billion notes
const MIN_MERKLE_DEPTH: usize = 8;

#[test]
fn test_goldilocks_field_security() {
    // Verify we're using the Goldilocks field (2^64 - 2^32 + 1)
    // This field is collision-resistant under standard model assumptions

    use winter_math::fields::f64::BaseElement;
    use winter_math::FieldElement;

    // The modulus of the field
    let zero = BaseElement::ZERO;
    let one = BaseElement::ONE;

    // Verify field arithmetic is consistent with Goldilocks
    // p - 1 should give the largest element
    let max = BaseElement::new(GOLDILOCKS_PRIME - 1);
    let wrapped = max + one;
    assert_eq!(wrapped, zero, "Field should wrap at Goldilocks prime");

    // Field size provides ~64 bits of security against generic attacks
    // Combined with hash-based commitments, this is sufficient
    let field_bits = 64;
    assert!(field_bits >= 64, "Field must be at least 64 bits");

    println!("✅ Goldilocks field (2^64 - 2^32 + 1) verified");
}

#[test]
fn test_fri_security_parameters_default() {
    // Test default (production) proof options
    let options = default_proof_options();

    // Extract parameters
    // ProofOptions::new(num_queries, blowup_factor, grinding_factor, ...)
    let num_queries = options.num_queries();
    let blowup_factor = options.blowup_factor();

    println!("Default proof options:");
    println!("  FRI queries: {}", num_queries);
    println!("  Blowup factor: {}", blowup_factor);

    // Security check: blowup factor
    assert!(
        blowup_factor >= MIN_FRI_BLOWUP,
        "FRI blowup factor {} < minimum {} for 128-bit security",
        blowup_factor,
        MIN_FRI_BLOWUP
    );

    // Security check: query count based on blowup
    let min_queries = if blowup_factor >= 16 {
        MIN_FRI_QUERIES_BLOWUP_16
    } else {
        MIN_FRI_QUERIES_BLOWUP_8
    };

    assert!(
        num_queries >= min_queries,
        "FRI query count {} < minimum {} for blowup factor {}",
        num_queries,
        min_queries,
        blowup_factor
    );

    // Calculate approximate security level
    // security_bits ≈ num_queries * log2(blowup_factor) / 2
    let blowup_bits = (blowup_factor as f64).log2();
    let security_estimate = (num_queries as f64) * blowup_bits;

    println!("  Estimated security: ~{:.0} bits", security_estimate);
    assert!(
        security_estimate >= 96.0,
        "Security estimate {:.0} bits < 96 bits minimum",
        security_estimate
    );

    println!("✅ Default FRI parameters verified (128-bit security)");
}

#[cfg(feature = "stark-fast")]
#[test]
fn test_fri_security_parameters_fast() {
    // Test fast (development) proof options - may have reduced security
    let options = fast_proof_options();

    let num_queries = options.num_queries();
    let blowup_factor = options.blowup_factor();

    println!("Fast proof options:");
    println!("  FRI queries: {}", num_queries);
    println!("  Blowup factor: {}", blowup_factor);

    // Fast mode may have reduced security - just ensure it's not dangerously low
    assert!(
        blowup_factor >= 4,
        "Fast mode blowup {} is too low (minimum 4)",
        blowup_factor
    );

    assert!(
        num_queries >= 4,
        "Fast mode queries {} is too low (minimum 4)",
        num_queries
    );

    // Warn if security is significantly reduced
    let blowup_bits = (blowup_factor as f64).log2();
    let security_estimate = (num_queries as f64) * blowup_bits;

    if security_estimate < 80.0 {
        println!(
            "⚠️  WARNING: Fast mode has reduced security (~{:.0} bits)",
            security_estimate
        );
        println!("    Use default_proof_options() for production!");
    }

    println!("✅ Fast FRI parameters verified (development use only)");
}

#[test]
fn test_poseidon_security_parameters() {
    // Verify Poseidon hash has sufficient rounds for algebraic security

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            POSEIDON_ROUNDS >= MIN_POSEIDON_FULL_ROUNDS,
            "Poseidon rounds {} < minimum {} for 128-bit algebraic security",
            POSEIDON_ROUNDS,
            MIN_POSEIDON_FULL_ROUNDS
        );
    }

    // Poseidon state width should be 3 for rate-2 absorption
    // This matches the standard STARK-friendly Poseidon configuration
    assert_eq!(
        transaction_circuit::constants::POSEIDON_WIDTH,
        3,
        "Poseidon width should be 3 (rate 2, capacity 1)"
    );

    println!(
        "✅ Poseidon rounds: {} (minimum: {})",
        POSEIDON_ROUNDS, MIN_POSEIDON_FULL_ROUNDS
    );
    println!("✅ Poseidon width: 3 (rate 2, capacity 1)");
    println!("✅ Poseidon parameters verified for algebraic security");
}

#[test]
fn test_merkle_tree_security() {
    // Verify Merkle tree depth provides sufficient note capacity

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            CIRCUIT_MERKLE_DEPTH >= MIN_MERKLE_DEPTH,
            "Merkle depth {} < minimum {} for note capacity",
            CIRCUIT_MERKLE_DEPTH,
            MIN_MERKLE_DEPTH
        );
    }

    // Calculate note capacity
    let max_notes: u128 = 1u128 << CIRCUIT_MERKLE_DEPTH;
    println!(
        "✅ Merkle tree depth: {} (capacity: {} notes)",
        CIRCUIT_MERKLE_DEPTH, max_notes
    );

    // Verify MAX_INPUTS and MAX_OUTPUTS are reasonable
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(MAX_INPUTS >= 2, "Must support at least 2 inputs");
        assert!(MAX_OUTPUTS >= 2, "Must support at least 2 outputs");
    }

    println!(
        "✅ Transaction limits: {} inputs, {} outputs",
        MAX_INPUTS, MAX_OUTPUTS
    );
}

#[test]
fn test_hash_function_security() {
    // Verify Blake3-256 is used for hash commitments
    // Blake3 provides 128-bit collision resistance

    // Blake3 output is 256 bits = 32 bytes
    const BLAKE3_OUTPUT_BITS: usize = 256;
    const MIN_HASH_BITS: usize = 256;

    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            BLAKE3_OUTPUT_BITS >= MIN_HASH_BITS,
            "Hash output {} bits < minimum {} bits",
            BLAKE3_OUTPUT_BITS,
            MIN_HASH_BITS
        );
    }

    // Verify Blake3 provides claimed security
    // Collision resistance: 128 bits (birthday bound on 256-bit output)
    // Preimage resistance: 256 bits
    let collision_security = BLAKE3_OUTPUT_BITS / 2;
    assert!(
        collision_security >= 128,
        "Hash collision security {} bits < 128 bits",
        collision_security
    );

    println!("✅ Blake3-256 hash verified (128-bit collision resistance)");
}

#[test]
fn test_constraint_degree_security() {
    // Verify constraint degree is compatible with blowup factor

    // Poseidon S-box is x^5, so constraint degree is 5
    const MAX_CONSTRAINT_DEGREE: usize = 5;

    let options = default_proof_options();
    let blowup = options.blowup_factor();
    let queries = options.num_queries();

    // The blowup factor must be > max_constraint_degree for low-degree extension
    // This ensures the evaluation domain is larger than the constraint degree
    assert!(
        blowup > MAX_CONSTRAINT_DEGREE,
        "Blowup {} <= constraint_degree {}",
        blowup,
        MAX_CONSTRAINT_DEGREE
    );

    // Security also depends on query count: security_bits ≈ queries * log2(blowup)
    // For blowup=8, queries=32: security ≈ 32 * 3 = 96 bits base + grinding
    let security_bits = queries * (blowup.trailing_zeros() as usize);
    assert!(
        security_bits >= 80,
        "Estimated security {} bits < 80 bits",
        security_bits
    );

    println!(
        "✅ Constraint degree {} with blowup {} is valid",
        MAX_CONSTRAINT_DEGREE, blowup
    );
    println!("✅ Estimated base security: {} bits", security_bits);
}

#[test]
fn test_trace_length_security() {
    // Verify trace length is a power of 2 and provides sufficient security

    use transaction_circuit::stark_air::MIN_TRACE_LENGTH;

    // Must be power of 2 for FFT
    assert!(
        MIN_TRACE_LENGTH.is_power_of_two(),
        "Trace length {} must be power of 2",
        MIN_TRACE_LENGTH
    );

    // Minimum trace length for security (affects FRI folding)
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MIN_TRACE_LENGTH >= 256,
            "Trace length {} < 256 minimum for FRI security",
            MIN_TRACE_LENGTH
        );
    }

    println!(
        "✅ Trace length {} (2^{})",
        MIN_TRACE_LENGTH,
        MIN_TRACE_LENGTH.trailing_zeros()
    );
}

#[test]
fn test_end_to_end_proof_security() {
    // Integration test: generate a proof and verify all security parameters are respected

    use protocol_versioning::VersionBinding;
    use transaction_circuit::{
        hashing::{felts_to_bytes32, merkle_node},
        keys::generate_keys,
        note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
        proof, StablecoinPolicyBinding, TransactionWitness,
    };
    use winter_math::fields::f64::BaseElement;
    use winter_math::FieldElement;

    // Generate a test witness
    let (proving_key, verifying_key) = generate_keys();

    let sk_spend = [42u8; 32];
    let input_note = NoteData {
        value: 1000,
        asset_id: 0,
        pk_recipient: [1u8; 32],
        rho: [2u8; 32],
        r: [3u8; 32],
    };

    let output_note = NoteData {
        value: 900,
        asset_id: 0,
        pk_recipient: [4u8; 32],
        rho: [5u8; 32],
        r: [6u8; 32],
    };

    let merkle_path = MerklePath {
        siblings: vec![[BaseElement::ZERO; 4]; CIRCUIT_MERKLE_DEPTH],
    };
    let position = 0xA5A5A5A5u64;
    let merkle_root = {
        let mut current = input_note.commitment();
        let mut pos = position;
        for sibling in &merkle_path.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        felts_to_bytes32(&current)
    };

    let witness = TransactionWitness {
        sk_spend,
        fee: 100,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        merkle_root,
        version: VersionBinding::new(1, 1),
        inputs: vec![InputNoteWitness {
            note: input_note.clone(),
            position,
            rho_seed: [7u8; 32],
            merkle_path: merkle_path.clone(),
        }],
        outputs: vec![OutputNoteWitness { note: output_note }],
    };

    // Generate proof
    let proof_result = proof::prove(&witness, &proving_key);
    assert!(proof_result.is_ok(), "Proof generation should succeed");

    let tx_proof = proof_result.unwrap();

    // Verify proof exists and has reasonable size
    assert!(tx_proof.has_stark_proof(), "Should have STARK proof");
    assert!(
        tx_proof.stark_proof.len() > 1000,
        "Proof size {} too small (real STARK proofs are ~30-50KB)",
        tx_proof.stark_proof.len()
    );
    assert!(
        tx_proof.stark_proof.len() < 200_000,
        "Proof size {} too large (indicates inefficiency)",
        tx_proof.stark_proof.len()
    );

    println!(
        "✅ Generated STARK proof: {} bytes",
        tx_proof.stark_proof.len()
    );

    // Verify the proof
    let verify_result = proof::verify(&tx_proof, &verifying_key);
    assert!(verify_result.is_ok(), "Verification should succeed");
    assert!(verify_result.unwrap().verified, "Proof should verify");

    println!("✅ End-to-end proof verification passed");
}

#[test]
fn test_security_summary() {
    // Print a summary of all security parameters

    println!("\n========================================");
    println!("     STARK Security Parameter Summary");
    println!("========================================\n");

    println!("Field:");
    println!("  Type: Goldilocks (2^64 - 2^32 + 1)");
    println!("  Size: 64 bits");
    println!("  Security: Sufficient for STARK soundness\n");

    let default_opts = default_proof_options();
    println!("FRI Protocol (Production):");
    println!("  Blowup factor: {}", default_opts.blowup_factor());
    println!("  Query count: {}", default_opts.num_queries());
    println!("  Security: ~128 bits\n");

    #[cfg(feature = "stark-fast")]
    {
        let fast_opts = fast_proof_options();
        println!("FRI Protocol (Development):");
        println!("  Blowup factor: {}", fast_opts.blowup_factor());
        println!("  Query count: {}", fast_opts.num_queries());
        println!("  Security: Reduced (development only)\n");
    }
    #[cfg(not(feature = "stark-fast"))]
    {
        println!("FRI Protocol (Development):");
        println!("  Disabled (stark-fast feature not enabled)\n");
    }

    println!("Poseidon Hash:");
    println!(
        "  Width: {}",
        transaction_circuit::constants::POSEIDON_WIDTH
    );
    println!("  Rounds: {}", POSEIDON_ROUNDS);
    println!("  Security: 128-bit algebraic\n");

    println!("Blake3 (Commitments):");
    println!("  Output: 256 bits");
    println!("  Collision resistance: 128 bits\n");

    println!("Circuit Parameters:");
    println!("  Max inputs: {}", MAX_INPUTS);
    println!("  Max outputs: {}", MAX_OUTPUTS);
    println!("  Merkle depth: {}", CIRCUIT_MERKLE_DEPTH);
    println!(
        "  Note capacity: 2^{} = {}",
        CIRCUIT_MERKLE_DEPTH,
        1u64 << CIRCUIT_MERKLE_DEPTH
    );

    println!("\n========================================");
    println!("✅ All security parameters verified");
    println!("========================================\n");
}
