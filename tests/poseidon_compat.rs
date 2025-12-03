//! Test that pallet and circuit Poseidon implementations match.

use transaction_circuit::hashing::{merkle_node, Felt};

// Re-implement the pallet's Poseidon for comparison in a test context
mod pallet_poseidon {
    const POSEIDON_WIDTH: usize = 3;
    const POSEIDON_ROUNDS: usize = 8;
    const MERKLE_DOMAIN_TAG: u64 = 4;
    const FIELD_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;

    #[inline]
    fn round_constant(round: usize, position: usize) -> u64 {
        let seed = ((round as u64).wrapping_add(1).wrapping_mul(0x9e37_79b9u64))
            ^ ((position as u64).wrapping_add(1).wrapping_mul(0x7f4a_7c15u64));
        seed
    }

    #[inline]
    fn reduce(val: u128) -> u64 {
        (val % FIELD_MODULUS) as u64
    }

    #[inline]
    fn field_mul(a: u64, b: u64) -> u64 {
        reduce((a as u128) * (b as u128))
    }

    #[inline]
    fn field_add(a: u64, b: u64) -> u64 {
        reduce((a as u128) + (b as u128))
    }

    #[inline]
    fn field_exp5(x: u64) -> u64 {
        let x2 = field_mul(x, x);
        let x4 = field_mul(x2, x2);
        field_mul(x4, x)
    }

    fn mix(state: &mut [u64; POSEIDON_WIDTH]) {
        const MIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];
        let state_snapshot = *state;
        let mut tmp = [0u64; POSEIDON_WIDTH];
        for (row, output) in MIX.iter().zip(tmp.iter_mut()) {
            let mut acc = 0u64;
            for (&coef, &value) in row.iter().zip(state_snapshot.iter()) {
                acc = field_add(acc, field_mul(value, coef));
            }
            *output = acc;
        }
        *state = tmp;
    }

    fn permutation(state: &mut [u64; POSEIDON_WIDTH]) {
        for round in 0..POSEIDON_ROUNDS {
            for (position, value) in state.iter_mut().enumerate() {
                *value = field_add(*value, round_constant(round, position));
            }
            for value in state.iter_mut() {
                *value = field_exp5(*value);
            }
            mix(state);
        }
    }

    fn absorb(state: &mut [u64; POSEIDON_WIDTH], chunk: &[u64]) {
        for (state_slot, value) in state.iter_mut().zip(chunk.iter()) {
            *state_slot = field_add(*state_slot, *value);
        }
        permutation(state);
    }

    pub fn sponge(domain_tag: u64, inputs: &[u64]) -> u64 {
        let mut state = [domain_tag, 0, 1];
        let rate = POSEIDON_WIDTH - 1;
        let mut cursor = 0;
        while cursor < inputs.len() {
            let take = core::cmp::min(rate, inputs.len() - cursor);
            let mut chunk = [0u64; POSEIDON_WIDTH - 1];
            chunk[..take].copy_from_slice(&inputs[cursor..cursor + take]);
            absorb(&mut state, &chunk);
            cursor += take;
        }
        state[0]
    }

    pub fn merkle_node(left: u64, right: u64) -> u64 {
        sponge(MERKLE_DOMAIN_TAG, &[left, right])
    }
}

#[test]
fn poseidon_merkle_hash_matches() {
    // Test with zeros
    let circuit_result = merkle_node(Felt::new(0), Felt::new(0)).as_int();
    let pallet_result = pallet_poseidon::merkle_node(0, 0);
    println!("merkle_node(0, 0):");
    println!("  circuit: {}", circuit_result);
    println!("  pallet:  {}", pallet_result);
    assert_eq!(circuit_result, pallet_result, "merkle_node(0,0) mismatch");

    // Test with small values
    let circuit_result = merkle_node(Felt::new(1), Felt::new(2)).as_int();
    let pallet_result = pallet_poseidon::merkle_node(1, 2);
    println!("merkle_node(1, 2):");
    println!("  circuit: {}", circuit_result);
    println!("  pallet:  {}", pallet_result);
    assert_eq!(circuit_result, pallet_result, "merkle_node(1,2) mismatch");

    // Test with larger values
    let large1 = 12345678901234567890u64;
    let large2 = 9876543210987654321u64;
    let circuit_result = merkle_node(Felt::new(large1), Felt::new(large2)).as_int();
    let pallet_result = pallet_poseidon::merkle_node(large1, large2);
    println!("merkle_node(large1, large2):");
    println!("  circuit: {}", circuit_result);
    println!("  pallet:  {}", pallet_result);
    assert_eq!(circuit_result, pallet_result, "merkle_node(large) mismatch");
}

#[test]
fn poseidon_empty_tree_root_matches() {
    // Compute the empty tree root for depth 32
    // Empty leaf = 0, then hash(empty, empty) recursively
    let depth = 32;
    
    let mut circuit_current = Felt::new(0);
    let mut pallet_current = 0u64;
    
    for level in 0..depth {
        circuit_current = merkle_node(circuit_current, circuit_current);
        pallet_current = pallet_poseidon::merkle_node(pallet_current, pallet_current);
        
        if level < 5 || level == depth - 1 {
            println!("Level {} default:");
            println!("  circuit: {}", circuit_current.as_int());
            println!("  pallet:  {}", pallet_current);
        }
        assert_eq!(circuit_current.as_int(), pallet_current, "Level {} mismatch", level);
    }
    
    println!("Empty tree root (depth {}):", depth);
    println!("  circuit: {} (0x{:016x})", circuit_current.as_int(), circuit_current.as_int());
    println!("  pallet:  {} (0x{:016x})", pallet_current, pallet_current);
}
