//! Test that pallet and circuit Poseidon implementations match.

use transaction_circuit::hashing::{merkle_node_bytes, Commitment};

// Re-implement the pallet's Poseidon for comparison in a test context
mod pallet_poseidon {
    const POSEIDON_WIDTH: usize = 3;
    const POSEIDON_ROUNDS: usize = 8;
    const MERKLE_DOMAIN_TAG: u64 = 4;
    const FIELD_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;

    #[inline]
    fn round_constant(round: usize, position: usize) -> u64 {
        let seed = ((round as u64).wrapping_add(1).wrapping_mul(0x9e37_79b9u64))
            ^ ((position as u64)
                .wrapping_add(1)
                .wrapping_mul(0x7f4a_7c15u64));
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

    fn sponge_hash(domain_tag: u64, inputs: &[u64]) -> [u64; 4] {
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
        let mut out = [0u64; 4];
        out[0] = state[0];
        out[1] = state[1];
        permutation(&mut state);
        out[2] = state[0];
        out[3] = state[1];
        out
    }

    fn bytes32_to_limbs(bytes: &Commitment) -> [u64; 4] {
        let mut out = [0u64; 4];
        for (idx, chunk) in bytes.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            out[idx] = u64::from_be_bytes(buf);
        }
        out
    }

    pub fn limbs_to_bytes32(limbs: &[u64; 4]) -> Commitment {
        let mut out = [0u8; 32];
        for (idx, limb) in limbs.iter().enumerate() {
            let start = idx * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn merkle_node_bytes(left: &Commitment, right: &Commitment) -> Commitment {
        let left_limbs = bytes32_to_limbs(left);
        let right_limbs = bytes32_to_limbs(right);
        let mut inputs = Vec::with_capacity(8);
        inputs.extend_from_slice(&[
            left_limbs[2],
            left_limbs[3],
            left_limbs[0],
            left_limbs[1],
        ]);
        inputs.extend_from_slice(&[
            right_limbs[2],
            right_limbs[3],
            right_limbs[0],
            right_limbs[1],
        ]);
        let out = sponge_hash(MERKLE_DOMAIN_TAG, &inputs);
        limbs_to_bytes32(&out)
    }
}

#[test]
fn poseidon_merkle_hash_matches() {
    // Test with zeros
    let left = [0u8; 32];
    let right = [0u8; 32];
    let circuit_result = merkle_node_bytes(&left, &right).expect("canonical");
    let pallet_result = pallet_poseidon::merkle_node_bytes(&left, &right);
    println!("merkle_node(0, 0):");
    println!("  circuit: {}", hex::encode(circuit_result));
    println!("  pallet:  {}", hex::encode(pallet_result));
    assert_eq!(circuit_result, pallet_result, "merkle_node(0,0) mismatch");

    // Test with small values
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left[24..32].copy_from_slice(&1u64.to_be_bytes());
    right[24..32].copy_from_slice(&2u64.to_be_bytes());
    let circuit_result = merkle_node_bytes(&left, &right).expect("canonical");
    let pallet_result = pallet_poseidon::merkle_node_bytes(&left, &right);
    println!("merkle_node(1, 2):");
    println!("  circuit: {}", hex::encode(circuit_result));
    println!("  pallet:  {}", hex::encode(pallet_result));
    assert_eq!(circuit_result, pallet_result, "merkle_node(1,2) mismatch");

    // Test with larger values
    let large1 = [1u64, 2, 3, 4];
    let large2 = [5u64, 6, 7, 8];
    let left = pallet_poseidon::limbs_to_bytes32(&large1);
    let right = pallet_poseidon::limbs_to_bytes32(&large2);
    let circuit_result = merkle_node_bytes(&left, &right).expect("canonical");
    let pallet_result = pallet_poseidon::merkle_node_bytes(&left, &right);
    println!("merkle_node(large1, large2):");
    println!("  circuit: {}", hex::encode(circuit_result));
    println!("  pallet:  {}", hex::encode(pallet_result));
    assert_eq!(circuit_result, pallet_result, "merkle_node(large) mismatch");
}

#[test]
fn poseidon_empty_tree_root_matches() {
    // Compute the empty tree root for depth 32
    // Empty leaf = 0, then hash(empty, empty) recursively
    let depth = 32;

    let mut circuit_current = [0u8; 32];
    let mut pallet_current = [0u8; 32];

    for level in 0..depth {
        circuit_current =
            merkle_node_bytes(&circuit_current, &circuit_current).expect("canonical");
        pallet_current = pallet_poseidon::merkle_node_bytes(&pallet_current, &pallet_current);

        if level < 5 || level == depth - 1 {
            println!("Level {level} default:");
            println!("  circuit: {}", hex::encode(circuit_current));
            println!("  pallet:  {}", hex::encode(pallet_current));
        }
        assert_eq!(circuit_current, pallet_current, "Level {} mismatch", level);
    }

    println!("Empty tree root (depth {}):", depth);
    println!(
        "  circuit: {}",
        hex::encode(circuit_current)
    );
    println!("  pallet:  {}", hex::encode(pallet_current));
}
