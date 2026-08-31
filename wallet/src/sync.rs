#[derive(Default, Debug)]
pub struct SyncOutcome {
    pub commitments: usize,
    pub ciphertexts: usize,
    pub recovered: usize,
    pub spent: usize,
    pub poseidon2_v8_blocks: usize,
    pub poseidon2_v8_commitments: usize,
    pub poseidon2_v8_ciphertexts: usize,
    pub poseidon2_v8_recovered: usize,
    pub poseidon2_v8_spent: usize,
    pub poseidon2_v8_detached_blocks: usize,
}
