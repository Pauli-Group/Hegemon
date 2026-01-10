#[derive(Default, Debug)]
pub struct SyncOutcome {
    pub commitments: usize,
    pub ciphertexts: usize,
    pub recovered: usize,
    pub spent: usize,
}
