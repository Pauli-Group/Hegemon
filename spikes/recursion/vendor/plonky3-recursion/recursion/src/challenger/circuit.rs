//! Circuit-based challenger implementation.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};

use crate::Target;
use crate::traits::RecursiveChallenger;

const GOLDILOCKS_ORDER_U64: u64 = 18446744069414584321;
const POSEIDON2_WIDTH: usize = 12;
const POSEIDON2_EXTERNAL_ROUNDS: usize = 4;
const POSEIDON2_INTERNAL_ROUNDS: usize = 22;

const INTERNAL_MATRIX_DIAG: [u64; POSEIDON2_WIDTH] = [
    0xc3b6c08e23ba9300,
    0xd84b5de94a324fb6,
    0x0d0c371c5b35b84f,
    0x7964f570e7188037,
    0x5daf18bbd996604b,
    0x6743bc47b9595257,
    0x5528b9362c59bb70,
    0xac45e25b7127b68b,
    0xa2077d7dfbb606b5,
    0xf3faac6faee378ae,
    0x0c6388b51545e883,
    0xd27dbb6944917b60,
];

const EXTERNAL_ROUND_CONSTANTS: [[[u64; POSEIDON2_WIDTH]; POSEIDON2_EXTERNAL_ROUNDS]; 2] = [
    [
        [
            0x7914ff869d09bdc3,
            0xb03ee00cfebfb05b,
            0x375eb98de727052d,
            0xdd8d1543e04114c3,
            0xfb0767ab77ed1f7a,
            0x542cc730c3972c50,
            0xa825a62cfe711418,
            0xe47f81105525816a,
            0xeb5c7dcde6c3738a,
            0x6b8104926185e10e,
            0xa06eee93a6045fb8,
            0xbd87e85188445457,
        ],
        [
            0xb1b6960dc01581f4,
            0x1115e21368af8891,
            0x14d94244202b4d15,
            0x92e83baa9d07f0ef,
            0x1966581757bdfb99,
            0x1902430824b960d7,
            0xcb327f95f40eaecd,
            0xe5fafddec3c17c1f,
            0x92421473488f71bd,
            0x2168f2b2f622ae51,
            0xd191e8bda72fe558,
            0x31ae6876405abab5,
        ],
        [
            0xf39272caff95caab,
            0x44bf5ad3597e99f6,
            0xcc2ba812e2327d54,
            0x6bd5380bf8ed35d8,
            0x8473d71f7750b0ba,
            0xea023aa925dee3a0,
            0xea08e2de3aa450e0,
            0xf49b8ee36da12b44,
            0x2ef5f3f207eba00c,
            0x827abbd7733372f4,
            0xf04714126b1385ab,
            0x37800dcceb8107e2,
        ],
        [
            0xe85ff87c7c8f77a6,
            0xb8268cefb3261610,
            0x14d0bb9f7604547f,
            0x788cf96ecb430dde,
            0x3cbe69615ba2e1d0,
            0x55ae1c01d4262c04,
            0x7429dc16119c28f6,
            0xcda93b327917418b,
            0x2497a9225c187b37,
            0x91ac79167a6f377e,
            0xa5effac16d7668a3,
            0xd78a26ce76d4d811,
        ],
    ],
    [
        [
            0x5e0497fa4c4f1682,
            0x547d0d0b9b99a7e3,
            0xd229d5678cced1de,
            0xc12e48a54ac5022e,
            0xc00d4ab46ef4d7b2,
            0xb4645340a95b0b6a,
            0xbb06f800d2bd2524,
            0x596b284ffd64c009,
            0x885736fcd5b663bf,
            0x7fbe08c4afe0a5cd,
            0x0c2b541d80c5d2aa,
            0x0685f06c8e1189d3,
        ],
        [
            0xbf0934418bc86dc0,
            0x345243ffbec349d4,
            0xa9332c45ff7c7d82,
            0xb8cc956e50dd0450,
            0xbfe62fe64e38ae9c,
            0x8583d2cd534f1b9b,
            0x04520d21cc10efed,
            0x99e81987be9932a3,
            0xf0d3a301a33955e0,
            0x5a5dbcbf1df5522b,
            0x0c13e879a2360261,
            0x094a1123513e9ba3,
        ],
        [
            0x858d9ad9c453649d,
            0xfdce777f1dbb0ff9,
            0x24194bbf7e6ee44f,
            0x15a6a88ce9f441a5,
            0x55a03ae2f62e843c,
            0x515c6e41f49d9b3d,
            0x431ba02861d0f884,
            0xeefd245429d11dd9,
            0x831f1811991a26a4,
            0x2269f8805c3d40c2,
            0x6c8a794a8943b2a9,
            0x2298bd8b15776de9,
        ],
        [
            0x959639a90173c751,
            0x65b6244a78e84c2b,
            0x8a04fc785b1407be,
            0x68e27a5a1cde026f,
            0xa408bb722d770889,
            0x804491c567e5f3d5,
            0xcbc7d07164231f8b,
            0x3441ffec6f80800d,
            0x190b7cc675a4192a,
            0x8944fdce36a23877,
            0xe2a24e1ce229fb4d,
            0xffcb89b9e9a6e223,
        ],
    ],
];

const INTERNAL_ROUND_CONSTANTS: [u64; POSEIDON2_INTERNAL_ROUNDS] = [
    0xc0929f33e2853d1b,
    0xd87c59fd9506f59c,
    0x9b8986da30c5661d,
    0xacb45c9caf8f9bab,
    0x4f64d87fd0164596,
    0x04bddf3342d684d9,
    0xcaa3498150fc3e3b,
    0x5ddd38a00e26563b,
    0x5105844dcef0279d,
    0x63f9e1ff40676ef7,
    0x64bb32f2134ce6ba,
    0xa2a96bba1042ab02,
    0x17f6c4815e81af65,
    0x6b49fe48b8e0cc07,
    0x2e5e3d70d8fe257d,
    0xd4bed28c49c172e9,
    0xcfb25a871027d329,
    0xb62ad38bb2bf0f3b,
    0xdfe40c70f2c288dc,
    0x2fbb65b92fa854d9,
    0xb0fe72a89100504b,
    0xfec87ab0375b5da0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengerMode {
    GoldilocksPoseidon2,
    Fallback,
}

pub trait ChallengerField: PrimeCharacteristicRing + ExtensionField<Self::Base> {
    type Base: PrimeField64;
}

impl<BF: PrimeField64 + BinomiallyExtendable<D>, const D: usize> ChallengerField
    for BinomialExtensionField<BF, D>
{
    type Base = BF;
}

/// Concrete challenger implementation for Fiat-Shamir operations in circuits.
pub struct CircuitChallenger<const RATE: usize> {
    /// Sponge state tracked over base-field coefficients represented as extension targets.
    state: Vec<Target>,
    /// Buffered coefficients waiting to be absorbed.
    input_buffer: Vec<Target>,
    /// Buffered squeezed coefficients.
    output_buffer: Vec<Target>,
    /// Selected challenger mode for the concrete field configuration.
    mode: Option<ChallengerMode>,
    /// Number of bits in the base field.
    base_field_bits: usize,
    /// Extension degree.
    extension_degree: usize,
    /// Width used by fallback mode.
    fallback_width: usize,
    /// Whether runtime constants/state were initialized.
    initialized: bool,
}

impl<const RATE: usize> CircuitChallenger<RATE> {
    /// Create a new circuit challenger with empty state.
    pub const fn new() -> Self {
        Self {
            state: Vec::new(),
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
            mode: None,
            base_field_bits: 0,
            extension_degree: 0,
            fallback_width: 0,
            initialized: false,
        }
    }

    fn detect_mode<BF: PrimeField64, F: ExtensionField<BF>>() -> ChallengerMode {
        if BF::ORDER_U64 == GOLDILOCKS_ORDER_U64 && F::DIMENSION == 2 && RATE == 6 {
            ChallengerMode::GoldilocksPoseidon2
        } else {
            ChallengerMode::Fallback
        }
    }

    fn ensure_initialized<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
    ) {
        if self.initialized {
            return;
        }
        let mode = Self::detect_mode::<BF, F>();
        let width = match mode {
            ChallengerMode::GoldilocksPoseidon2 => POSEIDON2_WIDTH,
            ChallengerMode::Fallback => core::cmp::max(RATE.saturating_mul(2), 4),
        };
        let zero = circuit.add_const(F::ZERO);
        self.state = vec![zero; width];
        self.mode = Some(mode);
        self.base_field_bits = BF::bits();
        self.extension_degree = F::DIMENSION;
        self.fallback_width = core::cmp::max(RATE.saturating_mul(2), 4);
        self.initialized = true;
    }

    fn decompose_to_base_coeffs<BF: PrimeField64, F: ExtensionField<BF>>(
        &self,
        circuit: &mut CircuitBuilder<F>,
        value: Target,
    ) -> Result<Vec<Target>, CircuitBuilderError> {
        if self.extension_degree == 1 {
            return Ok(vec![value]);
        }
        let total_bits = self.base_field_bits * self.extension_degree;
        let bits = circuit.decompose_to_bits::<BF>(value, total_bits)?;
        let mut coeffs = Vec::with_capacity(self.extension_degree);
        for idx in 0..self.extension_degree {
            let start = idx * self.base_field_bits;
            let end = start + self.base_field_bits;
            coeffs.push(circuit.reconstruct_index_from_bits::<BF>(&bits[start..end])?);
        }
        Ok(coeffs)
    }

    fn compose_from_base_coeffs<BF: PrimeField64, F: ExtensionField<BF>>(
        &self,
        circuit: &mut CircuitBuilder<F>,
        coeffs: &[Target],
    ) -> Target {
        if coeffs.len() == 1 {
            return coeffs[0];
        }
        let mut acc = circuit.add_const(F::ZERO);
        for (idx, coeff) in coeffs.iter().copied().enumerate() {
            let mut basis = vec![BF::ZERO; self.extension_degree];
            basis[idx] = BF::ONE;
            let basis_element = F::from_basis_coefficients_slice(&basis)
                .expect("basis size must match extension dimension");
            let basis_target = circuit.add_const(basis_element);
            let term = circuit.mul(coeff, basis_target);
            acc = circuit.add(acc, term);
        }
        acc
    }

    fn absorb_base_coeff<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>, coeff: Target) {
        self.output_buffer.clear();
        self.input_buffer.push(coeff);
        if self.input_buffer.len() == RATE {
            self.duplex(circuit);
        }
    }

    /// Observe a base-field value embedded in the extension field.
    pub fn observe_base<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        value: Target,
    ) -> Result<(), CircuitBuilderError> {
        self.ensure_initialized::<BF, F>(circuit);
        let coeffs = self.decompose_to_base_coeffs::<BF, F>(circuit, value)?;
        if coeffs.len() > 1 {
            for coeff in coeffs.iter().copied().skip(1) {
                circuit.assert_zero(coeff);
            }
        }
        self.absorb_base_coeff(circuit, coeffs[0]);
        Ok(())
    }

    /// Observe a slice of base-field values embedded in the extension field.
    pub fn observe_base_slice<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        values: &[Target],
    ) -> Result<(), CircuitBuilderError> {
        for &value in values {
            self.observe_base::<BF, F>(circuit, value)?;
        }
        Ok(())
    }

    /// Observe an algebra element by absorbing all base-field coefficients in order.
    pub fn observe_algebra<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        value: Target,
    ) -> Result<(), CircuitBuilderError> {
        self.ensure_initialized::<BF, F>(circuit);
        let coeffs = self.decompose_to_base_coeffs::<BF, F>(circuit, value)?;
        for coeff in coeffs {
            self.absorb_base_coeff(circuit, coeff);
        }
        Ok(())
    }

    /// Observe a slice of algebra elements by absorbing all coefficients in order.
    pub fn observe_algebra_slice<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        values: &[Target],
    ) -> Result<(), CircuitBuilderError> {
        for &value in values {
            self.observe_algebra::<BF, F>(circuit, value)?;
        }
        Ok(())
    }

    fn sample_base_value<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
    ) -> Target {
        self.ensure_initialized::<BF, F>(circuit);
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplex(circuit);
        }
        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty after duplex")
    }

    fn sample_algebra_internal<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
    ) -> Target {
        let mut coeffs = Vec::with_capacity(self.extension_degree);
        for _ in 0..self.extension_degree {
            coeffs.push(self.sample_base_value::<BF, F>(circuit));
        }
        self.compose_from_base_coeffs::<BF, F>(circuit, &coeffs)
    }

    fn sample_base_internal<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
    ) -> Target {
        self.sample_base_value::<BF, F>(circuit)
    }

    /// Sample a `bits`-bit value using native `sample_bits` semantics and return it as an internal target.
    pub fn sample_bits_public<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        bits: usize,
    ) -> Result<Target, CircuitBuilderError> {
        self.ensure_initialized::<BF, F>(circuit);
        if bits > self.base_field_bits {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: self.base_field_bits,
                n_bits: bits,
            });
        }
        let sampled_base = self.sample_base_value::<BF, F>(circuit);
        let sampled_bits = circuit.decompose_to_bits::<BF>(sampled_base, self.base_field_bits)?;
        circuit.reconstruct_index_from_bits::<BF>(&sampled_bits[..bits])
    }

    /// Check PoW witness bits using native base-field sampling semantics.
    pub fn check_witness_base<BF: PrimeField64, F: ExtensionField<BF>>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        witness_bits: usize,
        witness: Target,
    ) -> Result<(), CircuitBuilderError> {
        self.observe_base::<BF, F>(circuit, witness)?;
        let sampled_base = self.sample_base_internal::<BF, F>(circuit);
        let sampled_bits = circuit.decompose_to_bits::<BF>(sampled_base, self.base_field_bits)?;
        for bit in sampled_bits.into_iter().take(witness_bits) {
            circuit.assert_zero(bit);
        }
        Ok(())
    }

    fn duplex<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        debug_assert!(self.initialized, "challenger must be initialized");
        debug_assert!(self.input_buffer.len() <= RATE, "input buffer exceeds RATE");
        debug_assert!(RATE <= self.state.len(), "RATE must not exceed state width");

        for (idx, value) in self.input_buffer.drain(..).enumerate() {
            self.state[idx] = value;
        }

        match self.mode.expect("challenger mode must be initialized") {
            ChallengerMode::GoldilocksPoseidon2 => self.poseidon2_permute_goldilocks(circuit),
            ChallengerMode::Fallback => self.fallback_permute(circuit),
        }

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.state[..RATE]);
    }

    fn fallback_permute<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        let zero = circuit.add_const(F::ZERO);
        let mut sum = zero;
        for &value in &self.state {
            sum = circuit.add(sum, value);
        }

        for (idx, slot) in self.state.iter_mut().enumerate() {
            let c = circuit.alloc_const(F::from_u64((idx as u64) + 1), "fallback round const");
            let x = circuit.add(*slot, c);
            let x2 = circuit.mul(x, x);
            let x4 = circuit.mul(x2, x2);
            let x5 = circuit.mul(x4, x);
            *slot = circuit.add(x5, sum);
        }
    }

    fn sbox7<F: Field>(&self, circuit: &mut CircuitBuilder<F>, x: Target) -> Target {
        let x2 = circuit.mul(x, x);
        let x4 = circuit.mul(x2, x2);
        let x6 = circuit.mul(x4, x2);
        circuit.mul(x6, x)
    }

    fn apply_mds4<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>, values: &mut [Target; 4]) {
        let x0 = values[0];
        let x1 = values[1];
        let x2 = values[2];
        let x3 = values[3];

        let t01 = circuit.add(x0, x1);
        let t23 = circuit.add(x2, x3);
        let t0123 = circuit.add(t01, t23);
        let t01123 = circuit.add(t0123, x1);
        let t01233 = circuit.add(t0123, x3);

        let two_x0 = circuit.add(x0, x0);
        let two_x2 = circuit.add(x2, x2);
        values[3] = circuit.add(t01233, two_x0);
        values[1] = circuit.add(t01123, two_x2);
        values[0] = circuit.add(t01123, t01);
        values[2] = circuit.add(t01233, t23);
    }

    fn mds_light<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        for chunk_idx in 0..(POSEIDON2_WIDTH / 4) {
            let base = chunk_idx * 4;
            let mut chunk = [
                self.state[base],
                self.state[base + 1],
                self.state[base + 2],
                self.state[base + 3],
            ];
            self.apply_mds4(circuit, &mut chunk);
            self.state[base..base + 4].copy_from_slice(&chunk);
        }

        let zero = circuit.add_const(F::ZERO);
        let mut sums = [zero; 4];
        for (k, sum_slot) in sums.iter_mut().enumerate() {
            let mut acc = zero;
            let mut idx = k;
            while idx < POSEIDON2_WIDTH {
                acc = circuit.add(acc, self.state[idx]);
                idx += 4;
            }
            *sum_slot = acc;
        }

        for idx in 0..POSEIDON2_WIDTH {
            self.state[idx] = circuit.add(self.state[idx], sums[idx % 4]);
        }
    }

    fn matmul_internal<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        let mut sum = circuit.add_const(F::ZERO);
        for &value in &self.state {
            sum = circuit.add(sum, value);
        }

        for (idx, slot) in self.state.iter_mut().enumerate() {
            let diag = circuit.alloc_const(
                F::from_u64(INTERNAL_MATRIX_DIAG[idx]),
                "poseidon2 internal diag",
            );
            let scaled = circuit.mul(*slot, diag);
            *slot = circuit.add(scaled, sum);
        }
    }

    fn external_round<F: Field>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        side: usize,
        round: usize,
    ) {
        for idx in 0..POSEIDON2_WIDTH {
            let rc = circuit.alloc_const(
                F::from_u64(EXTERNAL_ROUND_CONSTANTS[side][round][idx]),
                "poseidon2 external rc",
            );
            let shifted = circuit.add(self.state[idx], rc);
            self.state[idx] = self.sbox7(circuit, shifted);
        }
        self.mds_light(circuit);
    }

    fn internal_round<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>, round: usize) {
        let rc = circuit.alloc_const(
            F::from_u64(INTERNAL_ROUND_CONSTANTS[round]),
            "poseidon2 internal rc",
        );
        let shifted = circuit.add(self.state[0], rc);
        self.state[0] = self.sbox7(circuit, shifted);
        self.matmul_internal(circuit);
    }

    fn poseidon2_permute_goldilocks<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        debug_assert_eq!(self.state.len(), POSEIDON2_WIDTH, "unexpected state width");
        self.mds_light(circuit);
        for round in 0..POSEIDON2_EXTERNAL_ROUNDS {
            self.external_round(circuit, 0, round);
        }
        for round in 0..POSEIDON2_INTERNAL_ROUNDS {
            self.internal_round(circuit, round);
        }
        for round in 0..POSEIDON2_EXTERNAL_ROUNDS {
            self.external_round(circuit, 1, round);
        }
    }
}

impl<const RATE: usize> Default for CircuitChallenger<RATE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F, const RATE: usize> RecursiveChallenger<F> for CircuitChallenger<RATE>
where
    F: ChallengerField,
{
    fn observe(&mut self, circuit: &mut CircuitBuilder<F>, value: Target) {
        self.observe_base::<<F as ChallengerField>::Base, F>(circuit, value)
            .expect("failed to observe base value in circuit challenger");
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        self.sample_algebra_internal::<<F as ChallengerField>::Base, F>(circuit)
    }

    fn clear(&mut self) {
        self.state.clear();
        self.input_buffer.clear();
        self.output_buffer.clear();
        self.mode = None;
        self.base_field_bits = 0;
        self.extension_degree = 0;
        self.fallback_width = 0;
        self.initialized = false;
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;

    use super::*;

    type Challenge = p3_field::extension::BinomialExtensionField<Goldilocks, 2>;

    const DEFAULT_CHALLENGER_RATE: usize = 6;

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let val1 = circuit.add_const(Challenge::from(Goldilocks::ONE));
        let val2 = circuit.add_const(Challenge::from(Goldilocks::TWO));
        challenger.observe(&mut circuit, val1);
        challenger.observe(&mut circuit, val2);

        let challenge = challenger.sample(&mut circuit);
        assert!(challenge.0 > 0);
    }

    #[test]
    fn test_circuit_challenger_sample_vec() {
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let challenges = challenger.sample_vec(&mut circuit, 3);
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_circuit_challenger_clear() {
        let mut circuit = CircuitBuilder::<Challenge>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let val = circuit.add_const(Challenge::from(Goldilocks::ONE));
        RecursiveChallenger::<Challenge>::observe(&mut challenger, &mut circuit, val);

        assert!(challenger.initialized);
        assert!(!challenger.input_buffer.is_empty() || !challenger.output_buffer.is_empty());

        RecursiveChallenger::<Challenge>::clear(&mut challenger);

        assert!(!challenger.initialized);
        assert!(challenger.state.is_empty());
        assert!(challenger.input_buffer.is_empty());
        assert!(challenger.output_buffer.is_empty());
    }
}
