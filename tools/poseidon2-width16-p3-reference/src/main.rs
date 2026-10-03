use p3_field::{InjectiveMonomial, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{default_goldilocks_poseidon2_16, Goldilocks as P3Goldilocks};
use p3_poseidon2::{
    ExternalLayer, ExternalLayerConstants, ExternalLayerConstructor, InternalLayer,
    InternalLayerConstructor, Poseidon2,
};
use p3_symmetric::Permutation;
use transaction_core::poseidon2_width16::{
    poseidon2_width16_compress14, poseidon2_width16_permutation, poseidon2_width16_sponge, Felt,
    Poseidon2Width16RoundConstants, POSEIDON2_WIDTH16_DIGEST,
    POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG, POSEIDON2_WIDTH16_RATE,
    POSEIDON2_WIDTH16_ROUND_CONSTANTS, POSEIDON2_WIDTH16_SPONGE_MODE_MARKER,
    POSEIDON2_WIDTH16_SUITE_MARKER,
};

const WIDTH: usize = 16;
const D: u64 = 7;
const COMPRESS_DOMAIN: u64 = 0x4845_475f_4d45_524b;
const HASH_DOMAIN: u64 = 0x4845_475f_4841_5348;

fn p3_external_linear(state: &mut [P3Goldilocks; WIDTH]) {
    const M4: [[u64; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    const P4: [[u64; 4]; 4] = [[2, 1, 1, 1], [1, 2, 1, 1], [1, 1, 2, 1], [1, 1, 1, 2]];
    let input = *state;
    for output_lane in 0..WIDTH {
        let outer_row = output_lane / 4;
        let inner_row = output_lane % 4;
        let mut value = P3Goldilocks::ZERO;
        for input_lane in 0..WIDTH {
            let outer_column = input_lane / 4;
            let inner_column = input_lane % 4;
            let coefficient = M4[outer_row][outer_column] * P4[inner_row][inner_column];
            value += input[input_lane] * P3Goldilocks::from_u64(coefficient);
        }
        state[output_lane] = value;
    }
}

fn p3_internal_linear(state: &mut [P3Goldilocks; WIDTH]) {
    let sum: P3Goldilocks = state.iter().copied().sum();
    for (lane, value) in state.iter_mut().enumerate() {
        *value =
            *value * P3Goldilocks::from_u64(POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG[lane]) + sum;
    }
}

#[derive(Clone)]
struct HardenedExternal {
    constants: ExternalLayerConstants<P3Goldilocks, WIDTH>,
}

impl ExternalLayerConstructor<P3Goldilocks, WIDTH> for HardenedExternal {
    fn new_from_constants(constants: ExternalLayerConstants<P3Goldilocks, WIDTH>) -> Self {
        Self { constants }
    }
}

fn p3_external_round(state: &mut [P3Goldilocks; WIDTH], constants: &[P3Goldilocks; WIDTH]) {
    for (value, constant) in state.iter_mut().zip(constants) {
        *value = (*value + *constant).injective_exp_n();
    }
    p3_external_linear(state);
}

impl ExternalLayer<P3Goldilocks, WIDTH, D> for HardenedExternal {
    fn permute_state_initial(&self, state: &mut [P3Goldilocks; WIDTH]) {
        p3_external_linear(state);
        for constants in self.constants.get_initial_constants() {
            p3_external_round(state, constants);
        }
    }

    fn permute_state_terminal(&self, state: &mut [P3Goldilocks; WIDTH]) {
        for constants in self.constants.get_terminal_constants() {
            p3_external_round(state, constants);
        }
    }
}

#[derive(Clone)]
struct HardenedInternal {
    constants: Vec<P3Goldilocks>,
}

impl InternalLayerConstructor<P3Goldilocks> for HardenedInternal {
    fn new_from_constants(constants: Vec<P3Goldilocks>) -> Self {
        Self { constants }
    }
}

impl InternalLayer<P3Goldilocks, WIDTH, D> for HardenedInternal {
    fn permute_state(&self, state: &mut [P3Goldilocks; WIDTH]) {
        for constant in &self.constants {
            state[0] = (state[0] + *constant).injective_exp_n();
            p3_internal_linear(state);
        }
    }
}

type HardenedP3 = Poseidon2<P3Goldilocks, HardenedExternal, HardenedInternal, WIDTH, D>;

fn p3_constants(
    constants: Poseidon2Width16RoundConstants,
) -> (
    ExternalLayerConstants<P3Goldilocks, WIDTH>,
    Vec<P3Goldilocks>,
) {
    let initial = constants
        .external_initial
        .map(|row| row.map(P3Goldilocks::from_u64))
        .to_vec();
    let terminal = constants
        .external_terminal
        .map(|row| row.map(P3Goldilocks::from_u64))
        .to_vec();
    let internal = constants.internal.map(P3Goldilocks::from_u64).to_vec();
    (ExternalLayerConstants::new(initial, terminal), internal)
}

fn hardened_p3() -> HardenedP3 {
    let (external, internal) = p3_constants(POSEIDON2_WIDTH16_ROUND_CONSTANTS);
    Poseidon2::new(external, internal)
}

fn p3_compress14(
    permutation: &HardenedP3,
    domain: u64,
    left: &[P3Goldilocks; 7],
    right: &[P3Goldilocks; 7],
) -> [P3Goldilocks; 7] {
    let mut state = [P3Goldilocks::ZERO; WIDTH];
    state[..7].copy_from_slice(left);
    state[7..14].copy_from_slice(right);
    state[14] = P3Goldilocks::from_u64(domain);
    state[15] = P3Goldilocks::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
    permutation.permute_mut(&mut state);
    state[..7].try_into().expect("seven output lanes")
}

fn p3_sponge(permutation: &HardenedP3, domain: u64, input: &[P3Goldilocks]) -> [P3Goldilocks; 7] {
    let mut state = [P3Goldilocks::ZERO; WIDTH];
    state[8] = P3Goldilocks::from_u64(domain);
    state[9] = P3Goldilocks::from_u64(input.len() as u64);
    state[10] = P3Goldilocks::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
    state[15] = P3Goldilocks::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
    let blocks = if input.is_empty() {
        1
    } else {
        input.len().div_ceil(POSEIDON2_WIDTH16_RATE)
    };
    for block in 0..blocks {
        let start = block * POSEIDON2_WIDTH16_RATE;
        let take = core::cmp::min(input.len().saturating_sub(start), POSEIDON2_WIDTH16_RATE);
        for lane in 0..take {
            state[lane] += input[start + lane];
        }
        if block + 1 == blocks {
            state[11] += P3Goldilocks::ONE;
        }
        permutation.permute_mut(&mut state);
    }
    state[..POSEIDON2_WIDTH16_DIGEST]
        .try_into()
        .expect("seven output lanes")
}

fn canonical_p3<const N: usize>(state: &[P3Goldilocks; N]) -> [u64; N] {
    state.map(|value| value.as_canonical_u64())
}

fn canonical_hegemon<const N: usize>(state: &[Felt; N]) -> [u64; N] {
    state.map(|value| value.as_canonical_u64())
}

fn main() {
    let reference = hardened_p3();
    for seed in [0u64, 1, 0x0123_4567_89ab_cdef] {
        let mut hegemon =
            core::array::from_fn(|lane| Felt::from_u64(seed.wrapping_add(lane as u64)));
        let mut p3 =
            core::array::from_fn(|lane| P3Goldilocks::from_u64(seed.wrapping_add(lane as u64)));
        poseidon2_width16_permutation(&mut hegemon);
        reference.permute_mut(&mut p3);
        assert_eq!(canonical_hegemon(&hegemon), canonical_p3(&p3));
    }

    let left_h = core::array::from_fn(|lane| Felt::from_u64(lane as u64));
    let right_h = core::array::from_fn(|lane| Felt::from_u64((lane + 7) as u64));
    let left_p = core::array::from_fn(|lane| P3Goldilocks::from_u64(lane as u64));
    let right_p = core::array::from_fn(|lane| P3Goldilocks::from_u64((lane + 7) as u64));
    let hegemon = poseidon2_width16_compress14(COMPRESS_DOMAIN, &left_h, &right_h);
    let p3 = p3_compress14(&reference, COMPRESS_DOMAIN, &left_p, &right_p);
    assert_eq!(canonical_hegemon(&hegemon), canonical_p3(&p3));

    for length in [0usize, 7, 8, 9, 16, 34, 120] {
        let hegemon_input = (0..length)
            .map(|value| Felt::from_u64(value as u64))
            .collect::<Vec<_>>();
        let p3_input = (0..length)
            .map(|value| P3Goldilocks::from_u64(value as u64))
            .collect::<Vec<_>>();
        let hegemon = poseidon2_width16_sponge(HASH_DOMAIN, &hegemon_input).unwrap();
        let p3 = p3_sponge(&reference, HASH_DOMAIN, &p3_input);
        assert_eq!(
            canonical_hegemon(&hegemon),
            canonical_p3(&p3),
            "p3 reference mismatch at length {length}"
        );
    }

    let mut hardened = core::array::from_fn(|lane| Felt::from_u64(lane as u64));
    poseidon2_width16_permutation(&mut hardened);
    let stock = default_goldilocks_poseidon2_16();
    let mut stock_state = core::array::from_fn(|lane| P3Goldilocks::from_u64(lane as u64));
    stock.permute_mut(&mut stock_state);
    assert_ne!(canonical_hegemon(&hardened), canonical_p3(&stock_state));

    println!(
        "poseidon2-width16-p3-reference: hardened KATs match; stock p3 negative control differs"
    );
}
