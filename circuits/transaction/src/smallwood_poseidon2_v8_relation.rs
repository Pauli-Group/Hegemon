//! Packed additive relation material for the Poseidon2 V8 stablecoin state model.
//!
//! Historical width-12 relations do not import this module.  It prepares the
//! exact 120-word V8 public surface, the complete 55-field private config, the
//! shared before/after path, the fixed nineteen-call Poseidon2 schedule, and a
//! compact SIMD helper layout.  The executable compiler consumes every family below, while
//! production authorization remains exclusively owned by protocol versioning.

use blake3::Hasher;
use transaction_core::{
    poseidon2_width16::{
        poseidon2_width16_step_ring, Felt, POSEIDON2_WIDTH16_DIGEST, POSEIDON2_WIDTH16_STEPS,
        POSEIDON2_WIDTH16_SUITE_MARKER, POSEIDON2_WIDTH16_WIDTH,
    },
    stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_config_digest, stablecoin_poseidon2_v8_issuer_authorization,
        stablecoin_poseidon2_v8_issuer_commitment, stablecoin_poseidon2_v8_leaf,
        verify_stablecoin_transition_v8, StablecoinPoseidon2V8Context, StablecoinPoseidon2V8Digest,
        StablecoinPoseidon2V8Direction, StablecoinPoseidon2V8Error, StablecoinPoseidon2V8Public,
        StablecoinPoseidon2V8Witness, STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS,
        STABLECOIN_POSEIDON2_V8_BASE_PUBLIC_FIELDS, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF, STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0,
        STABLECOIN_POSEIDON2_V8_MAX_SCALAR, STABLECOIN_POSEIDON2_V8_MAX_VALUE,
        STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM, STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS,
        STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS,
    },
};

pub const SMALLWOOD_POSEIDON2_V8_RELATION_ID: &str =
    "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v3";
pub const SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR: usize = 64;
/// Base rows before the fixed 39-row stablecoin tail.  The 647-row base uses
/// the canonical one-permutation `poseidon2_width16_compress14` Merkle node
/// and therefore needs two, not three, 64-lane Poseidon2 groups.
pub const SMALLWOOD_POSEIDON2_V8_BASE_RELATION_ROWS: usize = 647;
pub const SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_FIELDS: usize = 94;
pub const SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_ROWS: usize = 2;
pub const SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS: usize = 21;
pub const SMALLWOOD_POSEIDON2_V8_ROLE_ROWS: usize = POSEIDON2_WIDTH16_DIGEST + 2;
pub const SMALLWOOD_POSEIDON2_V8_BOOLEAN_ROWS: usize = 1;
pub const SMALLWOOD_POSEIDON2_V8_NUMERIC_AUX_ROWS: usize = 1;
pub const SMALLWOOD_POSEIDON2_V8_MUL_ROWS: usize = 3;
pub const SMALLWOOD_POSEIDON2_V8_RANGE_DIGIT_SLOTS: usize = 1_434;
pub const SMALLWOOD_POSEIDON2_V8_RANGE_ROWS: usize =
    SMALLWOOD_POSEIDON2_V8_RANGE_DIGIT_SLOTS.div_ceil(SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR);
pub const SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS: usize =
    SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_ROWS
        + SMALLWOOD_POSEIDON2_V8_ROLE_ROWS
        + SMALLWOOD_POSEIDON2_V8_BOOLEAN_ROWS
        + SMALLWOOD_POSEIDON2_V8_NUMERIC_AUX_ROWS
        + SMALLWOOD_POSEIDON2_V8_MUL_ROWS
        + SMALLWOOD_POSEIDON2_V8_RANGE_ROWS;
pub const SMALLWOOD_POSEIDON2_V8_RELATION_ROWS: usize =
    SMALLWOOD_POSEIDON2_V8_BASE_RELATION_ROWS + SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS;
/// Source-level compiler readiness evidence. This is not a production-authorization seam.
pub const SMALLWOOD_POSEIDON2_V8_COMPILER_COMPLETE: bool = true;

const SOURCE_ROW_0: usize = 0;
const SOURCE_ROW_1: usize = 1;
const ROLE_DIFF_ROW_0: usize = 2;
const ROLE_SELECTOR_ROW: usize = ROLE_DIFF_ROW_0 + POSEIDON2_WIDTH16_DIGEST;
const ROLE_INVERSE_ROW: usize = ROLE_SELECTOR_ROW + 1;
const BOOLEAN_ROW: usize = ROLE_INVERSE_ROW + 1;
const NUMERIC_AUX_ROW: usize = BOOLEAN_ROW + 1;
const MUL_A_ROW: usize = NUMERIC_AUX_ROW + 1;
const MUL_B_ROW: usize = MUL_A_ROW + 1;
const MUL_C_ROW: usize = MUL_B_ROW + 1;
const RANGE_ROW_0: usize = MUL_C_ROW + 1;

const RANGE_BITS_U32: usize = 32;
const RANGE_BITS_U63: usize = 63;
const RANGE_BITS_EPOCH: usize = 51;
const RANGE_BITS_VALUE: usize = 56;
const RANGE_BITS_EPOCH_REMAINDER: usize = 12;
const RANGE_BITS_ASSET_QUOTIENT: usize = 28;
const LIMB_BASE: u64 = 1u64 << 32;
const LIMB_MASK: u64 = LIMB_BASE - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8CompressionCall {
    pub domain_tag: u64,
    pub left: StablecoinPoseidon2V8Digest,
    pub right: StablecoinPoseidon2V8Digest,
    pub output: StablecoinPoseidon2V8Digest,
    pub states: [[u64; POSEIDON2_WIDTH16_WIDTH]; POSEIDON2_WIDTH16_STEPS + 1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8RelationMaterial {
    pub rows: Vec<[u64; SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR]>,
    pub poseidon_calls: Vec<SmallwoodPoseidon2V8CompressionCall>,
    pub range_bit_widths: Vec<u8>,
    pub profile_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8RelationError {
    Semantic(StablecoinPoseidon2V8Error),
    ArithmeticOverflow,
    RangeOverflow,
    WrongRowCount,
    MaterialMismatch,
}

impl From<StablecoinPoseidon2V8Error> for SmallwoodPoseidon2V8RelationError {
    fn from(error: StablecoinPoseidon2V8Error) -> Self {
        Self::Semantic(error)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Mul3Limbs {
    x0: u64,
    x1: u64,
    p0: u64,
    p1: u64,
    p2: u64,
    c0: u64,
    out: [u64; 4],
    c1: u64,
    c2: u64,
}

impl Mul3Limbs {
    fn build(x: u64, y: u32, z: u32) -> Self {
        let x0 = x & LIMB_MASK;
        let x1 = x >> 32;
        let first = u128::from(x) * u128::from(y);
        let p0 = (first & u128::from(LIMB_MASK)) as u64;
        let p1 = ((first >> 32) & u128::from(LIMB_MASK)) as u64;
        let p2 = ((first >> 64) & u128::from(LIMB_MASK)) as u64;
        let c0 = ((u128::from(x0) * u128::from(y)) >> 32) as u64;
        let second = first * u128::from(z);
        let out =
            core::array::from_fn(|index| ((second >> (32 * index)) & u128::from(LIMB_MASK)) as u64);
        let c1 = ((u128::from(p0) * u128::from(z)) >> 32) as u64;
        let c2 = ((u128::from(p1) * u128::from(z) + u128::from(c1)) >> 32) as u64;
        Self {
            x0,
            x1,
            p0,
            p1,
            p2,
            c0,
            out,
            c1,
            c2,
        }
    }

    fn range_values(self) -> [u64; 12] {
        [
            self.x0,
            self.x1,
            self.p0,
            self.p1,
            self.p2,
            self.c0,
            self.out[0],
            self.out[1],
            self.out[2],
            self.out[3],
            self.c1,
            self.c2,
        ]
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct CollateralAux {
    left: Mul3Limbs,
    right: Mul3Limbs,
    diff: [u64; 4],
    borrows: [u64; 4],
}

impl CollateralAux {
    fn build(
        collateral_amount: u64,
        price_numerator: u32,
        debt: u64,
        price_denominator: u32,
        ratio_ppm: u32,
    ) -> Result<Self, SmallwoodPoseidon2V8RelationError> {
        let left = Mul3Limbs::build(
            collateral_amount,
            price_numerator,
            STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM as u32,
        );
        let right = Mul3Limbs::build(debt, price_denominator, ratio_ppm);
        let mut diff = [0u64; 4];
        let mut borrows = [0u64; 4];
        let mut borrow = 0u64;
        for index in 0..4 {
            let subtrahend = right.out[index] + borrow;
            if left.out[index] >= subtrahend {
                diff[index] = left.out[index] - subtrahend;
                borrow = 0;
            } else {
                diff[index] = LIMB_BASE + left.out[index] - subtrahend;
                borrow = 1;
            }
            borrows[index] = borrow;
        }
        if borrow != 0 {
            return Err(SmallwoodPoseidon2V8RelationError::ArithmeticOverflow);
        }
        Ok(Self {
            left,
            right,
            diff,
            borrows,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct RelationAux {
    path_bits: [u64; 4],
    path_quotient: u64,
    same_epoch: u64,
    decimal_bits: [u64; 5],
    decimal_slack_bits: [u64; 5],
    decimal_accumulators: [u64; 5],
    enabled_age: u64,
    retirement_order_gap: u64,
    retirement_height_gap: u64,
    oracle_age: u64,
    oracle_slack: u64,
    attestation_age: u64,
    attestation_slack: u64,
    ratio_slack: u64,
    before_cap_slack: u64,
    after_cap_slack: u64,
    epoch_gap: u64,
    epoch_remainder: u64,
    time_carries: [u64; 7],
    collateral: CollateralAux,
}

fn snapshot(state: &[Felt; POSEIDON2_WIDTH16_WIDTH]) -> [u64; POSEIDON2_WIDTH16_WIDTH] {
    state.map(|value| value.as_canonical_u64())
}

fn compression_call(
    domain_tag: u64,
    left: StablecoinPoseidon2V8Digest,
    right: StablecoinPoseidon2V8Digest,
) -> SmallwoodPoseidon2V8CompressionCall {
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH];
    state[..POSEIDON2_WIDTH16_DIGEST].copy_from_slice(&left);
    state[POSEIDON2_WIDTH16_DIGEST..2 * POSEIDON2_WIDTH16_DIGEST].copy_from_slice(&right);
    state[14] = Felt::from_u64(domain_tag);
    state[15] = Felt::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
    let mut states = [[0u64; POSEIDON2_WIDTH16_WIDTH]; POSEIDON2_WIDTH16_STEPS + 1];
    states[0] = snapshot(&state);
    for step in 0..POSEIDON2_WIDTH16_STEPS {
        poseidon2_width16_step_ring(&mut state, step);
        states[step + 1] = snapshot(&state);
    }
    let mut output = [Felt::ZERO; POSEIDON2_WIDTH16_DIGEST];
    output.copy_from_slice(&state[..POSEIDON2_WIDTH16_DIGEST]);
    SmallwoodPoseidon2V8CompressionCall {
        domain_tag,
        left,
        right,
        output,
        states,
    }
}

fn poseidon_calls(
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
) -> Vec<SmallwoodPoseidon2V8CompressionCall> {
    let mut calls = Vec::with_capacity(STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS);
    let fields = witness.config.to_fields();
    let chunk_domains = [
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
    ];
    let mut chunk_digests = [[Felt::ZERO; 7]; 4];
    for chunk in 0..4 {
        let mut left = [Felt::ZERO; 7];
        let mut right = [Felt::ZERO; 7];
        for lane in 0..7 {
            let left_index = chunk * 14 + lane;
            let right_index = chunk * 14 + 7 + lane;
            if left_index < fields.len() {
                left[lane] = fields[left_index];
            }
            if right_index < fields.len() {
                right[lane] = fields[right_index];
            }
        }
        let call = compression_call(chunk_domains[chunk], left, right);
        chunk_digests[chunk] = call.output;
        calls.push(call);
    }
    let left_call = compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0,
        chunk_digests[0],
        chunk_digests[1],
    );
    let left_digest = left_call.output;
    calls.push(left_call);
    let right_call = compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
        chunk_digests[2],
        chunk_digests[3],
    );
    let right_digest = right_call.output;
    calls.push(right_call);
    let root_call = compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
        left_digest,
        right_digest,
    );
    let config_digest = root_call.output;
    calls.push(root_call);

    let index = public.asset_id & 15;
    let before_right = [
        Felt::from_u64(witness.before.epoch_id),
        Felt::from_u64(witness.before.minted_in_epoch),
        Felt::from_u64(witness.before.total_debt),
        Felt::from_u64(witness.before.sequence),
        Felt::from_u64(index as u64),
        Felt::ZERO,
        Felt::ZERO,
    ];
    let before_leaf_call = compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        config_digest,
        before_right,
    );
    let mut before_node = before_leaf_call.output;
    calls.push(before_leaf_call);
    let after_right = [
        Felt::from_u64(public.after.epoch_id),
        Felt::from_u64(public.after.minted_in_epoch),
        Felt::from_u64(public.after.total_debt),
        Felt::from_u64(public.after.sequence),
        Felt::from_u64(index as u64),
        Felt::ZERO,
        Felt::ZERO,
    ];
    let after_leaf_call = compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        config_digest,
        after_right,
    );
    let mut after_node = after_leaf_call.output;
    calls.push(after_leaf_call);
    let mut cursor = index as usize;
    for (level, sibling) in witness.siblings.iter().copied().enumerate() {
        let domain = STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0 + level as u64;
        let before_call = if cursor & 1 == 0 {
            compression_call(domain, before_node, sibling)
        } else {
            compression_call(domain, sibling, before_node)
        };
        before_node = before_call.output;
        calls.push(before_call);
        let after_call = if cursor & 1 == 0 {
            compression_call(domain, after_node, sibling)
        } else {
            compression_call(domain, sibling, after_node)
        };
        after_node = after_call.output;
        calls.push(after_call);
        cursor >>= 1;
    }
    let issuer_right = [
        Felt::from_u64(public.asset_id as u64),
        Felt::from_u64(public.policy_version as u64),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    calls.push(compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
        witness.issuer_secret,
        issuer_right,
    ));
    calls.push(compression_call(
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
        witness.issuer_secret,
        public.action_intent,
    ));
    debug_assert_eq!(calls.len(), STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS);
    calls
}

fn checked_sub(left: u64, right: u64) -> Result<u64, SmallwoodPoseidon2V8RelationError> {
    left.checked_sub(right)
        .ok_or(SmallwoodPoseidon2V8RelationError::ArithmeticOverflow)
}

fn build_aux(
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
) -> Result<RelationAux, SmallwoodPoseidon2V8RelationError> {
    if public.direction == StablecoinPoseidon2V8Direction::Disabled {
        return Ok(RelationAux {
            // The zero-test and decimal-product lanes are unconditional identities.  Their
            // canonical disabled witnesses are therefore one, not the derived-helper default.
            same_epoch: 1,
            decimal_accumulators: [1; 5],
            ..RelationAux::default()
        });
    }
    let config = witness.config;
    let current_epoch = public.parent_height >> 12;
    let mut decimal_bits = [0u64; 5];
    let mut decimal_slack_bits = [0u64; 5];
    let decimal_slack = 18u64
        .checked_sub(config.collateral_decimals as u64)
        .ok_or(SmallwoodPoseidon2V8RelationError::ArithmeticOverflow)?;
    for bit in 0..5 {
        decimal_bits[bit] = ((config.collateral_decimals as u64) >> bit) & 1;
        decimal_slack_bits[bit] = (decimal_slack >> bit) & 1;
    }
    let powers = [10u64, 100, 10_000, 100_000_000, 10_000_000_000_000_000];
    let mut accumulator = 1u64;
    let mut decimal_accumulators = [0u64; 5];
    for bit in 0..5 {
        if decimal_bits[bit] == 1 {
            accumulator = accumulator
                .checked_mul(powers[bit])
                .ok_or(SmallwoodPoseidon2V8RelationError::ArithmeticOverflow)?;
        }
        decimal_accumulators[bit] = accumulator;
    }
    let mint = public.direction == StablecoinPoseidon2V8Direction::Mint;
    let (
        enabled_age,
        retirement_order_gap,
        retirement_height_gap,
        oracle_age,
        oracle_slack,
        attestation_age,
        attestation_slack,
        ratio_slack,
        collateral,
    ) = if mint {
        let enabled_age = checked_sub(public.parent_height, config.enabled_at)?;
        let (retirement_order_gap, retirement_height_gap) = match config.retired_at {
            Some(retired_at) => (
                checked_sub(checked_sub(retired_at, config.enabled_at)?, 1)?,
                checked_sub(checked_sub(retired_at, public.parent_height)?, 1)?,
            ),
            None => (0, 0),
        };
        let oracle_age = checked_sub(public.parent_height, config.oracle_submitted_at)?;
        let oracle_slack = checked_sub(config.oracle_max_age, oracle_age)?;
        let attestation_age = checked_sub(public.parent_height, config.attestation_created_at)?;
        let attestation_slack = checked_sub(config.attestation_max_age, attestation_age)?;
        let ratio_slack = checked_sub(
            config.min_collateral_ratio_ppm as u64,
            STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM,
        )?;
        let collateral = CollateralAux::build(
            config.collateral_amount,
            config.oracle_price_numerator,
            public.after.total_debt,
            config.oracle_price_denominator,
            config.min_collateral_ratio_ppm,
        )?;
        (
            enabled_age,
            retirement_order_gap,
            retirement_height_gap,
            oracle_age,
            oracle_slack,
            attestation_age,
            attestation_slack,
            ratio_slack,
            collateral,
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0, 0, CollateralAux::default())
    };
    Ok(RelationAux {
        path_bits: core::array::from_fn(|bit| ((public.asset_id as u64) >> bit) & 1),
        path_quotient: (public.asset_id as u64) >> 4,
        same_epoch: u64::from(witness.before.epoch_id == current_epoch),
        decimal_bits,
        decimal_slack_bits,
        decimal_accumulators,
        enabled_age,
        retirement_order_gap,
        retirement_height_gap,
        oracle_age,
        oracle_slack,
        attestation_age,
        attestation_slack,
        ratio_slack,
        before_cap_slack: checked_sub(config.max_mint_per_epoch, witness.before.minted_in_epoch)?,
        after_cap_slack: checked_sub(config.max_mint_per_epoch, public.after.minted_in_epoch)?,
        epoch_gap: checked_sub(current_epoch, witness.before.epoch_id)?,
        epoch_remainder: public.parent_height - (current_epoch << 12),
        time_carries: if mint {
            [
                (((config.enabled_at & LIMB_MASK) + (enabled_age & LIMB_MASK)) >> 32) & 1,
                if config.retired_at.is_some() {
                    (((config.enabled_at & LIMB_MASK) + 1 + (retirement_order_gap & LIMB_MASK))
                        >> 32)
                        & 1
                } else {
                    0
                },
                if config.retired_at.is_some() {
                    (((public.parent_height & LIMB_MASK) + 1 + (retirement_height_gap & LIMB_MASK))
                        >> 32)
                        & 1
                } else {
                    0
                },
                (((config.oracle_submitted_at & LIMB_MASK) + (oracle_age & LIMB_MASK)) >> 32) & 1,
                (((oracle_age & LIMB_MASK) + (oracle_slack & LIMB_MASK)) >> 32) & 1,
                (((config.attestation_created_at & LIMB_MASK) + (attestation_age & LIMB_MASK))
                    >> 32)
                    & 1,
                (((attestation_age & LIMB_MASK) + (attestation_slack & LIMB_MASK)) >> 32) & 1,
            ]
        } else {
            [0; 7]
        },
        collateral,
    })
}

fn source_fields(
    witness: StablecoinPoseidon2V8Witness,
) -> [u64; SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_FIELDS] {
    let mut source = [0u64; SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_FIELDS];
    let mut cursor = 0usize;
    for value in witness.config.to_fields() {
        source[cursor] = value.as_canonical_u64();
        cursor += 1;
    }
    for sibling in witness.siblings {
        for value in sibling {
            source[cursor] = value.as_canonical_u64();
            cursor += 1;
        }
    }
    for value in witness.issuer_secret {
        source[cursor] = value.as_canonical_u64();
        cursor += 1;
    }
    for value in [
        witness.before.epoch_id,
        witness.before.minted_in_epoch,
        witness.before.total_debt,
        witness.before.sequence,
    ] {
        source[cursor] = value;
        cursor += 1;
    }
    debug_assert_eq!(cursor, source.len());
    source
}

fn role_differences(
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
) -> [[Felt; POSEIDON2_WIDTH16_DIGEST]; SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS] {
    let unit = [
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    if public.direction == StablecoinPoseidon2V8Direction::Disabled {
        return [unit; SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS];
    }
    let commitments = [
        witness.config.issuer_commitment,
        witness.config.policy_admin_commitment,
        witness.config.oracle_authority_commitment,
        witness.config.attestation_authority_commitment,
        witness.config.locked_collateral_commitment,
    ];
    let mut out = [[Felt::ZERO; POSEIDON2_WIDTH16_DIGEST]; SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS];
    out[..5].copy_from_slice(&commitments);
    let mut cursor = 5;
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            out[cursor] =
                core::array::from_fn(|limb| commitments[left][limb] - commitments[right][limb]);
            cursor += 1;
        }
    }
    out[cursor] = if public.direction == StablecoinPoseidon2V8Direction::Mint {
        witness.issuer_secret
    } else {
        unit
    };
    cursor += 1;
    out[cursor] = [
        Felt::from_u64(public.magnitude),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    cursor += 1;
    out[cursor] = if public.direction == StablecoinPoseidon2V8Direction::Mint {
        [
            Felt::from_u64(witness.config.oracle_price_numerator as u64),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]
    } else {
        unit
    };
    cursor += 1;
    out[cursor] = if public.direction == StablecoinPoseidon2V8Direction::Mint {
        [
            Felt::from_u64(witness.config.oracle_price_denominator as u64),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]
    } else {
        unit
    };
    cursor += 1;
    out[cursor] = [
        Felt::from_u64(public.asset_id as u64),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    cursor += 1;
    out[cursor] = public.action_intent;
    debug_assert_eq!(cursor + 1, out.len());
    out
}

fn range_digit_count(bits: u8) -> usize {
    usize::from(bits) / 2
}

fn push_range(
    values: &mut Vec<(u64, u8)>,
    value: u64,
    bits: usize,
) -> Result<(), SmallwoodPoseidon2V8RelationError> {
    if bits < 64 && value >= (1u64 << bits) {
        return Err(SmallwoodPoseidon2V8RelationError::RangeOverflow);
    }
    values.push((value, bits as u8));
    Ok(())
}

fn range_values(
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
    aux: &RelationAux,
) -> Result<Vec<(u64, u8)>, SmallwoodPoseidon2V8RelationError> {
    debug_assert_eq!(STABLECOIN_POSEIDON2_V8_MAX_SCALAR, (1u64 << 63) - 1);
    let config = witness.config;
    let mut values = Vec::new();
    for value in [
        config.asset_id as u64,
        config.policy_version as u64,
        config.min_collateral_ratio_ppm as u64,
        config.oracle_price_numerator as u64,
        config.oracle_price_denominator as u64,
        config.collateral_asset_id as u64,
        aux.ratio_slack,
    ] {
        push_range(&mut values, value, RANGE_BITS_U32)?;
    }
    for value in [
        config.enabled_at,
        config.retired_at.unwrap_or(0),
        config.oracle_submitted_at,
        config.oracle_max_age,
        config.attestation_created_at,
        config.attestation_max_age,
        config.collateral_scale,
        public.parent_height,
        witness.before.sequence,
        public.after.sequence,
        aux.enabled_age,
        aux.retirement_order_gap,
        aux.retirement_height_gap,
        aux.oracle_age,
        aux.oracle_slack,
        aux.attestation_age,
        aux.attestation_slack,
    ] {
        push_range(&mut values, value, RANGE_BITS_U63)?;
    }
    for value in [
        witness.before.epoch_id,
        public.after.epoch_id,
        aux.epoch_gap,
    ] {
        push_range(&mut values, value, RANGE_BITS_EPOCH)?;
    }
    for value in [
        config.max_mint_per_epoch,
        config.collateral_amount,
        public.magnitude,
        witness.before.minted_in_epoch,
        witness.before.total_debt,
        public.after.minted_in_epoch,
        public.after.total_debt,
        aux.before_cap_slack,
        aux.after_cap_slack,
    ] {
        push_range(&mut values, value, RANGE_BITS_VALUE)?;
    }
    push_range(&mut values, aux.epoch_remainder, RANGE_BITS_EPOCH_REMAINDER)?;
    push_range(&mut values, aux.path_quotient, RANGE_BITS_ASSET_QUOTIENT)?;
    for value in aux
        .collateral
        .left
        .range_values()
        .into_iter()
        .chain(aux.collateral.right.range_values())
        .chain(aux.collateral.diff)
    {
        push_range(&mut values, value, RANGE_BITS_U32)?;
    }
    let slots: usize = values
        .iter()
        .map(|(_, bits)| range_digit_count(*bits))
        .sum();
    debug_assert_eq!(slots, SMALLWOOD_POSEIDON2_V8_RANGE_DIGIT_SLOTS);
    Ok(values)
}

fn relation_profile_digest() -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_POSEIDON2_V8_RELATION_ID.as_bytes());
    for value in [
        STABLECOIN_POSEIDON2_V8_BASE_PUBLIC_FIELDS as u64,
        STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS as u64,
        SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_FIELDS as u64,
        STABLECOIN_POSEIDON2_V8_TRANSITION_PERMUTATIONS as u64,
        STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS as u64,
        SMALLWOOD_POSEIDON2_V8_RANGE_DIGIT_SLOTS as u64,
        SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS as u64,
        SMALLWOOD_POSEIDON2_V8_RELATION_ROWS as u64,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub fn build_smallwood_poseidon2_v8_relation_material(
    context: StablecoinPoseidon2V8Context,
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
) -> Result<SmallwoodPoseidon2V8RelationMaterial, SmallwoodPoseidon2V8RelationError> {
    verify_stablecoin_transition_v8(context, public, witness)?;
    let aux = build_aux(public, witness)?;
    let ranges = range_values(public, witness, &aux)?;
    let mut rows = vec![
        [0u64; SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR];
        SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS
    ];
    let source = source_fields(witness);
    rows[SOURCE_ROW_0].copy_from_slice(&source[..64]);
    rows[SOURCE_ROW_1][..source.len() - 64].copy_from_slice(&source[64..]);

    let differences = role_differences(public, witness);
    for condition in 0..SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS {
        let selected = differences[condition]
            .iter()
            .position(|value| *value != Felt::ZERO)
            .ok_or(SmallwoodPoseidon2V8RelationError::ArithmeticOverflow)?;
        for limb in 0..POSEIDON2_WIDTH16_DIGEST {
            rows[ROLE_DIFF_ROW_0 + limb][condition] =
                differences[condition][limb].as_canonical_u64();
        }
        rows[ROLE_SELECTOR_ROW][condition] = selected as u64;
        rows[ROLE_INVERSE_ROW][condition] = differences[condition][selected]
            .try_inverse()
            .expect("selected role difference is nonzero")
            .as_canonical_u64();
    }
    for lane in SMALLWOOD_POSEIDON2_V8_ROLE_CONDITIONS..SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR {
        rows[ROLE_DIFF_ROW_0][lane] = 1;
        rows[ROLE_INVERSE_ROW][lane] = 1;
    }

    let mint = u64::from(public.direction == StablecoinPoseidon2V8Direction::Mint);
    let burn = u64::from(public.direction == StablecoinPoseidon2V8Direction::Burn);
    let enabled = mint + burn;
    let mut boolean_values = Vec::new();
    boolean_values.extend([
        enabled,
        mint,
        burn,
        u64::from(witness.config.active),
        u64::from(witness.config.retired_at.is_some()),
        u64::from(witness.config.attestation_disputed),
        u64::from(witness.config.attestation_present),
    ]);
    boolean_values.extend(aux.path_bits);
    boolean_values.push(aux.same_epoch);
    boolean_values.extend(aux.decimal_bits);
    boolean_values.extend(aux.decimal_slack_bits);
    boolean_values.extend(aux.collateral.borrows);
    boolean_values.extend(aux.time_carries);
    boolean_values.extend(
        ranges
            .iter()
            .filter(|(_, bits)| *bits % 2 == 1)
            .map(|(value, bits)| (value >> (bits - 1)) & 1),
    );
    rows[BOOLEAN_ROW][..boolean_values.len()].copy_from_slice(&boolean_values);

    let mut numeric = Vec::new();
    numeric.extend([
        aux.path_quotient,
        aux.enabled_age,
        aux.retirement_order_gap,
        aux.retirement_height_gap,
        aux.oracle_age,
        aux.oracle_slack,
        aux.attestation_age,
        aux.attestation_slack,
        aux.ratio_slack,
        aux.before_cap_slack,
        aux.after_cap_slack,
        aux.epoch_gap,
        aux.epoch_remainder,
    ]);
    numeric.extend(aux.decimal_accumulators);
    numeric.extend(aux.collateral.left.range_values());
    numeric.extend(aux.collateral.right.range_values());
    numeric.extend(aux.collateral.diff);
    debug_assert!(numeric.len() <= SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR);
    rows[NUMERIC_AUX_ROW][..numeric.len()].copy_from_slice(&numeric);

    let mut mul_lane = 0usize;
    let mut push_mul = |left: u64, right: u64, output: u64| {
        rows[MUL_A_ROW][mul_lane] = left;
        rows[MUL_B_ROW][mul_lane] = right;
        rows[MUL_C_ROW][mul_lane] = output;
        mul_lane += 1;
    };
    let powers = [10u64, 100, 10_000, 100_000_000, 10_000_000_000_000_000];
    let mut previous = 1u64;
    for bit in 0..5 {
        let factor = 1 + aux.decimal_bits[bit] * (powers[bit] - 1);
        push_mul(previous, factor, aux.decimal_accumulators[bit]);
        previous = aux.decimal_accumulators[bit];
    }
    for (limbs, y, z) in [
        (
            aux.collateral.left,
            witness.config.oracle_price_numerator as u64,
            STABLECOIN_POSEIDON2_V8_RATIO_SCALE_PPM,
        ),
        (
            aux.collateral.right,
            witness.config.oracle_price_denominator as u64,
            witness.config.min_collateral_ratio_ppm as u64,
        ),
    ] {
        push_mul(limbs.x0, y, limbs.p0 + LIMB_BASE * limbs.c0);
        push_mul(limbs.x1, y, limbs.p1 + LIMB_BASE * limbs.p2 - limbs.c0);
        push_mul(limbs.p0, z, limbs.out[0] + LIMB_BASE * limbs.c1);
        push_mul(limbs.p1, z, limbs.out[1] + LIMB_BASE * limbs.c2 - limbs.c1);
        push_mul(
            limbs.p2,
            z,
            limbs.out[2] + LIMB_BASE * limbs.out[3] - limbs.c2,
        );
    }
    let epoch_inverse = if aux.epoch_gap == 0 {
        0
    } else {
        Felt::from_u64(aux.epoch_gap)
            .try_inverse()
            .expect("nonzero epoch gap is invertible")
            .as_canonical_u64()
    };
    push_mul(aux.epoch_gap, epoch_inverse, 1 - aux.same_epoch);
    push_mul(
        aux.same_epoch,
        witness.before.minted_in_epoch,
        aux.same_epoch * witness.before.minted_in_epoch,
    );
    push_mul(aux.same_epoch, aux.epoch_gap, 0);
    debug_assert_eq!(mul_lane, 18);

    let mut digit_slot = 0usize;
    for (value, bits) in &ranges {
        let digits = range_digit_count(*bits);
        for digit in 0..digits {
            rows[RANGE_ROW_0 + digit_slot / SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR]
                [digit_slot % SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR] = (value >> (2 * digit)) & 3;
            digit_slot += 1;
        }
    }
    debug_assert_eq!(digit_slot, SMALLWOOD_POSEIDON2_V8_RANGE_DIGIT_SLOTS);
    debug_assert_eq!(rows.len(), SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS);

    Ok(SmallwoodPoseidon2V8RelationMaterial {
        rows,
        poseidon_calls: poseidon_calls(public, witness),
        range_bit_widths: ranges.into_iter().map(|(_, bits)| bits).collect(),
        profile_digest: relation_profile_digest(),
    })
}

pub fn verify_smallwood_poseidon2_v8_relation_material(
    context: StablecoinPoseidon2V8Context,
    public: StablecoinPoseidon2V8Public,
    witness: StablecoinPoseidon2V8Witness,
    material: &SmallwoodPoseidon2V8RelationMaterial,
) -> Result<(), SmallwoodPoseidon2V8RelationError> {
    if material.rows.len() != SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS {
        return Err(SmallwoodPoseidon2V8RelationError::WrongRowCount);
    }
    let expected = build_smallwood_poseidon2_v8_relation_material(context, public, witness)?;
    if *material != expected {
        return Err(SmallwoodPoseidon2V8RelationError::MaterialMismatch);
    }
    Ok(())
}

pub fn smallwood_poseidon2_v8_relation_profile_digest() -> [u8; 32] {
    relation_profile_digest()
}

pub fn smallwood_poseidon2_v8_relation_supports_mask_and_auth(
    activity_mask: u8,
    auth_mode: crate::smallwood_frontend::SmallwoodPrivateAuthMode,
) -> bool {
    activity_mask < 16
        && matches!(
            auth_mode,
            crate::smallwood_frontend::SmallwoodPrivateAuthMode::SingleKey
                | crate::smallwood_frontend::SmallwoodPrivateAuthMode::ApprovalStep
                | crate::smallwood_frontend::SmallwoodPrivateAuthMode::FinalThresholdSpend
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_frontend::SmallwoodPrivateAuthMode;
    use transaction_core::stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_root, StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters,
    };

    const HEIGHT: u64 = 9_000;

    fn digest(tag: u64) -> [Felt; 7] {
        core::array::from_fn(|index| Felt::from_u64(tag + index as u64))
    }

    fn fixture() -> (
        StablecoinPoseidon2V8Context,
        StablecoinPoseidon2V8Public,
        StablecoinPoseidon2V8Witness,
    ) {
        let issuer_secret = digest(11);
        let action_intent = digest(31);
        let asset_id = 1001;
        let policy_version = 7;
        let config = StablecoinPoseidon2V8Config {
            asset_id,
            policy_version,
            active: true,
            enabled_at: 1,
            retired_at: Some(20_000),
            issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(
                asset_id,
                policy_version,
                &issuer_secret,
            ),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_submitted_at: 8_900,
            oracle_max_age: 500,
            oracle_price_numerator: 2,
            oracle_price_denominator: 1,
            collateral_amount: 10_000,
            attestation_created_at: 8_800,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 500,
            policy_admin_commitment: digest(101),
            oracle_authority_commitment: digest(201),
            attestation_authority_commitment: digest(301),
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: digest(401),
        };
        let before = StablecoinPoseidon2V8Counters {
            epoch_id: HEIGHT >> 12,
            minted_in_epoch: 100,
            total_debt: 1_000,
            sequence: 9,
        };
        let after = StablecoinPoseidon2V8Counters {
            epoch_id: HEIGHT >> 12,
            minted_in_epoch: 125,
            total_debt: 1_025,
            sequence: 10,
        };
        let siblings = [digest(501), digest(601), digest(701), digest(801)];
        let config_digest = stablecoin_poseidon2_v8_config_digest(config);
        let before_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, before, &siblings).unwrap();
        let after_root =
            stablecoin_poseidon2_v8_root(asset_id, config_digest, after, &siblings).unwrap();
        let public = StablecoinPoseidon2V8Public {
            direction: StablecoinPoseidon2V8Direction::Mint,
            asset_id,
            policy_version,
            magnitude: 25,
            action_intent,
            parent_height: HEIGHT,
            before_root,
            after_root,
            after,
            issuer_authorization: stablecoin_poseidon2_v8_issuer_authorization(
                &action_intent,
                &issuer_secret,
            ),
        };
        let witness = StablecoinPoseidon2V8Witness {
            config,
            before,
            siblings,
            issuer_secret,
        };
        (
            StablecoinPoseidon2V8Context {
                current_root: before_root,
                parent_height: HEIGHT,
                expected_action_intent: action_intent,
            },
            public,
            witness,
        )
    }

    #[test]
    fn exact_geometry_and_hash_schedule_fit_without_a_fourth_group() {
        assert_eq!(SMALLWOOD_POSEIDON2_V8_PRIVATE_SOURCE_FIELDS, 94);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_RANGE_ROWS, 23);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_ADDED_RELATION_ROWS, 39);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_RELATION_ROWS, 686);
        assert_eq!(STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS, 23);
        assert_eq!(STABLECOIN_POSEIDON2_V8_AUTHORIZED_PUBLIC_FIELDS, 120);
        assert!(STABLECOIN_POSEIDON2_V8_TOTAL_ADDED_PERMUTATIONS <= 26);

        let (context, public, witness) = fixture();
        let material =
            build_smallwood_poseidon2_v8_relation_material(context, public, witness).unwrap();
        assert_eq!(material.rows.len(), 39);
        assert_eq!(material.poseidon_calls.len(), 19);
        assert_eq!(material.range_bit_widths.len(), 66);
        assert_eq!(
            material.poseidon_calls[6].output,
            stablecoin_poseidon2_v8_config_digest(witness.config)
        );
        assert_eq!(
            material.poseidon_calls[7].output,
            stablecoin_poseidon2_v8_leaf(
                public.asset_id & 15,
                material.poseidon_calls[6].output,
                witness.before
            )
        );
        assert_eq!(
            material.poseidon_calls[17].output,
            stablecoin_poseidon2_v8_issuer_commitment(
                public.asset_id,
                public.policy_version,
                &witness.issuer_secret
            )
        );
        assert_eq!(
            material.poseidon_calls[18].output,
            stablecoin_poseidon2_v8_issuer_authorization(
                &public.action_intent,
                &witness.issuer_secret
            )
        );
    }

    #[test]
    fn material_readback_and_mutations_fail_closed() {
        let (context, public, witness) = fixture();
        let material =
            build_smallwood_poseidon2_v8_relation_material(context, public, witness).unwrap();
        verify_smallwood_poseidon2_v8_relation_material(context, public, witness, &material)
            .unwrap();

        let mut mutated = material.clone();
        mutated.rows[0][17] ^= 1;
        assert_eq!(
            verify_smallwood_poseidon2_v8_relation_material(context, public, witness, &mutated,),
            Err(SmallwoodPoseidon2V8RelationError::MaterialMismatch)
        );

        let mut mutated = material;
        mutated.poseidon_calls[12].states[9][3] ^= 1;
        assert_eq!(
            verify_smallwood_poseidon2_v8_relation_material(context, public, witness, &mutated,),
            Err(SmallwoodPoseidon2V8RelationError::MaterialMismatch)
        );
    }

    #[test]
    fn absent_retirement_uses_canonical_zero_helpers_at_low_limb_wrap() {
        let (mut context, mut public, mut witness) = fixture();
        let height = u32::MAX as u64;
        assert_eq!(((height & LIMB_MASK) + 1) >> 32, 1);
        witness.config.enabled_at = height;
        witness.config.retired_at = None;
        witness.config.oracle_submitted_at = height;
        witness.config.attestation_created_at = height;
        witness.before.epoch_id = height >> 12;
        public.parent_height = height;
        public.after.epoch_id = height >> 12;
        let config_digest = stablecoin_poseidon2_v8_config_digest(witness.config);
        public.before_root = stablecoin_poseidon2_v8_root(
            public.asset_id,
            config_digest,
            witness.before,
            &witness.siblings,
        )
        .unwrap();
        public.after_root = stablecoin_poseidon2_v8_root(
            public.asset_id,
            config_digest,
            public.after,
            &witness.siblings,
        )
        .unwrap();
        context.current_root = public.before_root;
        context.parent_height = height;

        let material =
            build_smallwood_poseidon2_v8_relation_material(context, public, witness).unwrap();
        assert_eq!(material.rows[NUMERIC_AUX_ROW][2..4], [0, 0]);
        assert_eq!(material.rows[BOOLEAN_ROW][27..29], [0, 0]);
    }

    #[test]
    fn extension_is_orthogonal_to_all_masks_and_auth_modes() {
        for mask in 0..16 {
            for mode in [
                SmallwoodPrivateAuthMode::SingleKey,
                SmallwoodPrivateAuthMode::ApprovalStep,
                SmallwoodPrivateAuthMode::FinalThresholdSpend,
            ] {
                assert!(smallwood_poseidon2_v8_relation_supports_mask_and_auth(
                    mask, mode
                ));
            }
        }
    }

    #[test]
    fn relation_identity_is_fresh_and_stable() {
        assert!(SMALLWOOD_POSEIDON2_V8_RELATION_ID.contains("poseidon2-v8"));
        assert_ne!(smallwood_poseidon2_v8_relation_profile_digest(), [0u8; 32]);
        assert!(SMALLWOOD_POSEIDON2_V8_COMPILER_COMPLETE);
        assert_eq!(STABLECOIN_POSEIDON2_V8_MAX_VALUE, (1u64 << 56) - 1);
    }
}
