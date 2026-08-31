//! Full isolated native Pay1x2 relation for direct IronSpartan.
//!
//! The relation is deliberately not linked into Hegemon consensus. It proves
//! one native-asset input, one depth-32 hidden membership path, one recipient
//! output, mandatory change, spend authorization, a nonzero nullifier, 61-bit
//! monetary ranges, and exact integer conservation. All semantic hashes use
//! the scalar prototype's fixed SHAKE256-448 frames. No balance-tag hash is in
//! the private relation; that tag belongs to the canonical public adapter.

use binius_field::{BinaryField128bGhash as B128, Field};
use binius_spartan_frontend::{
    circuit_builder::{CircuitBuilder, ConstraintBuilder},
    constraint_system::ConstraintWire,
};
use hegemon_standalone_pay1x2_statement_prototype::CANONICAL_STATEMENT_BYTES;
use hegemon_standalone_shake256_binius_backend::{STATE_BITS, keccak_f1600};
use hegemon_standalone_shake256_prototype::{
    PROFILE_TAG, SEMANTIC_DIGEST_BYTES, SHAKE256_RATE_BYTES, SPEND_KEY_DERIVATION_ROLE_TAG,
    SPEND_KEY_OUTPUT_ORDER_TAG, SemanticRole,
};

pub const MERKLE_DEPTH: usize = 32;
pub const DIGEST_BYTES: usize = SEMANTIC_DIGEST_BYTES;
pub const DIGEST_BITS: usize = DIGEST_BYTES * 8;
pub const U64_BITS: usize = 64;
pub const SPEND_KEY_BITS: usize = 48 * 8;
pub const RECIPIENT_BITS: usize = 32 * 8;
pub const RHO_BITS: usize = 48 * 8;
pub const RANDOMNESS_BITS: usize = 48 * 8;
pub const KDF_OUTPUT_BITS: usize = 2 * DIGEST_BITS;
pub const PAY1X2_SHAKE256_PERMUTATIONS: usize = 40;
pub const KECCAK_CHI_MULTIPLICATIONS: usize = 38_400 * PAY1X2_SHAKE256_PERMUTATIONS;
pub const PRIVATE_WITNESS_BYTES: usize = 2_448;
pub const PUBLIC_STATEMENT_BYTES: usize = CANONICAL_STATEMENT_BYTES;

pub const OFFSET_FEE: usize = 22;
pub const OFFSET_ANCHOR: usize = 30;
pub const OFFSET_NULLIFIER: usize = 86;
pub const OFFSET_OUTPUT_0: usize = 142;
pub const OFFSET_OUTPUT_1: usize = 198;
pub const OFFSET_CIPHERTEXT_0: usize = 254;
pub const OFFSET_CIPHERTEXT_1: usize = 310;
pub const OFFSET_NETWORK_BINDING: usize = 366;
pub const OFFSET_BALANCE_TAG: usize = 422;

const FIXED_ADAPTER_PREFIX: [u8; OFFSET_FEE] = [
    b'H', b'G', b'S', b'2', // magic
    0, 2, // statement version
    0, 5, // prospective circuit version
    0, 4, // prospective Delta crypto suite
    1, // backend
    1, // Pay1x2 profile
    1, // input count
    2, // output count
    0, 0, 0, 0, 0, 0, 0, 0, // native asset id
];

const SHAKE_DOMAIN_SUFFIX: u8 = 0x1f;

#[derive(Clone, Debug)]
pub struct NoteWires<W: Copy> {
    /// Eight-byte big-endian serialized integer, with bits LSB-first per byte.
    pub value: Vec<W>,
    /// Kept as witness bytes and constrained to the compile-time native id 0.
    pub asset_id: Vec<W>,
    pub pk_recipient: Vec<W>,
    pub rho: Vec<W>,
    pub randomness: Vec<W>,
    pub pk_auth: Vec<W>,
}

#[derive(Clone, Debug)]
pub struct StatementWires<W: Copy> {
    /// The exact 478-byte network-bound HGS2 encoding. The narrow relation fields are slices
    /// of this single public input, so they are not duplicated in the proof.
    pub canonical: Vec<W>,
}

#[derive(Clone, Debug)]
pub struct Pay1x2Wires<W: Copy> {
    pub spend_key: Vec<W>,
    pub input_note: NoteWires<W>,
    /// Full u64 encoding is retained and its high 32 bits are constrained to
    /// zero, matching the scalar statement rather than silently truncating it.
    pub position: Vec<W>,
    pub siblings: Vec<Vec<W>>,
    pub output_notes: [NoteWires<W>; 2],
    pub statement: StatementWires<W>,
}

fn allocate_note(builder: &mut ConstraintBuilder<B128>) -> NoteWires<ConstraintWire> {
    NoteWires {
        value: allocate_precommit(builder, U64_BITS),
        asset_id: allocate_precommit(builder, U64_BITS),
        pk_recipient: allocate_precommit(builder, RECIPIENT_BITS),
        rho: allocate_precommit(builder, RHO_BITS),
        randomness: allocate_precommit(builder, RANDOMNESS_BITS),
        pk_auth: allocate_precommit(builder, DIGEST_BITS),
    }
}

fn allocate_precommit(builder: &mut ConstraintBuilder<B128>, count: usize) -> Vec<ConstraintWire> {
    (0..count).map(|_| builder.alloc_precommit()).collect()
}

fn allocate_public(builder: &mut ConstraintBuilder<B128>, count: usize) -> Vec<ConstraintWire> {
    (0..count).map(|_| builder.alloc_inout()).collect()
}

/// Allocate the exact 2,448-byte witness and 478-byte HGS2 public statement.
pub fn allocate_pay1x2_wires(builder: &mut ConstraintBuilder<B128>) -> Pay1x2Wires<ConstraintWire> {
    Pay1x2Wires {
        spend_key: allocate_precommit(builder, SPEND_KEY_BITS),
        input_note: allocate_note(builder),
        position: allocate_precommit(builder, U64_BITS),
        siblings: (0..MERKLE_DEPTH)
            .map(|_| allocate_precommit(builder, DIGEST_BITS))
            .collect(),
        output_notes: [allocate_note(builder), allocate_note(builder)],
        statement: StatementWires {
            canonical: allocate_public(builder, CANONICAL_STATEMENT_BYTES * 8),
        },
    }
}

/// Constrain the complete fixed native Pay1x2 relation.
pub fn constrain_pay1x2<B>(builder: &mut B, wires: &Pay1x2Wires<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    assert_wire_geometry(wires);
    let zero = builder.constant(B128::ZERO);
    let one = builder.constant(B128::ONE);

    constrain_all_external_bits(builder, wires);
    assert_constant_bytes(
        builder,
        statement_bytes(&wires.statement, 0, OFFSET_FEE),
        &FIXED_ADAPTER_PREFIX,
        zero,
        one,
    );

    // Native asset is a fixed profile invariant. It remains present in each
    // note preimage, but no prover can select another asset id.
    for note in [
        &wires.input_note,
        &wires.output_notes[0],
        &wires.output_notes[1],
    ] {
        assert_all_equal(builder, &note.asset_id, zero);
        constrain_61_bit_be_u64(builder, &note.value, zero);
    }
    let fee_bits = statement_bytes(&wires.statement, OFFSET_FEE, 8);
    constrain_61_bit_be_u64(builder, fee_bits, zero);

    // A depth-32 tree admits only the low 32 bits of the canonical u64
    // position. Keeping and constraining the high bytes avoids truncation.
    assert_all_equal(builder, &wires.position[..32], zero);

    // One domain-separated SHAKE call yields auth || nullifier_key. Exact
    // equality constraints bind the input and mandatory change note to the
    // derived spending authority.
    let kdf_frame = spend_key_frame(builder, &wires.spend_key, zero, one);
    let kdf_output = shake256_bits(builder, &kdf_frame, 2 * DIGEST_BYTES, zero, one);
    let spend_auth = &kdf_output[..DIGEST_BITS];
    let nullifier_key = &kdf_output[DIGEST_BITS..];
    assert_equal_bits(builder, spend_auth, &wires.input_note.pk_auth);
    assert_equal_bits(builder, spend_auth, &wires.output_notes[1].pk_auth);
    // Three exact note commitments. Input commitment remains hidden and feeds
    // the Merkle path; output commitments are public statement fields.
    let input_commitment = constrain_note_commitment(builder, &wires.input_note, zero, one);
    let output0 = constrain_note_commitment(builder, &wires.output_notes[0], zero, one);
    let output1 = constrain_note_commitment(builder, &wires.output_notes[1], zero, one);
    constrain_nonzero_bits(builder, &input_commitment, zero, one);
    constrain_nonzero_bits(builder, &output0, zero, one);
    constrain_nonzero_bits(builder, &output1, zero, one);
    assert_equal_bits(
        builder,
        &output0,
        statement_bytes(&wires.statement, OFFSET_OUTPUT_0, DIGEST_BYTES),
    );
    assert_equal_bits(
        builder,
        &output1,
        statement_bytes(&wires.statement, OFFSET_OUTPUT_1, DIGEST_BYTES),
    );

    // Nullifier = SHAKE(nullifier_key, canonical u64 position, input rho).
    let nullifier_frame = semantic_frame(
        builder,
        SemanticRole::Nullifier.tag(),
        &[nullifier_key, &wires.position, &wires.input_note.rho],
        zero,
        one,
    );
    let nullifier = shake256_bits(builder, &nullifier_frame, DIGEST_BYTES, zero, one);
    let public_nullifier = statement_bytes(&wires.statement, OFFSET_NULLIFIER, DIGEST_BYTES);
    assert_equal_bits(builder, &nullifier, public_nullifier);
    constrain_nonzero_bits(builder, public_nullifier, zero, one);

    // Hidden depth-32 membership. Direction bit i is numeric bit i of the
    // canonical big-endian u64 position. Each conditional swap reuses one AND
    // per digest bit before hashing the exact 133-byte parent frame.
    let position_le = be_u64_bits_to_numeric_le(&wires.position);
    let mut current = input_commitment;
    for (level, sibling) in wires.siblings.iter().enumerate() {
        let (left, right) = conditional_swap(builder, &current, sibling, position_le[level]);
        let parent_frame = semantic_frame(
            builder,
            SemanticRole::MerkleNode.tag(),
            &[&left, &right],
            zero,
            one,
        );
        current = shake256_bits(builder, &parent_frame, DIGEST_BYTES, zero, one);
    }
    assert_equal_bits(
        builder,
        &current,
        statement_bytes(&wires.statement, OFFSET_ANCHOR, DIGEST_BYTES),
    );

    // Exact integer conservation, not characteristic-two field addition:
    // input = recipient + change + public fee. The two carry bits above u64
    // must be zero, and the 61-bit range keeps accepted monetary values in the
    // active bound.
    let input_value = be_u64_bits_to_numeric_le(&wires.input_note.value);
    let output0_value = be_u64_bits_to_numeric_le(&wires.output_notes[0].value);
    let output1_value = be_u64_bits_to_numeric_le(&wires.output_notes[1].value);
    let fee = be_u64_bits_to_numeric_le(fee_bits);
    let output_sum = add_unsigned_bits(builder, &output0_value, &output1_value, zero);
    let outputs_and_fee = add_unsigned_bits(builder, &output_sum, &fee, zero);
    assert_equal_bits(builder, &input_value, &outputs_and_fee[..U64_BITS]);
    assert_all_equal(builder, &outputs_and_fee[U64_BITS..], zero);
}

fn assert_wire_geometry<W: Copy>(wires: &Pay1x2Wires<W>) {
    assert_eq!(wires.spend_key.len(), SPEND_KEY_BITS);
    assert_eq!(wires.position.len(), U64_BITS);
    assert_eq!(wires.siblings.len(), MERKLE_DEPTH);
    assert!(
        wires
            .siblings
            .iter()
            .all(|sibling| sibling.len() == DIGEST_BITS)
    );
    for note in [
        &wires.input_note,
        &wires.output_notes[0],
        &wires.output_notes[1],
    ] {
        assert_eq!(note.value.len(), U64_BITS);
        assert_eq!(note.asset_id.len(), U64_BITS);
        assert_eq!(note.pk_recipient.len(), RECIPIENT_BITS);
        assert_eq!(note.rho.len(), RHO_BITS);
        assert_eq!(note.randomness.len(), RANDOMNESS_BITS);
        assert_eq!(note.pk_auth.len(), DIGEST_BITS);
    }
    assert_eq!(
        wires.statement.canonical.len(),
        CANONICAL_STATEMENT_BYTES * 8
    );
}

fn constrain_all_external_bits<B>(builder: &mut B, wires: &Pay1x2Wires<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    constrain_bits(builder, &wires.spend_key);
    constrain_note_bits(builder, &wires.input_note);
    constrain_bits(builder, &wires.position);
    for sibling in &wires.siblings {
        constrain_bits(builder, sibling);
    }
    for note in &wires.output_notes {
        constrain_note_bits(builder, note);
    }
    constrain_bits(builder, &wires.statement.canonical);
}

fn statement_bytes<W: Copy>(statement: &StatementWires<W>, offset: usize, len: usize) -> &[W] {
    &statement.canonical[offset * 8..(offset + len) * 8]
}

fn assert_constant_bytes<B>(
    builder: &mut B,
    actual: &[B::Wire],
    expected: &[u8],
    zero: B::Wire,
    one: B::Wire,
) where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(actual.len(), expected.len() * 8);
    for (&actual, expected) in
        actual.iter().zip(expected.iter().flat_map(|byte| {
            (0..8).map(move |bit| if (byte >> bit) & 1 == 1 { one } else { zero })
        }))
    {
        builder.assert_eq(actual, expected);
    }
}

fn constrain_note_bits<B>(builder: &mut B, note: &NoteWires<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    for bits in [
        &note.value,
        &note.asset_id,
        &note.pk_recipient,
        &note.rho,
        &note.randomness,
        &note.pk_auth,
    ] {
        constrain_bits(builder, bits);
    }
}

fn constrain_bits<B>(builder: &mut B, bits: &[B::Wire])
where
    B: CircuitBuilder<Field = B128>,
{
    for &bit in bits {
        let square = builder.mul(bit, bit);
        builder.assert_eq(square, bit);
    }
}

fn constrain_61_bit_be_u64<B>(builder: &mut B, bits: &[B::Wire], zero: B::Wire)
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(bits.len(), U64_BITS);
    // Big-endian first byte, per-byte LSB-first circuit encoding: numeric bits
    // 61, 62, and 63 are byte bits 5, 6, and 7.
    assert_all_equal(builder, &bits[5..8], zero);
}

fn constrain_nonzero_bits<B>(builder: &mut B, bits: &[B::Wire], zero: B::Wire, one: B::Wire)
where
    B: CircuitBuilder<Field = B128>,
{
    // Product(1 + bit_i) is one iff every Boolean bit is zero.
    let mut all_zero = one;
    for &bit in bits {
        let not_bit = builder.add(one, bit);
        all_zero = builder.mul(all_zero, not_bit);
    }
    builder.assert_eq(all_zero, zero);
}

fn assert_equal_bits<B>(builder: &mut B, left: &[B::Wire], right: &[B::Wire])
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(left.len(), right.len());
    for (&left, &right) in left.iter().zip(right) {
        builder.assert_eq(left, right);
    }
}

fn assert_all_equal<B>(builder: &mut B, bits: &[B::Wire], expected: B::Wire)
where
    B: CircuitBuilder<Field = B128>,
{
    for &bit in bits {
        builder.assert_eq(bit, expected);
    }
}

fn constrain_note_commitment<B>(
    builder: &mut B,
    note: &NoteWires<B::Wire>,
    zero: B::Wire,
    one: B::Wire,
) -> Vec<B::Wire>
where
    B: CircuitBuilder<Field = B128>,
{
    let frame = semantic_frame(
        builder,
        SemanticRole::NoteCommitment.tag(),
        &[
            &note.value,
            &note.asset_id,
            &note.pk_recipient,
            &note.rho,
            &note.randomness,
            &note.pk_auth,
        ],
        zero,
        one,
    );
    shake256_bits(builder, &frame, DIGEST_BYTES, zero, one)
}

fn spend_key_frame<B>(
    builder: &mut B,
    spend_key: &[B::Wire],
    zero: B::Wire,
    one: B::Wire,
) -> Vec<B::Wire>
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(spend_key.len(), SPEND_KEY_BITS);
    let mut frame = Vec::with_capacity(75 * 8);
    push_constant_bytes(builder, &mut frame, &PROFILE_TAG, zero, one);
    push_constant_bytes(
        builder,
        &mut frame,
        &SPEND_KEY_DERIVATION_ROLE_TAG,
        zero,
        one,
    );
    push_constant_bytes(builder, &mut frame, &SPEND_KEY_OUTPUT_ORDER_TAG, zero, one);
    push_constant_bytes(builder, &mut frame, &[1], zero, one);
    push_field(builder, &mut frame, spend_key, zero, one);
    assert_eq!(frame.len(), 75 * 8);
    frame
}

fn semantic_frame<B>(
    builder: &mut B,
    role: [u8; 8],
    fields: &[&[B::Wire]],
    zero: B::Wire,
    one: B::Wire,
) -> Vec<B::Wire>
where
    B: CircuitBuilder<Field = B128>,
{
    let mut frame = Vec::new();
    push_constant_bytes(builder, &mut frame, &PROFILE_TAG, zero, one);
    push_constant_bytes(builder, &mut frame, &role, zero, one);
    push_constant_bytes(builder, &mut frame, &[fields.len() as u8], zero, one);
    for field in fields {
        push_field(builder, &mut frame, field, zero, one);
    }
    frame
}

fn push_field<B>(
    builder: &mut B,
    frame: &mut Vec<B::Wire>,
    field: &[B::Wire],
    zero: B::Wire,
    one: B::Wire,
) where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(field.len() % 8, 0);
    let byte_len = u16::try_from(field.len() / 8).expect("fixed field width must fit u16");
    push_constant_bytes(builder, frame, &byte_len.to_be_bytes(), zero, one);
    frame.extend_from_slice(field);
}

fn push_constant_bytes<B>(
    _builder: &mut B,
    output: &mut Vec<B::Wire>,
    bytes: &[u8],
    zero: B::Wire,
    one: B::Wire,
) where
    B: CircuitBuilder<Field = B128>,
{
    for &byte in bytes {
        for bit in 0..8 {
            output.push(if (byte >> bit) & 1 == 1 { one } else { zero });
        }
    }
}

/// SHAKE256 over a byte-aligned fixed frame, supporting all four Pay1x2 frame
/// geometries. Frames longer than one rate block XOR into the continuing
/// Keccak state before the final domain/padding block.
fn shake256_bits<B>(
    builder: &mut B,
    frame: &[B::Wire],
    output_bytes: usize,
    zero: B::Wire,
    one: B::Wire,
) -> Vec<B::Wire>
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(frame.len() % 8, 0);
    assert!(output_bytes * 8 <= SHAKE256_RATE_BYTES * 8);
    let rate_bits = SHAKE256_RATE_BYTES * 8;
    let mut state = vec![zero; STATE_BITS];
    let mut consumed = 0usize;

    while frame.len() - consumed >= rate_bits {
        for offset in 0..rate_bits {
            state[offset] = builder.add(state[offset], frame[consumed + offset]);
        }
        keccak_f1600(builder, &mut state);
        consumed += rate_bits;
    }

    let remainder = &frame[consumed..];
    for (offset, &bit) in remainder.iter().enumerate() {
        state[offset] = builder.add(state[offset], bit);
    }
    let suffix_start = remainder.len();
    for bit in 0..8 {
        if (SHAKE_DOMAIN_SUFFIX >> bit) & 1 == 1 {
            state[suffix_start + bit] = builder.add(state[suffix_start + bit], one);
        }
    }
    // pad10*1 final bit at the end of the rate block.
    state[rate_bits - 1] = builder.add(state[rate_bits - 1], one);
    keccak_f1600(builder, &mut state);
    state[..output_bytes * 8].to_vec()
}

fn conditional_swap<B>(
    builder: &mut B,
    current: &[B::Wire],
    sibling: &[B::Wire],
    direction: B::Wire,
) -> (Vec<B::Wire>, Vec<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(current.len(), DIGEST_BITS);
    assert_eq!(sibling.len(), DIGEST_BITS);
    let mut left = Vec::with_capacity(DIGEST_BITS);
    let mut right = Vec::with_capacity(DIGEST_BITS);
    for (&current, &sibling) in current.iter().zip(sibling) {
        let delta = builder.add(current, sibling);
        let selected_delta = builder.mul(direction, delta);
        left.push(builder.add(current, selected_delta));
        right.push(builder.add(sibling, selected_delta));
    }
    (left, right)
}

fn be_u64_bits_to_numeric_le<W: Copy>(serialized: &[W]) -> Vec<W> {
    assert_eq!(serialized.len(), U64_BITS);
    let mut numeric = Vec::with_capacity(U64_BITS);
    for byte in (0..8).rev() {
        numeric.extend_from_slice(&serialized[byte * 8..(byte + 1) * 8]);
    }
    numeric
}

fn add_unsigned_bits<B>(
    builder: &mut B,
    left: &[B::Wire],
    right: &[B::Wire],
    zero: B::Wire,
) -> Vec<B::Wire>
where
    B: CircuitBuilder<Field = B128>,
{
    let width = left.len().max(right.len());
    let mut output = Vec::with_capacity(width + 1);
    let mut carry = zero;
    for index in 0..width {
        let left_bit = left.get(index).copied().unwrap_or(zero);
        let right_bit = right.get(index).copied().unwrap_or(zero);
        let left_xor_right = builder.add(left_bit, right_bit);
        output.push(builder.add(left_xor_right, carry));
        let direct_carry = builder.mul(left_bit, right_bit);
        let propagated_carry = builder.mul(left_xor_right, carry);
        carry = builder.add(direct_carry, propagated_carry);
    }
    output.push(carry);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_geometry_matches_scalar_relation() {
        assert_eq!(PRIVATE_WITNESS_BYTES, 2_448);
        assert_eq!(PUBLIC_STATEMENT_BYTES, 478);
        assert_eq!(OFFSET_NETWORK_BINDING + DIGEST_BYTES, OFFSET_BALANCE_TAG);
        assert_eq!(OFFSET_BALANCE_TAG + DIGEST_BYTES, PUBLIC_STATEMENT_BYTES);
        assert_eq!(PAY1X2_SHAKE256_PERMUTATIONS, 40);
        assert_eq!(KECCAK_CHI_MULTIPLICATIONS, 1_536_000);
        assert_eq!(SemanticRole::NoteCommitment.frame_len(), 229);
        assert_eq!(SemanticRole::Nullifier.frame_len(), 135);
        assert_eq!(SemanticRole::MerkleNode.frame_len(), 133);
    }

    #[test]
    fn big_endian_wire_order_maps_to_numeric_little_endian() {
        let serialized: Vec<_> = (0usize..64).collect();
        let numeric = be_u64_bits_to_numeric_le(&serialized);
        assert_eq!(&numeric[..8], &serialized[56..64]);
        assert_eq!(&numeric[56..], &serialized[..8]);
    }
}
