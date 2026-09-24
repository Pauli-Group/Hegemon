//! Full native-word M4 circuit for the isolated SHAKE256 Pay1x2 relation.
//!
//! This crate is research evidence only. The pinned M4 prover is transparent,
//! uses the upstream 96-bit/SHA-256/GF(2^128) profile, and is neither a
//! zero-knowledge nor a strict-PQ128 implementation.

#![forbid(unsafe_code)]

use std::array;

use binius_circuits::{bytes::swap_bytes, keccak::permutation::keccak_f1600};
use binius_core::{constraint_system::m4::WitnessM4, Word};
use binius_frontend::{CircuitBuilder, CircuitM4, CircuitStat, PopulateM4Error, Wire};
use binius_hash::StdHashSuite;
use binius_m4_prover::ProverM4;
use binius_m4_verifier::VerifierM4;
use binius_prover::OptimalPackedB128;
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::config::StdChallenger;
use hegemon_standalone_pay1x2_relation_prototype::{
    valid_fixture, verify_relation, Pay1x2Statement, Pay1x2Witness, MERKLE_DEPTH,
};
use hegemon_standalone_pay1x2_statement_prototype::{
    adapt_action, CanonicalCiphertextBytes, CANONICAL_STATEMENT_BYTES, KAT_NETWORK_IDENTITY,
};
use hegemon_standalone_shake256_prototype::{
    NoteOpening, SemanticRole, PROFILE_TAG, SEMANTIC_DIGEST_BYTES, SPEND_KEY_DERIVATION_ROLE_TAG,
    SPEND_KEY_OUTPUT_ORDER_TAG,
};

pub const UPSTREAM_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
pub const PRIVATE_WITNESS_BYTES: usize = 2_448;
pub const PRIVATE_WORDS: usize = PRIVATE_WITNESS_BYTES / 8;
pub const PUBLIC_STATEMENT_BYTES: usize = CANONICAL_STATEMENT_BYTES;
pub const PUBLIC_WORDS: usize = PUBLIC_STATEMENT_BYTES.div_ceil(8);
pub const DIGEST_BYTES: usize = SEMANTIC_DIGEST_BYTES;
pub const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
pub const PAY1X2_SHAKE256_PERMUTATIONS: usize = 40;
pub const SHAKE256_RATE_BYTES: usize = 136;
pub const SHAKE256_RATE_WORDS: usize = SHAKE256_RATE_BYTES / 8;

pub const OFFSET_FEE: usize = 22;
pub const OFFSET_ANCHOR: usize = 30;
pub const OFFSET_NULLIFIER: usize = 86;
pub const OFFSET_OUTPUT_0: usize = 142;
pub const OFFSET_OUTPUT_1: usize = 198;
pub const OFFSET_CIPHERTEXT_0: usize = 254;
pub const OFFSET_CIPHERTEXT_1: usize = 310;
pub const OFFSET_NETWORK_BINDING: usize = 366;
pub const OFFSET_BALANCE_TAG: usize = 422;

const SHAKE_DOMAIN_SUFFIX: u64 = 0x1f;
const RECIPIENT_CIPHERTEXT: &[u8] = b"canonical-recipient-ciphertext-v1";
const CHANGE_CIPHERTEXT: &[u8] = b"canonical-change-ciphertext-v1";
const FIXED_PREFIX_0: u64 = u64::from_le_bytes(*b"HGS2\0\x02\0\x05");
const FIXED_PREFIX_1: u64 = u64::from_le_bytes([0, 4, 1, 1, 1, 2, 0, 0]);

#[derive(Clone, Debug)]
pub struct NoteWords {
    pub value_be: Wire,
    pub asset_be: Wire,
    pub pk_recipient: [Wire; 4],
    pub rho: [Wire; 6],
    pub randomness: [Wire; 6],
    pub pk_auth: [Wire; DIGEST_WORDS],
}

#[derive(Clone, Debug)]
pub struct Pay1x2M4Wires {
    pub private: [Wire; PRIVATE_WORDS],
    /// The final word contains six statement bytes and two constrained zero
    /// padding bytes. The canonical statement itself remains exactly 478 bytes.
    pub public: [Wire; PUBLIC_WORDS],
    pub spend_key: [Wire; 6],
    pub input_note: NoteWords,
    pub position_be: Wire,
    pub siblings: [[Wire; DIGEST_WORDS]; MERKLE_DEPTH],
    pub output_notes: [NoteWords; 2],
}

pub struct BuiltPay1x2M4 {
    pub circuit: CircuitM4,
    pub wires: Pay1x2M4Wires,
}

#[derive(Clone, Debug)]
pub struct ProofGateReport {
    pub log_inverse_rate: usize,
    pub proof: Vec<u8>,
    pub honest_roundtrip: bool,
    pub all_public_mutations_rejected: bool,
    pub changed_proof_rejected: bool,
    pub trailing_proof_rejected: bool,
}

/// Build one main circuit with all 40 Keccak-f invocations inline and no M4
/// numbered chips. This avoids the upstream unconstrained chip-call seam.
pub fn build_pay1x2_m4() -> BuiltPay1x2M4 {
    let builder = CircuitBuilder::new();
    let private = array::from_fn(|_| builder.add_witness());
    let public = array::from_fn(|_| builder.add_inout());
    let wires = map_wires(private, public);
    constrain_pay1x2(&builder, &wires);
    let circuit = builder.build_m4();
    assert!(
        circuit.chips.is_empty(),
        "the full relation must stay in one main circuit"
    );
    circuit
        .validate()
        .expect("the single-main M4 circuit must validate");
    BuiltPay1x2M4 { circuit, wires }
}

fn map_note(words: &[Wire]) -> NoteWords {
    assert_eq!(words.len(), 25);
    NoteWords {
        value_be: words[0],
        asset_be: words[1],
        pk_recipient: words[2..6].try_into().unwrap(),
        rho: words[6..12].try_into().unwrap(),
        randomness: words[12..18].try_into().unwrap(),
        pk_auth: words[18..25].try_into().unwrap(),
    }
}

fn map_wires(private: [Wire; PRIVATE_WORDS], public: [Wire; PUBLIC_WORDS]) -> Pay1x2M4Wires {
    // 6 spend-key words, 25 input-note words, 1 position, 224 path
    // words, and 25 words per output = 306 words exactly.
    let spend_key = private[0..6].try_into().unwrap();
    let input_note = map_note(&private[6..31]);
    let position_be = private[31];
    let siblings = array::from_fn(|level| {
        let start = 32 + level * DIGEST_WORDS;
        private[start..start + DIGEST_WORDS].try_into().unwrap()
    });
    let output_notes = [map_note(&private[256..281]), map_note(&private[281..306])];
    Pay1x2M4Wires {
        private,
        public,
        spend_key,
        input_note,
        position_be,
        siblings,
        output_notes,
    }
}

fn constrain_pay1x2(builder: &CircuitBuilder, wires: &Pay1x2M4Wires) {
    let zero = builder.add_constant_64(0);

    // Bind the exact HGS2 profile prefix while leaving the authoritative
    // ciphertext/network/balance derivations to the existing action adapter.
    builder.assert_eq(
        "statement.prefix[0]",
        wires.public[0],
        builder.add_constant_64(FIXED_PREFIX_0),
    );
    builder.assert_eq(
        "statement.prefix[1]",
        wires.public[1],
        builder.add_constant_64(FIXED_PREFIX_1),
    );
    let prefix_tail = builder.band(
        wires.public[2],
        builder.add_constant_64(0x0000_ffff_ffff_ffff),
    );
    builder.assert_zero("statement.native_asset_tail", prefix_tail);
    let public_padding = builder.band(
        wires.public[59],
        builder.add_constant_64(0xffff_0000_0000_0000),
    );
    builder.assert_zero("statement.padding", public_padding);

    let fee_be = builder.bxor(
        builder.shr(wires.public[2], 48),
        builder.shl(wires.public[3], 16),
    );
    let fee = swap_bytes(builder, fee_be);
    let anchor = statement_digest(builder, &wires.public, 0);
    let public_nullifier = statement_digest(builder, &wires.public, 1);
    let public_output0 = statement_digest(builder, &wires.public, 2);
    let public_output1 = statement_digest(builder, &wires.public, 3);

    for (name, note) in [
        ("input", &wires.input_note),
        ("recipient", &wires.output_notes[0]),
        ("change", &wires.output_notes[1]),
    ] {
        builder.assert_zero(format!("{name}.asset"), note.asset_be);
        assert_61_bit(
            builder,
            &format!("{name}.value"),
            swap_bytes(builder, note.value_be),
        );
    }
    assert_61_bit(builder, "statement.fee", fee);

    let position = swap_bytes(builder, wires.position_be);
    builder.assert_zero("input.position.high32", builder.shr(position, 32));

    let kdf_frame = kdf_frame(builder, &wires.spend_key);
    let kdf_output = shake256_words(builder, &kdf_frame.words, kdf_frame.len_bytes, 14);
    let spend_auth: [Wire; DIGEST_WORDS] = kdf_output[..7].try_into().unwrap();
    let nullifier_key: [Wire; DIGEST_WORDS] = kdf_output[7..14].try_into().unwrap();
    assert_digest_eq(
        builder,
        "input.authorization",
        &spend_auth,
        &wires.input_note.pk_auth,
    );
    assert_digest_eq(
        builder,
        "change.authorization",
        &spend_auth,
        &wires.output_notes[1].pk_auth,
    );

    let input_commitment = note_commitment(builder, &wires.input_note);
    let output0 = note_commitment(builder, &wires.output_notes[0]);
    let output1 = note_commitment(builder, &wires.output_notes[1]);
    assert_digest_nonzero(builder, "input.commitment.nonzero", &input_commitment);
    assert_digest_nonzero(builder, "recipient.commitment.nonzero", &output0);
    assert_digest_nonzero(builder, "change.commitment.nonzero", &output1);
    assert_digest_eq(builder, "statement.output0", &output0, &public_output0);
    assert_digest_eq(builder, "statement.output1", &output1, &public_output1);

    let nullifier_frame = semantic_frame(
        builder,
        SemanticRole::Nullifier.tag(),
        &[
            (&nullifier_key, DIGEST_BYTES),
            (&[wires.position_be], 8),
            (&wires.input_note.rho, 48),
        ],
    );
    let nullifier: [Wire; DIGEST_WORDS] = shake256_words(
        builder,
        &nullifier_frame.words,
        nullifier_frame.len_bytes,
        DIGEST_WORDS,
    )
    .try_into()
    .unwrap();
    assert_digest_eq(
        builder,
        "statement.nullifier",
        &nullifier,
        &public_nullifier,
    );
    assert_digest_nonzero(builder, "statement.nullifier.nonzero", &public_nullifier);

    let mut current = input_commitment;
    for (level, sibling) in wires.siblings.iter().enumerate() {
        // Put numeric position bit `level` in the MSB, then sign-extend it
        // to an all-zero/all-one mask. One bitwise AND selects each digest word.
        let direction_msb = builder.shl(position, 63 - level as u32);
        let mask = builder.sar(direction_msb, 63);
        let left: [Wire; DIGEST_WORDS] = array::from_fn(|word| {
            let selected_delta = builder.band(mask, builder.bxor(current[word], sibling[word]));
            builder.bxor(current[word], selected_delta)
        });
        let right: [Wire; DIGEST_WORDS] = array::from_fn(|word| {
            let selected_delta = builder.band(mask, builder.bxor(current[word], sibling[word]));
            builder.bxor(sibling[word], selected_delta)
        });
        // Algebraic CSE collapses the duplicate selected_delta gates above.
        let frame = semantic_frame(
            builder,
            SemanticRole::MerkleNode.tag(),
            &[(&left, DIGEST_BYTES), (&right, DIGEST_BYTES)],
        );
        current = shake256_words(builder, &frame.words, frame.len_bytes, DIGEST_WORDS)
            .try_into()
            .unwrap();
    }
    assert_digest_eq(builder, "statement.anchor", &current, &anchor);

    let input_value = swap_bytes(builder, wires.input_note.value_be);
    let output0_value = swap_bytes(builder, wires.output_notes[0].value_be);
    let output1_value = swap_bytes(builder, wires.output_notes[1].value_be);
    let (output_sum, carry0) = builder.iadd(output0_value, output1_value);
    builder.assert_false("balance.output_sum_overflow", carry0);
    let (outputs_and_fee, carry1) = builder.iadd(output_sum, fee);
    builder.assert_false("balance.fee_sum_overflow", carry1);
    builder.assert_eq("balance.conservation", input_value, outputs_and_fee);

    // Keep the zero wire live only through actual constraints, not a dummy row.
    let _ = zero;
}

fn assert_61_bit(builder: &CircuitBuilder, name: &str, value: Wire) {
    builder.assert_zero(format!("{name}.high3"), builder.shr(value, 61));
}

fn statement_digest(
    builder: &CircuitBuilder,
    statement: &[Wire; PUBLIC_WORDS],
    digest_index: usize,
) -> [Wire; DIGEST_WORDS] {
    let base = 3 + digest_index * DIGEST_WORDS;
    array::from_fn(|word| {
        builder.bxor(
            builder.shr(statement[base + word], 48),
            builder.shl(statement[base + word + 1], 16),
        )
    })
}

fn assert_digest_eq(
    builder: &CircuitBuilder,
    name: &str,
    actual: &[Wire; DIGEST_WORDS],
    expected: &[Wire; DIGEST_WORDS],
) {
    for word in 0..DIGEST_WORDS {
        builder.assert_eq(format!("{name}[{word}]"), actual[word], expected[word]);
    }
}

fn assert_digest_nonzero(builder: &CircuitBuilder, name: &str, digest: &[Wire; DIGEST_WORDS]) {
    let combined = digest[1..]
        .iter()
        .fold(digest[0], |acc, &word| builder.bor(acc, word));
    builder.assert_non_zero(name, combined);
}

fn note_commitment(builder: &CircuitBuilder, note: &NoteWords) -> [Wire; DIGEST_WORDS] {
    let frame = semantic_frame(
        builder,
        SemanticRole::NoteCommitment.tag(),
        &[
            (&[note.value_be], 8),
            (&[note.asset_be], 8),
            (&note.pk_recipient, 32),
            (&note.rho, 48),
            (&note.randomness, 48),
            (&note.pk_auth, DIGEST_BYTES),
        ],
    );
    shake256_words(builder, &frame.words, frame.len_bytes, DIGEST_WORDS)
        .try_into()
        .unwrap()
}

struct PackedFrame {
    words: Vec<Wire>,
    len_bytes: usize,
}

struct FrameBuilder<'a> {
    builder: &'a CircuitBuilder,
    words: Vec<Wire>,
    partial: Option<(Wire, usize)>,
    len_bytes: usize,
}

impl<'a> FrameBuilder<'a> {
    fn new(builder: &'a CircuitBuilder) -> Self {
        Self {
            builder,
            words: Vec::new(),
            partial: None,
            len_bytes: 0,
        }
    }

    fn push_const(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut packed = [0u8; 8];
            packed[..chunk.len()].copy_from_slice(chunk);
            self.push_word_bytes(
                self.builder.add_constant_64(u64::from_le_bytes(packed)),
                chunk.len(),
            );
        }
    }

    fn push_words(&mut self, words: &[Wire], len_bytes: usize) {
        assert_eq!(words.len(), len_bytes.div_ceil(8));
        for (index, &word) in words.iter().enumerate() {
            let remaining = len_bytes - index * 8;
            self.push_word_bytes(word, remaining.min(8));
        }
    }

    fn push_word_bytes(&mut self, mut word: Wire, mut bytes: usize) {
        assert!((1..=8).contains(&bytes));
        self.len_bytes += bytes;
        if bytes < 8 {
            word = self
                .builder
                .band(word, self.builder.add_constant_64(low_byte_mask(bytes)));
        }

        while bytes > 0 {
            let used = self.partial.map_or(0, |(_, used)| used);
            if used == 0 && bytes == 8 {
                self.words.push(word);
                return;
            }
            if used == 0 {
                self.partial = Some((word, bytes));
                return;
            }

            let (current, _) = self.partial.take().unwrap();
            let take = (8 - used).min(bytes);
            let low = if take == 8 {
                word
            } else {
                self.builder
                    .band(word, self.builder.add_constant_64(low_byte_mask(take)))
            };
            let shifted = self.builder.shl(low, (used * 8) as u32);
            let merged = self.builder.bxor(current, shifted);
            if used + take == 8 {
                self.words.push(merged);
            } else {
                self.partial = Some((merged, used + take));
            }
            bytes -= take;
            if bytes > 0 {
                word = self.builder.shr(word, (take * 8) as u32);
            }
        }
    }

    fn finish(mut self) -> PackedFrame {
        if let Some((word, _)) = self.partial.take() {
            self.words.push(word);
        }
        assert_eq!(self.words.len(), self.len_bytes.div_ceil(8));
        PackedFrame {
            words: self.words,
            len_bytes: self.len_bytes,
        }
    }
}

const fn low_byte_mask(bytes: usize) -> u64 {
    if bytes == 8 {
        u64::MAX
    } else {
        (1u64 << (bytes * 8)) - 1
    }
}

fn kdf_frame(builder: &CircuitBuilder, spend_key: &[Wire; 6]) -> PackedFrame {
    let mut frame = FrameBuilder::new(builder);
    frame.push_const(&PROFILE_TAG);
    frame.push_const(&SPEND_KEY_DERIVATION_ROLE_TAG);
    frame.push_const(&SPEND_KEY_OUTPUT_ORDER_TAG);
    frame.push_const(&[1]);
    frame.push_const(&48u16.to_be_bytes());
    frame.push_words(spend_key, 48);
    let frame = frame.finish();
    assert_eq!(frame.len_bytes, 75);
    frame
}

fn semantic_frame(
    builder: &CircuitBuilder,
    role: [u8; 8],
    fields: &[(&[Wire], usize)],
) -> PackedFrame {
    let mut frame = FrameBuilder::new(builder);
    frame.push_const(&PROFILE_TAG);
    frame.push_const(&role);
    frame.push_const(&[fields.len() as u8]);
    for &(words, len_bytes) in fields {
        frame.push_const(&(len_bytes as u16).to_be_bytes());
        frame.push_words(words, len_bytes);
    }
    frame.finish()
}

fn shake256_words(
    builder: &CircuitBuilder,
    frame_words: &[Wire],
    frame_len_bytes: usize,
    output_words: usize,
) -> Vec<Wire> {
    assert_eq!(frame_words.len(), frame_len_bytes.div_ceil(8));
    assert!(output_words <= SHAKE256_RATE_WORDS);
    let zero = builder.add_constant_64(0);
    let mut state = [zero; 25];
    let full_blocks = frame_len_bytes / SHAKE256_RATE_BYTES;
    for block in 0..full_blocks {
        for word in 0..SHAKE256_RATE_WORDS {
            state[word] =
                builder.bxor(state[word], frame_words[block * SHAKE256_RATE_WORDS + word]);
        }
        keccak_f1600(builder, &mut state);
    }

    let remainder_bytes = frame_len_bytes % SHAKE256_RATE_BYTES;
    let base = full_blocks * SHAKE256_RATE_WORDS;
    for word in 0..remainder_bytes.div_ceil(8) {
        state[word] = builder.bxor(state[word], frame_words[base + word]);
    }
    let suffix_word = remainder_bytes / 8;
    let suffix_shift = (remainder_bytes % 8) * 8;
    state[suffix_word] = builder.bxor(
        state[suffix_word],
        builder.add_constant_64(SHAKE_DOMAIN_SUFFIX << suffix_shift),
    );
    state[SHAKE256_RATE_WORDS - 1] = builder.bxor(
        state[SHAKE256_RATE_WORDS - 1],
        builder.add_constant_64(0x80u64 << 56),
    );
    keccak_f1600(builder, &mut state);
    state[..output_words].to_vec()
}

pub fn canonical_fixture() -> (
    Pay1x2Statement,
    Pay1x2Witness,
    [u8; CANONICAL_STATEMENT_BYTES],
) {
    let (relation, witness) = valid_fixture().expect("the scalar KAT fixture must build");
    verify_relation(&relation, &witness).expect("the scalar KAT fixture must satisfy Pay1x2");
    let ciphertexts = [
        CanonicalCiphertextBytes::from_validated_exact(RECIPIENT_CIPHERTEXT).unwrap(),
        CanonicalCiphertextBytes::from_validated_exact(CHANGE_CIPHERTEXT).unwrap(),
    ];
    let statement = adapt_action(&relation, ciphertexts, KAT_NETWORK_IDENTITY)
        .expect("the scalar fixture must adapt to HGS2")
        .encode();
    (relation, witness, statement)
}

pub fn serialize_private_witness(witness: &Pay1x2Witness) -> [u8; PRIVATE_WITNESS_BYTES] {
    let mut bytes = Vec::with_capacity(PRIVATE_WITNESS_BYTES);
    bytes.extend_from_slice(&witness.spend_key);
    push_note_bytes(&mut bytes, &witness.input.note);
    bytes.extend_from_slice(&witness.input.position.to_be_bytes());
    for sibling in &witness.input.siblings {
        bytes.extend_from_slice(sibling.as_bytes());
    }
    push_note_bytes(&mut bytes, &witness.outputs[0]);
    push_note_bytes(&mut bytes, &witness.outputs[1]);
    bytes
        .try_into()
        .expect("the Pay1x2 witness is exactly 2,448 bytes")
}

fn push_note_bytes(output: &mut Vec<u8>, note: &NoteOpening) {
    output.extend_from_slice(&note.value.to_be_bytes());
    output.extend_from_slice(&note.asset_id.to_be_bytes());
    output.extend_from_slice(&note.pk_recipient);
    output.extend_from_slice(&note.rho);
    output.extend_from_slice(&note.randomness);
    output.extend_from_slice(&note.pk_auth);
}

pub fn pack_private_words(bytes: &[u8; PRIVATE_WITNESS_BYTES]) -> [u64; PRIVATE_WORDS] {
    array::from_fn(|word| u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap()))
}

pub fn pack_public_words(statement: &[u8; CANONICAL_STATEMENT_BYTES]) -> [u64; PUBLIC_WORDS] {
    array::from_fn(|word| {
        let start = word * 8;
        let mut bytes = [0u8; 8];
        if start < statement.len() {
            let take = (statement.len() - start).min(8);
            bytes[..take].copy_from_slice(&statement[start..start + take]);
        }
        u64::from_le_bytes(bytes)
    })
}

pub fn generate_fixture_witness(
    built: &BuiltPay1x2M4,
    witness: &Pay1x2Witness,
    statement: &[u8; CANONICAL_STATEMENT_BYTES],
) -> Result<WitnessM4, PopulateM4Error> {
    let private = pack_private_words(&serialize_private_witness(witness));
    let public = pack_public_words(statement);
    built.circuit.generate_witness(|filler| {
        for (&wire, value) in built.wires.private.iter().zip(private) {
            filler[wire] = Word(value);
        }
        for (&wire, value) in built.wires.public.iter().zip(public) {
            filler[wire] = Word(value);
        }
    })
}

pub fn circuit_stats(built: &BuiltPay1x2M4) -> CircuitStat {
    CircuitStat::collect(&built.circuit.main.circuit)
}

pub fn prove_and_check_gates(
    built: &BuiltPay1x2M4,
    witness: &WitnessM4,
    statement: &[u8; CANONICAL_STATEMENT_BYTES],
    log_inverse_rate: usize,
) -> ProofGateReport {
    let cs = built.circuit.to_constraint_system();
    cs.validate()
        .expect("the Pay1x2 M4 constraint system must validate");
    witness
        .verify(&cs)
        .expect("the generated KAT witness must satisfy the full M4 system");
    let verifier = VerifierM4::<StdHashSuite>::setup(&cs, log_inverse_rate)
        .expect("M4 verifier setup must succeed");
    let prover = ProverM4::<OptimalPackedB128, StdHashSuite>::setup(&verifier);
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    prover
        .prove(witness, &mut transcript)
        .expect("the full KAT witness must prove");
    let proof = transcript.finalize();
    let public = pack_public_words(statement).map(Word);
    let honest_roundtrip = verify_exact(&verifier, &public, &proof);

    let mutation_offsets = [
        0,
        5,
        7,
        9,
        10,
        11,
        12,
        13,
        21,
        OFFSET_FEE + 7,
        OFFSET_ANCHOR,
        OFFSET_NULLIFIER,
        OFFSET_OUTPUT_0,
        OFFSET_OUTPUT_1,
        OFFSET_CIPHERTEXT_0,
        OFFSET_CIPHERTEXT_1,
        OFFSET_NETWORK_BINDING,
        OFFSET_BALANCE_TAG,
    ];
    let all_public_mutations_rejected = mutation_offsets.into_iter().all(|offset| {
        let mut changed = *statement;
        changed[offset] ^= 1;
        !verify_exact(&verifier, &pack_public_words(&changed).map(Word), &proof)
    });

    let mut changed_proof = proof.clone();
    let flip = changed_proof.len() / 2;
    changed_proof[flip] ^= 1;
    let changed_proof_rejected = !verify_exact(&verifier, &public, &changed_proof);
    let mut trailing = proof.clone();
    trailing.push(0);
    let trailing_proof_rejected = !verify_exact(&verifier, &public, &trailing);

    ProofGateReport {
        log_inverse_rate,
        proof,
        honest_roundtrip,
        all_public_mutations_rejected,
        changed_proof_rejected,
        trailing_proof_rejected,
    }
}

fn verify_exact(verifier: &VerifierM4<StdHashSuite>, public: &[Word], proof: &[u8]) -> bool {
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    if verifier.verify(public, &mut transcript).is_err() {
        return false;
    }
    transcript.finalize().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegemon_standalone_pay1x2_relation_prototype::{
        derive_statement_unchecked, mutation_matrix, sparse_single_leaf_path,
    };
    use hegemon_standalone_shake256_prototype::derive_spend_key_material;

    #[test]
    fn exact_geometry_and_packing() {
        assert_eq!(PRIVATE_WORDS, 306);
        assert_eq!(PUBLIC_WORDS, 60);
        assert_eq!(DIGEST_WORDS, 7);
        assert_eq!(OFFSET_BALANCE_TAG + DIGEST_BYTES, PUBLIC_STATEMENT_BYTES);
        let (_, witness, statement) = canonical_fixture();
        assert_eq!(
            serialize_private_witness(&witness).len(),
            PRIVATE_WITNESS_BYTES
        );
        let public = pack_public_words(&statement);
        assert_eq!(public[59] >> 48, 0);
        assert_eq!(public[0], FIXED_PREFIX_0);
        assert_eq!(public[1], FIXED_PREFIX_1);
    }

    #[test]
    fn scalar_mutation_matrix_is_closed() {
        let outcomes = mutation_matrix().expect("the scalar mutation matrix must evaluate");
        assert_eq!(outcomes.len(), 30);
        assert!(outcomes.iter().all(|outcome| outcome.rejected));
    }

    #[test]
    fn full_circuit_kat_matches_scalar_and_binds_every_private_region() {
        let built = build_pay1x2_m4();
        let (_, witness, statement) = canonical_fixture();
        let honest = generate_fixture_witness(&built, &witness, &statement)
            .expect("the scalar KAT must satisfy the M4 circuit");
        honest
            .verify(&built.circuit.to_constraint_system())
            .expect("the generated M4 witness must verify natively");

        // One representative byte from every private semantic region, plus
        // every Merkle sibling, must affect the full circuit. These are raw
        // witness mutations against the unchanged authoritative statement.
        let mut offsets = vec![
            0, 48, 56, 64, 96, 144, 192, // spend key and input note fields
            248, // position
            2_048, 2_056, 2_064, 2_096, 2_144, 2_192, // recipient note
            2_248, 2_256, 2_264, 2_296, 2_344, 2_392, // change note
        ];
        offsets.extend((0..MERKLE_DEPTH).map(|level| 256 + level * DIGEST_BYTES));
        let private = serialize_private_witness(&witness);
        let public = pack_public_words(&statement);
        for offset in offsets {
            let mut changed = private;
            changed[offset] ^= 1;
            let private_words = pack_private_words(&changed);
            let result = built.circuit.generate_witness(|filler| {
                for (&wire, value) in built.wires.private.iter().zip(private_words) {
                    filler[wire] = Word(value);
                }
                for (&wire, value) in built.wires.public.iter().zip(public) {
                    filler[wire] = Word(value);
                }
            });
            assert!(result.is_err(), "private byte {offset} was not bound");
        }
    }

    #[test]
    fn deterministic_scalar_circuit_differential_variants_match() {
        let built = build_pay1x2_m4();
        let (_, base, _) = canonical_fixture();
        for seed in 1u8..=16 {
            let mut witness = base.clone();
            witness.spend_key = [seed.wrapping_mul(13); 48];
            let owner = derive_spend_key_material(&witness.spend_key);
            witness.input.note.pk_auth = owner.spend_auth_key.into_bytes();
            witness.outputs[1].pk_auth = owner.spend_auth_key.into_bytes();
            witness.input.note.rho = [seed.wrapping_add(0x20); 48];
            witness.input.note.randomness = [seed.wrapping_add(0x40); 48];
            witness.outputs[0].rho = [seed.wrapping_add(0x60); 48];
            witness.outputs[0].randomness = [seed.wrapping_add(0x80); 48];
            witness.outputs[1].rho = [seed.wrapping_add(0xa0); 48];
            witness.outputs[1].randomness = [seed.wrapping_add(0xc0); 48];
            witness.input.position = u64::from(seed) * 0x0101_0101;
            let fee = u64::from(seed % 7 + 1);
            witness.input.note.value = 10_000 + u64::from(seed) * 17;
            witness.outputs[0].value = 4_000 + u64::from(seed) * 3;
            witness.outputs[1].value = witness.input.note.value - witness.outputs[0].value - fee;
            let input_commitment = witness.input.note.commitment().unwrap();
            let (anchor, siblings) =
                sparse_single_leaf_path(witness.input.position, input_commitment).unwrap();
            witness.input.siblings = siblings;
            let mut relation = derive_statement_unchecked(&witness, fee).unwrap();
            relation.anchor = anchor;
            verify_relation(&relation, &witness)
                .unwrap_or_else(|error| panic!("scalar variant {seed} rejected: {error}"));
            let ciphertexts = [
                CanonicalCiphertextBytes::from_validated_exact(RECIPIENT_CIPHERTEXT).unwrap(),
                CanonicalCiphertextBytes::from_validated_exact(CHANGE_CIPHERTEXT).unwrap(),
            ];
            let statement = adapt_action(&relation, ciphertexts, KAT_NETWORK_IDENTITY)
                .unwrap()
                .encode();
            let generated = generate_fixture_witness(&built, &witness, &statement)
                .unwrap_or_else(|error| panic!("M4 variant {seed} rejected: {error}"));
            generated
                .verify(&built.circuit.to_constraint_system())
                .unwrap_or_else(|error| panic!("M4 variant {seed} failed: {error}"));
        }
    }
}
