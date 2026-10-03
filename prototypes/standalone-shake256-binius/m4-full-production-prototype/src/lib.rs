//! One-main native-word M4 realization of the prospective full V5/Delta
//! transfer relation.
//!
//! This crate is isolated research source. It is not reachable from consensus,
//! is not zero knowledge, and is not evidence for the strict PQ128 target.

#![forbid(unsafe_code)]

use std::array;

#[cfg(feature = "prototype-weak")]
use std::fmt;

use binius_circuits::{bytes::swap_bytes, keccak::permutation::keccak_f1600};
use binius_core::{constraint_system::m4::WitnessM4, Word};
use binius_frontend::{CircuitBuilder, CircuitM4, PopulateM4Error, Wire};
#[cfg(feature = "prototype-weak")]
use binius_hash::StdHashSuite;
#[cfg(feature = "prototype-weak")]
use binius_m4_prover::ProverM4;
#[cfg(feature = "prototype-weak")]
use binius_m4_verifier::VerifierM4;
#[cfg(feature = "prototype-weak")]
use binius_prover::OptimalPackedB128;
#[cfg(feature = "prototype-weak")]
use binius_transcript::{ProverTranscript, VerifierTranscript};
#[cfg(feature = "prototype-weak")]
use binius_verifier::config::StdChallenger;
#[cfg(feature = "prototype-weak")]
use hegemon_standalone_full_shake256_relation_prototype::composed_envelope::MAX_PROOF_BYTES;
use hegemon_standalone_full_shake256_relation_prototype::composed_envelope::{
    FullProofBinding, FullProofProverBinding,
};
#[cfg(feature = "prototype-weak")]
use hegemon_standalone_full_shake256_relation_prototype::decode_canonical_statement;
use hegemon_standalone_full_shake256_relation_prototype::{
    ActivationBinding, FullWitness, NoteKind, NoteOpening, PrivateAuthMode, BALANCE_SLOTS,
    CANONICAL_STATEMENT_BYTES, DIGEST_BYTES, FIELD_MODULUS, MAX_INPUTS, MAX_NOTE_VALUE,
    MAX_OUTPUTS, MAX_SIGNERS, MERKLE_DEPTH, NATIVE_ASSET_ID, PADDING_ASSET_ID,
    RESERVED_REDUCED_PADDING_ASSET_ID, SHIELDED_POOL_FAMILY_ID, STATEMENT_GRAMMAR_VERSION,
    STATEMENT_MAGIC, TARGET_ACTION_ID, TARGET_BACKEND_ID, TARGET_CIRCUIT_VERSION,
    TARGET_CRYPTO_SUITE, TARGET_PROOF_PROFILE,
};

#[cfg(all(feature = "prototype-weak", not(debug_assertions)))]
compile_error!("prototype-weak is a debug-only negative control and cannot be built for release");

pub const UPSTREAM_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
pub const PUBLIC_BYTES: usize = CANONICAL_STATEMENT_BYTES;
pub const STATEMENT_WORDS: usize = PUBLIC_BYTES.div_ceil(8);
pub const DERIVED_INTENT_WORDS: usize = DIGEST_WORDS;
pub const PUBLIC_WORDS: usize = STATEMENT_WORDS + DERIVED_INTENT_WORDS;
pub const PRIVATE_WORDS: usize = 671;
pub const PRIVATE_BYTES: usize = PRIVATE_WORDS * 8;
pub const INPUT_WORDS: usize = 261;
pub const OUTPUT_WORDS: usize = 30;
pub const AUTH_WORDS: usize = 89;
pub const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
pub const SHAKE256_RATE_BYTES: usize = 136;
pub const SHAKE256_RATE_WORDS: usize = SHAKE256_RATE_BYTES / 8;
/// Fixed upstream weak-profile rate. It is deliberately not caller-selectable.
#[cfg(feature = "prototype-weak")]
pub const WEAK_LOG_INVERSE_RATE: usize = 2;
/// The pinned upstream verifier hard-codes a 96-bit query target.
#[cfg(feature = "prototype-weak")]
pub const UPSTREAM_SECURITY_BITS: usize = binius_verifier::SECURITY_BITS;
/// The pinned M4 proof commits unmasked witness oracles.
#[cfg(feature = "prototype-weak")]
pub const BACKEND_IS_ZERO_KNOWLEDGE: bool = false;
/// This upstream profile has no strict composed PQ128 evidence.
#[cfg(feature = "prototype-weak")]
pub const BACKEND_IS_STRICT_PQ128: bool = false;
/// This isolated backend is never an authorized release verifier.
#[cfg(feature = "prototype-weak")]
pub const BACKEND_RELEASE_AUTHORIZED: bool = false;

pub const OFFSET_FLAGS: usize = 10;
pub const OFFSET_ANCHOR: usize = 14;
pub const OFFSET_NULLIFIERS: usize = 70;
pub const OFFSET_COMMITMENTS: usize = 182;
pub const OFFSET_CIPHERTEXT_HASHES: usize = 294;
pub const OFFSET_ASSETS: usize = 406;
pub const OFFSET_FEE: usize = 438;
pub const OFFSET_VALUE_BALANCE_SIGN: usize = 446;
pub const OFFSET_VALUE_BALANCE_MAGNITUDE: usize = 447;
pub const OFFSET_STABLE_ENABLED: usize = 455;
pub const OFFSET_STABLE_ASSET: usize = 456;
pub const OFFSET_STABLE_VERSION: usize = 464;
pub const OFFSET_STABLE_ISSUANCE_SIGN: usize = 468;
pub const OFFSET_STABLE_ISSUANCE_MAGNITUDE: usize = 469;
pub const OFFSET_STABLE_POLICY: usize = 477;
pub const OFFSET_STABLE_ORACLE: usize = 533;
pub const OFFSET_STABLE_ATTESTATION: usize = 589;
pub const OFFSET_BALANCE_TAG: usize = 645;
pub const OFFSET_ACTIVATION: usize = 701;

const PROFILE_TAG: [u8; 8] = *b"HEG-F4V1";
const ROLE_NOTE: [u8; 8] = *b"note.cm3";
const ROLE_NULLIFIER: [u8; 8] = *b"nullif.2";
const ROLE_MERKLE: [u8; 8] = *b"merk.nd2";
const ROLE_SPEND_KEYS: [u8; 8] = *b"sp.keys2";
const ROLE_POLICY: [u8; 8] = *b"policy.1";
const ROLE_ACCUMULATOR: [u8; 8] = *b"accum.01";
const ROLE_VALUE_LOCK: [u8; 8] = *b"val.lock";
const ROLE_INTENT: [u8; 8] = *b"intent.1";
const ROLE_BALANCE_TAG: [u8; 8] = *b"bal.tag1";
const KEY_OUTPUT_ORDER_TAG: [u8; 8] = *b"auth.nf1";
const SHAKE_DOMAIN_SUFFIX: u64 = 0x1f;

#[derive(Clone, Debug)]
struct NoteWords {
    /// Big-endian `u64` serialization of the private one-byte semantic tag.
    pub kind_be: Wire,
    pub value_be: Wire,
    pub asset_be: Wire,
    pub recipient: [Wire; 4],
    pub rho: [Wire; 6],
    pub randomness: [Wire; 6],
    pub auth: [Wire; DIGEST_WORDS],
}

#[derive(Clone, Debug)]
struct InputWords {
    pub spend_key: [Wire; 6],
    pub note: NoteWords,
    pub position_be: Wire,
    pub siblings: [[Wire; DIGEST_WORDS]; MERKLE_DEPTH],
    pub selectors_be: [Wire; BALANCE_SLOTS],
}

#[derive(Clone, Debug)]
struct OutputWords {
    pub note: NoteWords,
    pub selectors_be: [Wire; BALANCE_SLOTS],
}

#[derive(Clone, Debug)]
struct AccumulatorWords {
    pub policy_root: [Wire; DIGEST_WORDS],
    pub intent: [Wire; DIGEST_WORDS],
    pub threshold_be: Wire,
    pub signer_count_be: Wire,
    pub approval_count_be: Wire,
    pub approved_be: [Wire; MAX_SIGNERS],
}

impl AccumulatorWords {
    fn all_words(&self) -> Vec<Wire> {
        let mut words = Vec::with_capacity(23);
        words.extend(self.policy_root);
        words.extend(self.intent);
        words.push(self.threshold_be);
        words.push(self.signer_count_be);
        words.push(self.approval_count_be);
        words.extend(self.approved_be);
        words
    }
}

#[derive(Clone, Debug)]
struct AuthWords {
    pub mode_be: Wire,
    pub current: AccumulatorWords,
    pub next: AccumulatorWords,
    pub signer_tags: [[Wire; DIGEST_WORDS]; MAX_SIGNERS],
}

#[derive(Clone, Debug)]
struct DecodedPublic {
    pub input_flags: [Wire; MAX_INPUTS],
    pub output_flags: [Wire; MAX_OUTPUTS],
    pub anchor: [Wire; DIGEST_WORDS],
    pub nullifiers: [[Wire; DIGEST_WORDS]; MAX_INPUTS],
    pub commitments: [[Wire; DIGEST_WORDS]; MAX_OUTPUTS],
    pub ciphertext_hashes: [[Wire; DIGEST_WORDS]; MAX_OUTPUTS],
    pub assets: [Wire; BALANCE_SLOTS],
    pub fee: Wire,
    pub value_balance_sign: Wire,
    pub value_balance_magnitude: Wire,
    pub stable_enabled: Wire,
    pub stable_asset: Wire,
    pub stable_version: Wire,
    pub stable_issuance_sign: Wire,
    pub stable_issuance_magnitude: Wire,
    pub stable_policy: [Wire; DIGEST_WORDS],
    pub stable_oracle: [Wire; DIGEST_WORDS],
    pub stable_attestation: [Wire; DIGEST_WORDS],
    pub balance_tag: [Wire; DIGEST_WORDS],
}

#[derive(Clone, Debug)]
struct FullM4Wires {
    pub private: [Wire; PRIVATE_WORDS],
    pub public: [Wire; PUBLIC_WORDS],
    /// Derived by the composed verifier from the exact 853-byte statement.
    /// Raw M4 verification is intentionally not exported as an acceptance API.
    pub derived_intent: [Wire; DERIVED_INTENT_WORDS],
    pub statement: DecodedPublic,
    pub inputs: [InputWords; MAX_INPUTS],
    pub outputs: [OutputWords; MAX_OUTPUTS],
    pub auth: AuthWords,
}

struct BuiltFullM4 {
    circuit: CircuitM4,
    wires: FullM4Wires,
}

#[derive(Clone, Debug)]
struct ModeSelectors {
    single: Wire,
    init: Wire,
    approval: Wire,
    lock: Wire,
    final_spend: Wire,
}

#[derive(Clone, Debug)]
struct BalanceNote {
    value: Wire,
    selectors: [Wire; BALANCE_SLOTS],
}

#[derive(Clone, Debug)]
struct PolicySelectors {
    opening: AccumulatorWords,
    threshold: Wire,
    signer_count: Wire,
    slot_active: [Wire; MAX_SIGNERS],
}

impl ModeSelectors {
    fn all(&self) -> [Wire; 5] {
        [
            self.single,
            self.init,
            self.approval,
            self.lock,
            self.final_spend,
        ]
    }

    fn non_single(&self, builder: &CircuitBuilder) -> Wire {
        // `auth.mode.range` rejects every value outside 0..=4, and `single`
        // is exactly the equality test against zero.  On every accepted row,
        // its complement is therefore the union of the other four modes.
        builder.bnot(self.single)
    }
}

/// Build one M4 main circuit. No numbered chip is permitted: every constraint
/// and Keccak-f call is in the same main relation, avoiding the unconstrained
/// chip-call seam in the pinned experimental backend.
fn build_full_m4(expected_activation: &ActivationBinding) -> BuiltFullM4 {
    assert_authoritative_activation(expected_activation);
    let builder = CircuitBuilder::new();
    let private = array::from_fn(|_| builder.add_witness());
    let public = array::from_fn(|_| builder.add_inout());
    let statement = decode_public(&builder, &public[..STATEMENT_WORDS].try_into().unwrap());
    let derived_intent = public[STATEMENT_WORDS..PUBLIC_WORDS].try_into().unwrap();
    let (inputs, outputs, auth) = map_private(&private);
    let wires = FullM4Wires {
        private,
        public,
        derived_intent,
        statement,
        inputs,
        outputs,
        auth,
    };
    constrain_transport(&builder, &wires, expected_activation);
    let (modes, policy) = constrain_non_hash(&builder, &wires);
    constrain_hashes(&builder, &wires, &modes, &policy);
    let circuit = builder.build_m4();
    assert!(
        circuit.chips.is_empty(),
        "the full relation must remain in one M4 main circuit"
    );
    circuit
        .validate()
        .expect("the full single-main M4 circuit must validate");
    BuiltFullM4 { circuit, wires }
}

fn map_note(words: &[Wire]) -> NoteWords {
    assert_eq!(words.len(), 26);
    NoteWords {
        kind_be: words[0],
        value_be: words[1],
        asset_be: words[2],
        recipient: words[3..7].try_into().unwrap(),
        rho: words[7..13].try_into().unwrap(),
        randomness: words[13..19].try_into().unwrap(),
        auth: words[19..26].try_into().unwrap(),
    }
}

fn map_input(words: &[Wire]) -> InputWords {
    assert_eq!(words.len(), INPUT_WORDS);
    InputWords {
        spend_key: words[0..6].try_into().unwrap(),
        note: map_note(&words[6..32]),
        position_be: words[32],
        siblings: array::from_fn(|level| {
            let start = 33 + level * DIGEST_WORDS;
            words[start..start + DIGEST_WORDS].try_into().unwrap()
        }),
        selectors_be: words[257..261].try_into().unwrap(),
    }
}

fn map_output(words: &[Wire]) -> OutputWords {
    assert_eq!(words.len(), OUTPUT_WORDS);
    OutputWords {
        note: map_note(&words[0..26]),
        selectors_be: words[26..30].try_into().unwrap(),
    }
}

fn map_accumulator(words: &[Wire]) -> AccumulatorWords {
    assert_eq!(words.len(), 23);
    AccumulatorWords {
        policy_root: words[0..7].try_into().unwrap(),
        intent: words[7..14].try_into().unwrap(),
        threshold_be: words[14],
        signer_count_be: words[15],
        approval_count_be: words[16],
        approved_be: words[17..23].try_into().unwrap(),
    }
}

fn map_private(
    private: &[Wire; PRIVATE_WORDS],
) -> (
    [InputWords; MAX_INPUTS],
    [OutputWords; MAX_OUTPUTS],
    AuthWords,
) {
    let inputs = [map_input(&private[0..261]), map_input(&private[261..522])];
    let outputs = [
        map_output(&private[522..552]),
        map_output(&private[552..582]),
    ];
    let auth = AuthWords {
        mode_be: private[582],
        current: map_accumulator(&private[583..606]),
        next: map_accumulator(&private[606..629]),
        signer_tags: array::from_fn(|slot| {
            let start = 629 + slot * DIGEST_WORDS;
            private[start..start + DIGEST_WORDS].try_into().unwrap()
        }),
    };
    (inputs, outputs, auth)
}

fn decode_public(builder: &CircuitBuilder, public: &[Wire; STATEMENT_WORDS]) -> DecodedPublic {
    let input_flags = [
        public_byte(builder, public, OFFSET_FLAGS),
        public_byte(builder, public, OFFSET_FLAGS + 1),
    ];
    let output_flags = [
        public_byte(builder, public, OFFSET_FLAGS + 2),
        public_byte(builder, public, OFFSET_FLAGS + 3),
    ];
    let anchor = public_words_at(builder, public, OFFSET_ANCHOR);
    let nullifiers = array::from_fn(|index| {
        let start = OFFSET_NULLIFIERS + index * DIGEST_BYTES;
        public_words_at(builder, public, start)
    });
    let commitments = array::from_fn(|index| {
        let start = OFFSET_COMMITMENTS + index * DIGEST_BYTES;
        public_words_at(builder, public, start)
    });
    let ciphertext_hashes = array::from_fn(|index| {
        let start = OFFSET_CIPHERTEXT_HASHES + index * DIGEST_BYTES;
        public_words_at(builder, public, start)
    });
    let assets = array::from_fn(|slot| public_be_u64(builder, public, OFFSET_ASSETS + slot * 8));
    DecodedPublic {
        input_flags,
        output_flags,
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        assets,
        fee: public_be_u64(builder, public, OFFSET_FEE),
        value_balance_sign: public_byte(builder, public, OFFSET_VALUE_BALANCE_SIGN),
        value_balance_magnitude: public_be_u64(builder, public, OFFSET_VALUE_BALANCE_MAGNITUDE),
        stable_enabled: public_byte(builder, public, OFFSET_STABLE_ENABLED),
        stable_asset: public_be_u64(builder, public, OFFSET_STABLE_ASSET),
        stable_version: public_be_u32(builder, public, OFFSET_STABLE_VERSION),
        stable_issuance_sign: public_byte(builder, public, OFFSET_STABLE_ISSUANCE_SIGN),
        stable_issuance_magnitude: public_be_u64(builder, public, OFFSET_STABLE_ISSUANCE_MAGNITUDE),
        stable_policy: public_words_at(builder, public, OFFSET_STABLE_POLICY),
        stable_oracle: public_words_at(builder, public, OFFSET_STABLE_ORACLE),
        stable_attestation: public_words_at(builder, public, OFFSET_STABLE_ATTESTATION),
        balance_tag: public_words_at(builder, public, OFFSET_BALANCE_TAG),
    }
}

fn constrain_transport(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    expected_activation: &ActivationBinding,
) {
    let statement = &wires.statement;
    builder.assert_zero(
        "statement.trailing_word_padding",
        builder.band(
            wires.public[STATEMENT_WORDS - 1],
            builder.add_constant_64(0xffff_ff00_0000_0000),
        ),
    );
    assert_public_bytes_const(
        builder,
        "statement.magic",
        &wires.public[..STATEMENT_WORDS].try_into().unwrap(),
        0,
        &STATEMENT_MAGIC,
    );
    assert_public_bytes_const(
        builder,
        "statement.grammar_version",
        &wires.public[..STATEMENT_WORDS].try_into().unwrap(),
        8,
        &STATEMENT_GRAMMAR_VERSION.to_be_bytes(),
    );
    let activation = activation_bytes(expected_activation);
    assert_public_bytes_const(
        builder,
        "statement.activation",
        &wires.public[..STATEMENT_WORDS].try_into().unwrap(),
        OFFSET_ACTIVATION,
        &activation,
    );

    for (name, flag) in [
        ("input_flags[0]", statement.input_flags[0]),
        ("input_flags[1]", statement.input_flags[1]),
        ("output_flags[0]", statement.output_flags[0]),
        ("output_flags[1]", statement.output_flags[1]),
        ("value_balance.sign", statement.value_balance_sign),
        ("stable.enabled", statement.stable_enabled),
        ("stable.issuance_sign", statement.stable_issuance_sign),
    ] {
        assert_low_bool(builder, name, flag);
    }
}

fn constrain_non_hash(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
) -> (ModeSelectors, PolicySelectors) {
    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);
    let statement = &wires.statement;

    builder.assert_non_zero(
        "shape.input_nonempty",
        builder.bor(statement.input_flags[0], statement.input_flags[1]),
    );
    builder.assert_non_zero(
        "shape.output_nonempty",
        builder.bor(statement.output_flags[0], statement.output_flags[1]),
    );
    builder.assert_zero("value_balance.sign", statement.value_balance_sign);
    builder.assert_zero("value_balance.magnitude", statement.value_balance_magnitude);
    assert_61_bit(builder, "fee", statement.fee);
    assert_61_bit(
        builder,
        "stable.issuance_magnitude",
        statement.stable_issuance_magnitude,
    );
    let issuance_zero = builder.icmp_eq(statement.stable_issuance_magnitude, zero);
    builder.assert_eq_cond(
        "stable.issuance.no_negative_zero",
        statement.stable_issuance_sign,
        zero,
        issuance_zero,
    );

    constrain_slots(builder, statement);
    constrain_stablecoin(builder, statement);

    let balance_inputs: [BalanceNote; MAX_INPUTS] = array::from_fn(|index| {
        let inactive = builder.bnot(low_bool_msb(builder, statement.input_flags[index]));
        assert_words_zero_cond(
            builder,
            &format!("input[{index}].inactive"),
            &wires.private[index * INPUT_WORDS..(index + 1) * INPUT_WORDS],
            inactive,
        );
        let balance_note = constrain_note_and_selectors(
            builder,
            &format!("input[{index}]"),
            &wires.inputs[index].note,
            &wires.inputs[index].selectors_be,
            statement.input_flags[index],
            &statement.assets,
        );
        let position = swap_bytes(builder, wires.inputs[index].position_be);
        builder.assert_zero(
            format!("input[{index}].position.high32"),
            builder.shr(position, 32),
        );
        let inactive_public = builder.bnot(low_bool_msb(builder, statement.input_flags[index]));
        assert_digest_zero_cond(
            builder,
            &format!("nullifier[{index}].inactive"),
            &statement.nullifiers[index],
            inactive_public,
        );
        balance_note
    });
    let balance_outputs: [BalanceNote; MAX_OUTPUTS] = array::from_fn(|index| {
        let inactive = builder.bnot(low_bool_msb(builder, statement.output_flags[index]));
        let start = 522 + index * OUTPUT_WORDS;
        assert_words_zero_cond(
            builder,
            &format!("output[{index}].inactive"),
            &wires.private[start..start + OUTPUT_WORDS],
            inactive,
        );
        let balance_note = constrain_note_and_selectors(
            builder,
            &format!("output[{index}]"),
            &wires.outputs[index].note,
            &wires.outputs[index].selectors_be,
            statement.output_flags[index],
            &statement.assets,
        );
        assert_digest_zero_cond(
            builder,
            &format!("commitment[{index}].inactive"),
            &statement.commitments[index],
            inactive,
        );
        assert_digest_zero_cond(
            builder,
            &format!("ciphertext[{index}].inactive"),
            &statement.ciphertext_hashes[index],
            inactive,
        );
        let active = low_bool_msb(builder, statement.output_flags[index]);
        assert_digest_nonzero_cond(
            builder,
            &format!("ciphertext[{index}].active_nonzero"),
            &statement.ciphertext_hashes[index],
            active,
        );
        balance_note
    });
    let both_inputs = and_msb(
        builder,
        low_bool_msb(builder, statement.input_flags[0]),
        low_bool_msb(builder, statement.input_flags[1]),
    );
    assert_digest_unequal_cond(
        builder,
        "nullifiers.distinct",
        &statement.nullifiers[0],
        &statement.nullifiers[1],
        both_inputs,
    );

    let mode = swap_bytes(builder, wires.auth.mode_be);
    builder.assert_true(
        "auth.mode.range",
        builder.icmp_ule(mode, builder.add_constant_64(4)),
    );
    let modes = ModeSelectors {
        single: builder.icmp_eq(mode, zero),
        init: builder.icmp_eq(mode, one),
        approval: builder.icmp_eq(mode, builder.add_constant_64(2)),
        lock: builder.icmp_eq(mode, builder.add_constant_64(3)),
        final_spend: builder.icmp_eq(mode, builder.add_constant_64(4)),
    };
    let policy_opening =
        select_accumulator(builder, modes.init, &wires.auth.next, &wires.auth.current);
    let policy_threshold = swap_bytes(builder, policy_opening.threshold_be);
    let policy_signer_count = swap_bytes(builder, policy_opening.signer_count_be);
    let policy = PolicySelectors {
        opening: policy_opening,
        threshold: policy_threshold,
        signer_count: policy_signer_count,
        slot_active: array::from_fn(|slot| {
            builder.icmp_ult(builder.add_constant_64(slot as u64), policy_signer_count)
        }),
    };
    constrain_auth_non_hash(builder, wires, &modes, &policy);
    constrain_balance(builder, wires, &balance_inputs, &balance_outputs);
    (modes, policy)
}

fn constrain_slots(builder: &CircuitBuilder, statement: &DecodedPublic) {
    let zero = builder.add_constant_64(0);
    let padding = builder.add_constant_64(PADDING_ASSET_ID);
    let modulus = builder.add_constant_64(FIELD_MODULUS);
    let reduced_padding = builder.add_constant_64(RESERVED_REDUCED_PADDING_ASSET_ID);
    builder.assert_eq("assets[0].native", statement.assets[0], zero);

    for slot in 1..BALANCE_SLOTS {
        let asset = statement.assets[slot];
        let is_padding = builder.icmp_eq(asset, padding);
        let nonpadding = builder.bnot(is_padding);
        assert_implies(
            builder,
            &format!("assets[{slot}].field_range"),
            nonpadding,
            builder.icmp_ult(asset, modulus),
        );
        assert_implies(
            builder,
            &format!("assets[{slot}].reduced_padding_alias"),
            nonpadding,
            builder.icmp_ne(asset, reduced_padding),
        );
        assert_implies(
            builder,
            &format!("assets[{slot}].nonnative"),
            nonpadding,
            builder.icmp_ne(asset, zero),
        );
        let previous_padding = builder.icmp_eq(statement.assets[slot - 1], padding);
        assert_implies(
            builder,
            &format!("assets[{slot}].padding_suffix"),
            previous_padding,
            is_padding,
        );
        let previous_nonpadding = builder.bnot(previous_padding);
        let both_nonpadding = and_msb(builder, previous_nonpadding, nonpadding);
        assert_implies(
            builder,
            &format!("assets[{slot}].strict_order"),
            both_nonpadding,
            builder.icmp_ult(statement.assets[slot - 1], asset),
        );
    }
}

fn constrain_stablecoin(builder: &CircuitBuilder, statement: &DecodedPublic) {
    let zero = builder.add_constant_64(0);
    let enabled = low_bool_msb(builder, statement.stable_enabled);
    let disabled = builder.bnot(enabled);

    builder.assert_eq_cond(
        "stable.disabled.asset",
        statement.stable_asset,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.version",
        statement.stable_version,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.issuance_sign",
        statement.stable_issuance_sign,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.issuance_magnitude",
        statement.stable_issuance_magnitude,
        zero,
        disabled,
    );
    for (name, digest) in [
        ("policy", &statement.stable_policy),
        ("oracle", &statement.stable_oracle),
        ("attestation", &statement.stable_attestation),
    ] {
        assert_digest_zero_cond(
            builder,
            &format!("stable.disabled.{name}"),
            digest,
            disabled,
        );
        assert_digest_nonzero_cond(builder, &format!("stable.enabled.{name}"), digest, enabled);
    }

    assert_implies(
        builder,
        "stable.enabled.asset_nonzero",
        enabled,
        builder.icmp_ne(statement.stable_asset, zero),
    );
    assert_implies(
        builder,
        "stable.enabled.asset_range",
        enabled,
        builder.icmp_ult(
            statement.stable_asset,
            builder.add_constant_64(FIELD_MODULUS),
        ),
    );
    assert_implies(
        builder,
        "stable.enabled.asset_alias",
        enabled,
        builder.icmp_ne(
            statement.stable_asset,
            builder.add_constant_64(RESERVED_REDUCED_PADDING_ASSET_ID),
        ),
    );
    assert_implies(
        builder,
        "stable.enabled.version",
        enabled,
        builder.icmp_ne(statement.stable_version, zero),
    );
    assert_implies(
        builder,
        "stable.enabled.nonzero_delta",
        enabled,
        builder.icmp_ne(statement.stable_issuance_magnitude, zero),
    );
    let matches_slot = or_msb(
        builder,
        &statement
            .assets
            .map(|asset| builder.icmp_eq(statement.stable_asset, asset)),
    );
    assert_implies(
        builder,
        "stable.enabled.slotted_asset",
        enabled,
        matches_slot,
    );
}

fn constrain_note_and_selectors(
    builder: &CircuitBuilder,
    name: &str,
    note: &NoteWords,
    selectors_be: &[Wire; BALANCE_SLOTS],
    active_low: Wire,
    assets: &[Wire; BALANCE_SLOTS],
) -> BalanceNote {
    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);
    let active = low_bool_msb(builder, active_low);
    let kind = swap_bytes(builder, note.kind_be);
    assert_implies(
        builder,
        &format!("{name}.kind.range"),
        active,
        builder.icmp_ule(kind, builder.add_constant_64(2)),
    );
    let value = swap_bytes(builder, note.value_be);
    assert_61_bit(builder, &format!("{name}.value"), value);
    let asset = swap_bytes(builder, note.asset_be);
    assert_implies(
        builder,
        &format!("{name}.asset.range"),
        active,
        builder.icmp_ult(asset, builder.add_constant_64(FIELD_MODULUS)),
    );
    assert_implies(
        builder,
        &format!("{name}.asset.alias"),
        active,
        builder.icmp_ne(
            asset,
            builder.add_constant_64(RESERVED_REDUCED_PADDING_ASSET_ID),
        ),
    );

    let selectors = selectors_be.map(|wire| swap_bytes(builder, wire));
    for (slot, selector) in selectors.iter().enumerate() {
        assert_low_bool(builder, &format!("{name}.selector[{slot}]"), *selector);
    }
    let mut selector_sum = zero;
    for selector in selectors {
        let (next, carry) = builder.iadd(selector_sum, selector);
        builder.assert_false(format!("{name}.selector_sum_overflow"), carry);
        selector_sum = next;
    }
    builder.assert_eq_cond(format!("{name}.one_selector"), selector_sum, one, active);
    let selected_asset = selectors
        .iter()
        .enumerate()
        .fold(zero, |selected, (slot, selector)| {
            builder.select(low_bool_msb(builder, *selector), assets[slot], selected)
        });
    builder.assert_eq_cond(
        format!("{name}.selected_asset"),
        selected_asset,
        asset,
        active,
    );
    BalanceNote { value, selectors }
}

fn constrain_auth_non_hash(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    modes: &ModeSelectors,
    policy: &PolicySelectors,
) {
    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);
    let statement = &wires.statement;
    let in_active = statement
        .input_flags
        .map(|flag| low_bool_msb(builder, flag));
    let out_active = statement
        .output_flags
        .map(|flag| low_bool_msb(builder, flag));

    // Single-key mode has no auxiliary policy state and can only move ordinary
    // notes. Special note kinds therefore require a typed creation transition.
    let mut single_aux = wires.auth.current.all_words();
    single_aux.extend(wires.auth.next.all_words());
    single_aux.extend(wires.auth.signer_tags.iter().flatten().copied());
    assert_words_zero_cond(builder, "auth.single.aux", &single_aux, modes.single);
    for index in 0..MAX_INPUTS {
        assert_numeric_eq_cond(
            builder,
            &format!("auth.single.input[{index}].ordinary"),
            wires.inputs[index].note.kind_be,
            0,
            and_msb(builder, modes.single, in_active[index]),
        );
    }
    for index in 0..MAX_OUTPUTS {
        assert_numeric_eq_cond(
            builder,
            &format!("auth.single.output[{index}].ordinary"),
            wires.outputs[index].note.kind_be,
            0,
            and_msb(builder, modes.single, out_active[index]),
        );
    }

    // Init: ordinary inputs -> zero/native accumulator output 0, with a valid
    // zero-approval next policy and a canonical zero current lane.
    assert_flag_cond(
        builder,
        "auth.init.output0",
        statement.output_flags[0],
        true,
        modes.init,
    );
    for index in 0..MAX_INPUTS {
        assert_numeric_eq_cond(
            builder,
            &format!("auth.init.input[{index}].ordinary"),
            wires.inputs[index].note.kind_be,
            0,
            and_msb(builder, modes.init, in_active[index]),
        );
    }
    assert_numeric_eq_cond(
        builder,
        "auth.init.output0.accumulator",
        wires.outputs[0].note.kind_be,
        1,
        modes.init,
    );
    constrain_zero_native_note(
        builder,
        "auth.init.output0",
        &wires.outputs[0].note,
        modes.init,
    );
    assert_words_zero_cond(
        builder,
        "auth.init.current_zero",
        &wires.auth.current.all_words(),
        modes.init,
    );
    builder.assert_eq_cond(
        "auth.init.next.approval_count",
        swap_bytes(builder, wires.auth.next.approval_count_be),
        zero,
        modes.init,
    );
    for (slot, approved) in wires.auth.next.approved_be.iter().enumerate() {
        builder.assert_eq_cond(
            format!("auth.init.next.approved[{slot}]"),
            swap_bytes(builder, *approved),
            zero,
            modes.init,
        );
    }
    constrain_optional_ordinary_output1(builder, wires, modes.init, "auth.init");

    // Approval: exact two inputs, accumulator transition in slot 0 and an
    // ordinary signer note in slot 1. Output 1 remains optional ordinary.
    for (index, flag) in statement.input_flags.iter().enumerate() {
        assert_flag_cond(
            builder,
            &format!("auth.approval.input[{index}]"),
            *flag,
            true,
            modes.approval,
        );
    }
    assert_flag_cond(
        builder,
        "auth.approval.output0",
        statement.output_flags[0],
        true,
        modes.approval,
    );
    assert_numeric_eq_cond(
        builder,
        "auth.approval.input0.accumulator",
        wires.inputs[0].note.kind_be,
        1,
        modes.approval,
    );
    assert_numeric_eq_cond(
        builder,
        "auth.approval.input1.ordinary",
        wires.inputs[1].note.kind_be,
        0,
        modes.approval,
    );
    assert_numeric_eq_cond(
        builder,
        "auth.approval.output0.accumulator",
        wires.outputs[0].note.kind_be,
        1,
        modes.approval,
    );
    constrain_zero_native_note(
        builder,
        "auth.approval.input0",
        &wires.inputs[0].note,
        modes.approval,
    );
    constrain_zero_native_note(
        builder,
        "auth.approval.output0",
        &wires.outputs[0].note,
        modes.approval,
    );
    assert_words_zero_cond(
        builder,
        "auth.approval.input0.unused_spend_key",
        &wires.inputs[0].spend_key,
        modes.approval,
    );
    constrain_optional_ordinary_output1(builder, wires, modes.approval, "auth.approval");
    constrain_equal_accumulator_metadata(
        builder,
        "auth.approval.metadata",
        &wires.auth.current,
        &wires.auth.next,
        modes.approval,
    );
    let current_approvals = swap_bytes(builder, wires.auth.current.approval_count_be);
    let next_approvals = swap_bytes(builder, wires.auth.next.approval_count_be);
    let (incremented, carry) = builder.iadd(current_approvals, one);
    builder.assert_false("auth.approval.increment_overflow", carry);
    builder.assert_eq_cond(
        "auth.approval.increment",
        next_approvals,
        incremented,
        modes.approval,
    );

    // Value-lock creation: ordinary inputs -> typed value-lock output 0. The
    // current opening is the zero-approval policy descriptor; next is zero.
    assert_flag_cond(
        builder,
        "auth.lock.output0",
        statement.output_flags[0],
        true,
        modes.lock,
    );
    for index in 0..MAX_INPUTS {
        assert_numeric_eq_cond(
            builder,
            &format!("auth.lock.input[{index}].ordinary"),
            wires.inputs[index].note.kind_be,
            0,
            and_msb(builder, modes.lock, in_active[index]),
        );
    }
    assert_numeric_eq_cond(
        builder,
        "auth.lock.output0.value_lock",
        wires.outputs[0].note.kind_be,
        2,
        modes.lock,
    );
    constrain_optional_ordinary_output1(builder, wires, modes.lock, "auth.lock");
    assert_words_zero_cond(
        builder,
        "auth.lock.next_zero",
        &wires.auth.next.all_words(),
        modes.lock,
    );
    builder.assert_eq_cond(
        "auth.lock.current.approval_count",
        swap_bytes(builder, wires.auth.current.approval_count_be),
        zero,
        modes.lock,
    );
    for (slot, approved) in wires.auth.current.approved_be.iter().enumerate() {
        builder.assert_eq_cond(
            format!("auth.lock.current.approved[{slot}]"),
            swap_bytes(builder, *approved),
            zero,
            modes.lock,
        );
    }

    // Final: exact typed value-lock + accumulator inputs and only ordinary
    // outputs. Raw spend keys and raw next opening are canonical zero.
    for (index, flag) in statement.input_flags.iter().enumerate() {
        assert_flag_cond(
            builder,
            &format!("auth.final.input[{index}]"),
            *flag,
            true,
            modes.final_spend,
        );
    }
    assert_numeric_eq_cond(
        builder,
        "auth.final.input0.value_lock",
        wires.inputs[0].note.kind_be,
        2,
        modes.final_spend,
    );
    assert_numeric_eq_cond(
        builder,
        "auth.final.input1.accumulator",
        wires.inputs[1].note.kind_be,
        1,
        modes.final_spend,
    );
    constrain_zero_native_note(
        builder,
        "auth.final.input1",
        &wires.inputs[1].note,
        modes.final_spend,
    );
    for index in 0..MAX_OUTPUTS {
        assert_numeric_eq_cond(
            builder,
            &format!("auth.final.output[{index}].ordinary"),
            wires.outputs[index].note.kind_be,
            0,
            and_msb(builder, modes.final_spend, out_active[index]),
        );
    }
    for index in 0..MAX_INPUTS {
        assert_words_zero_cond(
            builder,
            &format!("auth.final.input[{index}].unused_spend_key"),
            &wires.inputs[index].spend_key,
            modes.final_spend,
        );
    }
    assert_words_zero_cond(
        builder,
        "auth.final.next_zero",
        &wires.auth.next.all_words(),
        modes.final_spend,
    );
    let final_approvals = swap_bytes(builder, wires.auth.current.approval_count_be);
    assert_implies(
        builder,
        "auth.final.threshold_reached",
        modes.final_spend,
        builder.icmp_uge(final_approvals, policy.threshold),
    );

    // Every non-single transition has one canonical policy structure. Init
    // selects next; Approval/Lock/Final select current. In Approval, the
    // current/next metadata equality above makes both lanes the same policy.
    constrain_policy_structure(
        builder,
        "auth.policy",
        policy,
        &wires.auth.signer_tags,
        modes.non_single(builder),
    );
    constrain_policy_approval_state(builder, "auth.current", &wires.auth.current, policy);
    constrain_policy_approval_state(builder, "auth.next", &wires.auth.next, policy);

    let mut changed_count = zero;
    for slot in 0..MAX_SIGNERS {
        let current = swap_bytes(builder, wires.auth.current.approved_be[slot]);
        let next = swap_bytes(builder, wires.auth.next.approved_be[slot]);
        let changed = builder.bxor(current, next);
        let current_true = low_bool_msb(builder, current);
        let next_true = low_bool_msb(builder, next);
        assert_implies(
            builder,
            &format!("auth.approval.no_clear[{slot}]"),
            and_msb(builder, modes.approval, current_true),
            next_true,
        );
        let (sum, carry) = builder.iadd(changed_count, changed);
        builder.assert_false(format!("auth.approval.changed_overflow[{slot}]"), carry);
        changed_count = sum;
    }
    builder.assert_eq_cond(
        "auth.approval.exactly_one_changed_slot",
        changed_count,
        one,
        modes.approval,
    );
}

fn constrain_policy_structure(
    builder: &CircuitBuilder,
    name: &str,
    policy: &PolicySelectors,
    signer_tags: &[[Wire; DIGEST_WORDS]; MAX_SIGNERS],
    active: Wire,
) {
    let one = builder.add_constant_64(1);
    let six = builder.add_constant_64(MAX_SIGNERS as u64);
    assert_implies(
        builder,
        &format!("{name}.signer_count.lower"),
        active,
        builder.icmp_uge(policy.signer_count, one),
    );
    assert_implies(
        builder,
        &format!("{name}.signer_count.upper"),
        active,
        builder.icmp_ule(policy.signer_count, six),
    );
    assert_implies(
        builder,
        &format!("{name}.threshold.lower"),
        active,
        builder.icmp_uge(policy.threshold, one),
    );
    assert_implies(
        builder,
        &format!("{name}.threshold.upper"),
        active,
        builder.icmp_ule(policy.threshold, policy.signer_count),
    );
    assert_digest_nonzero_cond(
        builder,
        &format!("{name}.intent"),
        &policy.opening.intent,
        active,
    );

    for slot in 0..MAX_SIGNERS {
        let slot_active = policy.slot_active[slot];
        assert_digest_nonzero_cond(
            builder,
            &format!("{name}.tag[{slot}].nonzero"),
            &signer_tags[slot],
            slot_active,
        );
        assert_digest_zero_cond(
            builder,
            &format!("{name}.tag[{slot}].inactive"),
            &signer_tags[slot],
            builder.bnot(slot_active),
        );

        for previous in 0..slot {
            assert_digest_unequal_cond(
                builder,
                &format!("{name}.tags[{previous},{slot}].unique"),
                &signer_tags[previous],
                &signer_tags[slot],
                slot_active,
            );
        }
    }
}

fn constrain_policy_approval_state(
    builder: &CircuitBuilder,
    name: &str,
    opening: &AccumulatorWords,
    policy: &PolicySelectors,
) {
    let zero = builder.add_constant_64(0);
    let approval_count = swap_bytes(builder, opening.approval_count_be);
    builder.assert_true(
        format!("{name}.approval_count"),
        builder.icmp_ule(approval_count, policy.signer_count),
    );

    let mut approved_sum = zero;
    for slot in 0..MAX_SIGNERS {
        let approved = swap_bytes(builder, opening.approved_be[slot]);
        // This check and the addition/carry chain were unconditional before
        // the refactor and remain so.
        assert_low_bool(builder, &format!("{name}.approved[{slot}]"), approved);
        let (sum, carry) = builder.iadd(approved_sum, approved);
        builder.assert_false(format!("{name}.approved_sum_overflow[{slot}]"), carry);
        approved_sum = sum;
        builder.assert_eq_cond(
            format!("{name}.approved[{slot}].inactive"),
            approved,
            zero,
            builder.bnot(policy.slot_active[slot]),
        );
    }
    builder.assert_eq(
        format!("{name}.approval_popcount"),
        approved_sum,
        approval_count,
    );
}

fn constrain_equal_accumulator_metadata(
    builder: &CircuitBuilder,
    name: &str,
    current: &AccumulatorWords,
    next: &AccumulatorWords,
    active: Wire,
) {
    assert_digest_eq_cond(
        builder,
        &format!("{name}.policy_root"),
        &current.policy_root,
        &next.policy_root,
        active,
    );
    assert_digest_eq_cond(
        builder,
        &format!("{name}.intent"),
        &current.intent,
        &next.intent,
        active,
    );
    for (field, left, right) in [
        ("threshold", current.threshold_be, next.threshold_be),
        (
            "signer_count",
            current.signer_count_be,
            next.signer_count_be,
        ),
    ] {
        builder.assert_eq_cond(format!("{name}.{field}"), left, right, active);
    }
}

fn constrain_optional_ordinary_output1(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    mode: Wire,
    name: &str,
) {
    let output1_active = low_bool_msb(builder, wires.statement.output_flags[1]);
    assert_numeric_eq_cond(
        builder,
        &format!("{name}.output1.ordinary"),
        wires.outputs[1].note.kind_be,
        0,
        and_msb(builder, mode, output1_active),
    );
}

fn constrain_zero_native_note(
    builder: &CircuitBuilder,
    name: &str,
    note: &NoteWords,
    active: Wire,
) {
    let zero = builder.add_constant_64(0);
    builder.assert_eq_cond(
        format!("{name}.zero_value"),
        swap_bytes(builder, note.value_be),
        zero,
        active,
    );
    builder.assert_eq_cond(
        format!("{name}.native_asset"),
        swap_bytes(builder, note.asset_be),
        builder.add_constant_64(NATIVE_ASSET_ID),
        active,
    );
}

fn constrain_balance(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    balance_inputs: &[BalanceNote; MAX_INPUTS],
    balance_outputs: &[BalanceNote; MAX_OUTPUTS],
) {
    let statement = &wires.statement;
    let zero = builder.add_constant_64(0);
    let enabled = low_bool_msb(builder, statement.stable_enabled);
    let issuance_negative = low_bool_msb(builder, statement.stable_issuance_sign);

    for slot in 0..BALANCE_SLOTS {
        let mut inputs = zero;
        let mut outputs = zero;
        for index in 0..MAX_INPUTS {
            let selector = balance_inputs[index].selectors[slot];
            let value = balance_inputs[index].value;
            let contribution = builder.select(low_bool_msb(builder, selector), value, zero);
            let (sum, carry) = builder.iadd(inputs, contribution);
            builder.assert_false(format!("balance[{slot}].input_overflow[{index}]"), carry);
            inputs = sum;
        }
        for index in 0..MAX_OUTPUTS {
            let selector = balance_outputs[index].selectors[slot];
            let value = balance_outputs[index].value;
            let contribution = builder.select(low_bool_msb(builder, selector), value, zero);
            let (sum, carry) = builder.iadd(outputs, contribution);
            builder.assert_false(format!("balance[{slot}].output_overflow[{index}]"), carry);
            outputs = sum;
        }

        if slot == 0 {
            let (outputs_and_fee, carry) = builder.iadd(outputs, statement.fee);
            builder.assert_false("balance.native.fee_overflow", carry);
            builder.assert_eq("balance.native", inputs, outputs_and_fee);
            continue;
        }

        let asset = statement.assets[slot];
        let padding = builder.icmp_eq(asset, builder.add_constant_64(PADDING_ASSET_ID));
        builder.assert_eq_cond(
            format!("balance[{slot}].padding_inputs"),
            inputs,
            zero,
            padding,
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].padding_outputs"),
            outputs,
            zero,
            padding,
        );

        let stable_slot = and_msb(
            builder,
            enabled,
            builder.icmp_eq(asset, statement.stable_asset),
        );
        let mint = and_msb(builder, stable_slot, issuance_negative);
        let burn = and_msb(builder, stable_slot, builder.bnot(issuance_negative));
        let (inputs_and_mint, mint_carry) =
            builder.iadd(inputs, statement.stable_issuance_magnitude);
        assert_implies(
            builder,
            &format!("balance[{slot}].mint_no_overflow"),
            mint,
            builder.bnot(mint_carry),
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].mint"),
            outputs,
            inputs_and_mint,
            mint,
        );
        let (outputs_and_burn, burn_carry) =
            builder.iadd(outputs, statement.stable_issuance_magnitude);
        assert_implies(
            builder,
            &format!("balance[{slot}].burn_no_overflow"),
            burn,
            builder.bnot(burn_carry),
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].burn"),
            inputs,
            outputs_and_burn,
            burn,
        );
        let ordinary = builder.bnot(stable_slot);
        builder.assert_eq_cond(
            format!("balance[{slot}].ordinary"),
            inputs,
            outputs,
            ordinary,
        );
    }
}

fn constrain_hashes(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    modes: &ModeSelectors,
    policy: &PolicySelectors,
) {
    let statement = &wires.statement;
    let in_active = statement
        .input_flags
        .map(|flag| low_bool_msb(builder, flag));
    let out_active = statement
        .output_flags
        .map(|flag| low_bool_msb(builder, flag));

    let spend_material: [[Wire; DIGEST_WORDS * 2]; MAX_INPUTS] = array::from_fn(|index| {
        let frame = spend_key_frame(builder, &wires.inputs[index].spend_key);
        shake256_words(builder, &frame.words, frame.len_bytes, DIGEST_WORDS * 2)
            .try_into()
            .unwrap()
    });
    let spend_auth: [[Wire; DIGEST_WORDS]; MAX_INPUTS] =
        array::from_fn(|index| spend_material[index][..DIGEST_WORDS].try_into().unwrap());
    let spend_nf: [[Wire; DIGEST_WORDS]; MAX_INPUTS] =
        array::from_fn(|index| spend_material[index][DIGEST_WORDS..].try_into().unwrap());

    // One policy pipeline is shared by all non-single modes. Init selects the
    // next opening; Approval/Lock/Final select current. Single hashes a
    // canonical all-zero opening but cannot consume the result.
    let policy_frame = policy_frame(builder, &policy.opening, &wires.auth.signer_tags);
    let policy_digest: [Wire; DIGEST_WORDS] = shake256_words(
        builder,
        &policy_frame.words,
        policy_frame.len_bytes,
        DIGEST_WORDS,
    )
    .try_into()
    .unwrap();
    assert_digest_eq_cond(
        builder,
        "auth.policy_root",
        &policy_digest,
        &policy.opening.policy_root,
        modes.non_single(builder),
    );

    // Two two-permutation pipelines cover every mode. This is the actual
    // branch multiplexing: inactive branches contribute a canonical 136-byte
    // dummy absorption, not a separately instantiated hash circuit.
    let dummy = dummy_frame(builder, SHAKE256_RATE_BYTES);
    let init_accumulator = accumulator_frame(builder, &wires.auth.next);
    let current_accumulator = accumulator_frame(builder, &wires.auth.current);
    let next_accumulator = accumulator_frame(builder, &wires.auth.next);
    let value_lock = value_lock_frame(
        builder,
        &wires.auth.current.policy_root,
        &wires.auth.current.intent,
    );
    let current_a = or_msb(builder, &[modes.approval, modes.final_spend]);
    let slot_a: [Wire; DIGEST_WORDS * 2] = mux_one_hot_shake256_words(
        builder,
        &dummy,
        &[
            // Put the shortest frame first.  Its zero suffix then remains the
            // default on words it does not occupy, so identical-arm selects
            // fold before either longer frame is considered.
            (modes.lock, &value_lock),
            (modes.init, &init_accumulator),
            (current_a, &current_accumulator),
        ],
        2,
        DIGEST_WORDS * 2,
    )
    .try_into()
    .unwrap();
    let slot_b: [Wire; DIGEST_WORDS * 2] = mux_one_hot_shake256_words(
        builder,
        &dummy,
        &[
            (modes.final_spend, &value_lock),
            (modes.approval, &next_accumulator),
        ],
        2,
        DIGEST_WORDS * 2,
    )
    .try_into()
    .unwrap();
    let slot_a_auth: [Wire; DIGEST_WORDS] = slot_a[..DIGEST_WORDS].try_into().unwrap();
    let slot_a_nf: [Wire; DIGEST_WORDS] = slot_a[DIGEST_WORDS..].try_into().unwrap();
    let slot_b_auth: [Wire; DIGEST_WORDS] = slot_b[..DIGEST_WORDS].try_into().unwrap();
    let slot_b_nf: [Wire; DIGEST_WORDS] = slot_b[DIGEST_WORDS..].try_into().unwrap();

    let mut resolved_auth = spend_auth;
    let mut resolved_nf = spend_nf;
    resolved_auth[0] = select_digest(builder, modes.approval, &slot_a_auth, &resolved_auth[0]);
    resolved_nf[0] = select_digest(builder, modes.approval, &slot_a_nf, &resolved_nf[0]);
    resolved_auth[0] = select_digest(builder, modes.final_spend, &slot_b_auth, &resolved_auth[0]);
    resolved_nf[0] = select_digest(builder, modes.final_spend, &slot_b_nf, &resolved_nf[0]);
    resolved_auth[1] = select_digest(builder, modes.final_spend, &slot_a_auth, &resolved_auth[1]);
    resolved_nf[1] = select_digest(builder, modes.final_spend, &slot_a_nf, &resolved_nf[1]);

    let output0_init_or_lock = or_msb(builder, &[modes.init, modes.lock]);
    assert_digest_eq_cond(
        builder,
        "auth.output0.init_or_lock",
        &wires.outputs[0].note.auth,
        &slot_a_auth,
        output0_init_or_lock,
    );
    assert_digest_eq_cond(
        builder,
        "auth.output0.approval",
        &wires.outputs[0].note.auth,
        &slot_b_auth,
        modes.approval,
    );

    let note_commitments: [[Wire; DIGEST_WORDS]; MAX_INPUTS + MAX_OUTPUTS] =
        array::from_fn(|index| {
            let note = if index < MAX_INPUTS {
                &wires.inputs[index].note
            } else {
                &wires.outputs[index - MAX_INPUTS].note
            };
            note_commitment(builder, note)
        });
    for index in 0..MAX_INPUTS {
        assert_digest_nonzero_cond(
            builder,
            &format!("input[{index}].commitment_nonzero"),
            &note_commitments[index],
            in_active[index],
        );
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].authorization"),
            &wires.inputs[index].note.auth,
            &resolved_auth[index],
            in_active[index],
        );
    }
    for index in 0..MAX_OUTPUTS {
        let commitment = &note_commitments[MAX_INPUTS + index];
        assert_digest_nonzero_cond(
            builder,
            &format!("output[{index}].commitment_nonzero"),
            commitment,
            out_active[index],
        );
        assert_digest_eq_cond(
            builder,
            &format!("output[{index}].commitment"),
            commitment,
            &statement.commitments[index],
            out_active[index],
        );
    }

    for index in 0..MAX_INPUTS {
        let nullifier_frame = semantic_frame(
            builder,
            ROLE_NULLIFIER,
            &[
                (&resolved_nf[index], DIGEST_BYTES),
                (&[wires.inputs[index].position_be], 8),
                (&wires.inputs[index].note.rho, 48),
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
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].nullifier"),
            &nullifier,
            &statement.nullifiers[index],
            in_active[index],
        );
        assert_digest_nonzero_cond(
            builder,
            &format!("input[{index}].nullifier_nonzero"),
            &nullifier,
            in_active[index],
        );
    }

    // Preserve exact scalar acceptance even for hypothetical SHAKE collisions:
    // each active path independently hashes all 32 levels to the anchor.
    for index in 0..MAX_INPUTS {
        let position = swap_bytes(builder, wires.inputs[index].position_be);
        let mut current = note_commitments[index];
        for (level, sibling) in wires.inputs[index].siblings.iter().enumerate() {
            let direction_msb = builder.shl(position, 63 - level as u32);
            let left: [Wire; DIGEST_WORDS] =
                array::from_fn(|word| builder.select(direction_msb, sibling[word], current[word]));
            let right: [Wire; DIGEST_WORDS] = array::from_fn(|word| {
                let pair_xor = builder.bxor(current[word], sibling[word]);
                builder.bxor(pair_xor, left[word])
            });
            let frame = semantic_frame(
                builder,
                ROLE_MERKLE,
                &[(&left, DIGEST_BYTES), (&right, DIGEST_BYTES)],
            );
            current = shake256_words(builder, &frame.words, frame.len_bytes, DIGEST_WORDS)
                .try_into()
                .unwrap();
        }
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].anchor"),
            &current,
            &statement.anchor,
            in_active[index],
        );
    }

    assert_digest_eq_cond(
        builder,
        "auth.final.intent",
        &wires.auth.current.intent,
        &wires.derived_intent,
        modes.final_spend,
    );

    constrain_approval_membership(
        builder,
        wires,
        modes.approval,
        &spend_auth[1],
        &policy.slot_active,
    );
}

fn constrain_approval_membership(
    builder: &CircuitBuilder,
    wires: &FullM4Wires,
    approval_mode: Wire,
    signer_auth: &[Wire; DIGEST_WORDS],
    slot_active: &[Wire; MAX_SIGNERS],
) {
    for slot in 0..MAX_SIGNERS {
        let current = swap_bytes(builder, wires.auth.current.approved_be[slot]);
        let next = swap_bytes(builder, wires.auth.next.approved_be[slot]);
        let changed = low_bool_msb(builder, builder.bxor(current, next));
        let tag_matches = digest_eq_msb(builder, signer_auth, &wires.auth.signer_tags[slot]);
        assert_implies(
            builder,
            &format!("auth.approval.changed_tag[{slot}]"),
            and_msb(builder, approval_mode, changed),
            tag_matches,
        );
        assert_implies(
            builder,
            &format!("auth.approval.member_changed[{slot}]"),
            and_msb(
                builder,
                approval_mode,
                and_msb(builder, slot_active[slot], tag_matches),
            ),
            changed,
        );
    }
}

fn note_commitment(builder: &CircuitBuilder, note: &NoteWords) -> [Wire; DIGEST_WORDS] {
    let kind = swap_bytes(builder, note.kind_be);
    let frame = semantic_frame(
        builder,
        ROLE_NOTE,
        &[
            (&[kind], 1),
            (&[note.value_be], 8),
            (&[note.asset_be], 8),
            (&note.recipient, 32),
            (&note.rho, 48),
            (&note.randomness, 48),
            (&note.auth, DIGEST_BYTES),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 232);
    shake256_words(builder, &frame.words, frame.len_bytes, DIGEST_WORDS)
        .try_into()
        .unwrap()
}

fn spend_key_frame(builder: &CircuitBuilder, spend_key: &[Wire; 6]) -> PackedFrame {
    let order = constant_words(builder, &KEY_OUTPUT_ORDER_TAG);
    let frame = semantic_frame(builder, ROLE_SPEND_KEYS, &[(&order, 8), (spend_key, 48)]);
    debug_assert_eq!(frame.len_bytes, 77);
    frame
}

fn policy_frame(
    builder: &CircuitBuilder,
    opening: &AccumulatorWords,
    tags: &[[Wire; DIGEST_WORDS]; MAX_SIGNERS],
) -> PackedFrame {
    let threshold = [opening.threshold_be];
    let signer_count = [opening.signer_count_be];
    let mut fields: Vec<(&[Wire], usize)> = vec![(&threshold, 8), (&signer_count, 8)];
    fields.extend(tags.iter().map(|tag| (&tag[..], DIGEST_BYTES)));
    let frame = semantic_frame(builder, ROLE_POLICY, &fields);
    debug_assert_eq!(frame.len_bytes, 385);
    frame
}

fn accumulator_frame(builder: &CircuitBuilder, opening: &AccumulatorWords) -> PackedFrame {
    let approved_numeric = opening.approved_be.map(|wire| swap_bytes(builder, wire));
    let approved = pack_low_bytes(builder, &approved_numeric);
    let order = constant_words(builder, &KEY_OUTPUT_ORDER_TAG);
    let frame = semantic_frame(
        builder,
        ROLE_ACCUMULATOR,
        &[
            (&order, 8),
            (&opening.policy_root, DIGEST_BYTES),
            (&opening.intent, DIGEST_BYTES),
            (&[opening.threshold_be], 8),
            (&[opening.signer_count_be], 8),
            (&[opening.approval_count_be], 8),
            (&approved, MAX_SIGNERS),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 181);
    frame
}

fn value_lock_frame(
    builder: &CircuitBuilder,
    policy_root: &[Wire; DIGEST_WORDS],
    intent: &[Wire; DIGEST_WORDS],
) -> PackedFrame {
    let order = constant_words(builder, &KEY_OUTPUT_ORDER_TAG);
    let frame = semantic_frame(
        builder,
        ROLE_VALUE_LOCK,
        &[
            (&order, 8),
            (policy_root, DIGEST_BYTES),
            (intent, DIGEST_BYTES),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 143);
    frame
}

#[derive(Clone, Debug)]
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
            let merged = self
                .builder
                .bxor(current, self.builder.shl(low, (used * 8) as u32));
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

fn dummy_frame(builder: &CircuitBuilder, len_bytes: usize) -> PackedFrame {
    let mut frame = FrameBuilder::new(builder);
    frame.push_const(&vec![0u8; len_bytes]);
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

/// Select already padded absorption blocks from a default and mutually
/// exclusive overrides before entering the shared Keccak pipeline. Every
/// frame must require the same number of permutations. The accepted relation
/// must make at most one override condition true; a false set selects the
/// default.
fn mux_one_hot_shake256_words(
    builder: &CircuitBuilder,
    default: &PackedFrame,
    overrides: &[(Wire, &PackedFrame)],
    permutations: usize,
    output_words: usize,
) -> Vec<Wire> {
    let default = padded_absorption(builder, default, permutations);
    let padded: Vec<Vec<Wire>> = overrides
        .iter()
        .map(|(_, frame)| padded_absorption(builder, frame, permutations))
        .collect();
    let zero = builder.add_constant_64(0);
    let mut state = [zero; 25];
    for block in 0..permutations {
        for word in 0..SHAKE256_RATE_WORDS {
            let absolute = block * SHAKE256_RATE_WORDS + word;
            let selected = overrides.iter().enumerate().fold(
                default[absolute],
                |acc, (index, (condition, _))| {
                    builder.select(*condition, padded[index][absolute], acc)
                },
            );
            state[word] = builder.bxor(state[word], selected);
        }
        keccak_f1600(builder, &mut state);
    }
    state[..output_words].to_vec()
}

fn padded_absorption(
    builder: &CircuitBuilder,
    frame: &PackedFrame,
    permutations: usize,
) -> Vec<Wire> {
    assert_eq!(frame.len_bytes / SHAKE256_RATE_BYTES + 1, permutations);
    let zero = builder.add_constant_64(0);
    let mut words = vec![zero; permutations * SHAKE256_RATE_WORDS];
    for (index, &word) in frame.words.iter().enumerate() {
        words[index] = word;
    }
    let suffix_word = frame.len_bytes / 8;
    let suffix_shift = (frame.len_bytes % 8) * 8;
    words[suffix_word] = builder.bxor(
        words[suffix_word],
        builder.add_constant_64(SHAKE_DOMAIN_SUFFIX << suffix_shift),
    );
    let final_word = permutations * SHAKE256_RATE_WORDS - 1;
    words[final_word] = builder.bxor(words[final_word], builder.add_constant_64(0x80u64 << 56));
    words
}

const fn low_byte_mask(bytes: usize) -> u64 {
    if bytes == 8 {
        u64::MAX
    } else {
        (1u64 << (bytes * 8)) - 1
    }
}

fn pack_bytes(builder: &CircuitBuilder, bytes: &[Wire]) -> Vec<Wire> {
    bytes
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(builder.add_constant_64(0), |word, (index, byte)| {
                    builder.bxor(word, builder.shl(*byte, (index * 8) as u32))
                })
        })
        .collect()
}

fn pack_low_bytes<const N: usize>(builder: &CircuitBuilder, bytes: &[Wire; N]) -> Vec<Wire> {
    pack_bytes(builder, bytes)
}

fn constant_words(builder: &CircuitBuilder, bytes: &[u8]) -> Vec<Wire> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut raw = [0u8; 8];
            raw[..chunk.len()].copy_from_slice(chunk);
            builder.add_constant_64(u64::from_le_bytes(raw))
        })
        .collect()
}

fn pack_digest(builder: &CircuitBuilder, bytes: &[Wire]) -> [Wire; DIGEST_WORDS] {
    assert_eq!(bytes.len(), DIGEST_BYTES);
    pack_bytes(builder, bytes).try_into().unwrap()
}

fn decode_be(builder: &CircuitBuilder, bytes: &[Wire]) -> Wire {
    assert!((1..=8).contains(&bytes.len()));
    bytes
        .iter()
        .enumerate()
        .fold(builder.add_constant_64(0), |value, (index, byte)| {
            builder.bxor(
                value,
                builder.shl(*byte, ((bytes.len() - index - 1) * 8) as u32),
            )
        })
}

fn select_digest(
    builder: &CircuitBuilder,
    condition: Wire,
    when_true: &[Wire; DIGEST_WORDS],
    when_false: &[Wire; DIGEST_WORDS],
) -> [Wire; DIGEST_WORDS] {
    array::from_fn(|word| builder.select(condition, when_true[word], when_false[word]))
}

fn select_accumulator(
    builder: &CircuitBuilder,
    condition: Wire,
    when_true: &AccumulatorWords,
    when_false: &AccumulatorWords,
) -> AccumulatorWords {
    AccumulatorWords {
        policy_root: select_digest(
            builder,
            condition,
            &when_true.policy_root,
            &when_false.policy_root,
        ),
        intent: select_digest(builder, condition, &when_true.intent, &when_false.intent),
        threshold_be: builder.select(condition, when_true.threshold_be, when_false.threshold_be),
        signer_count_be: builder.select(
            condition,
            when_true.signer_count_be,
            when_false.signer_count_be,
        ),
        approval_count_be: builder.select(
            condition,
            when_true.approval_count_be,
            when_false.approval_count_be,
        ),
        approved_be: array::from_fn(|slot| {
            builder.select(
                condition,
                when_true.approved_be[slot],
                when_false.approved_be[slot],
            )
        }),
    }
}

fn assert_authoritative_activation(activation: &ActivationBinding) {
    assert!(activation_is_authoritative(activation));
}

fn activation_is_authoritative(activation: &ActivationBinding) -> bool {
    activation.circuit_version == TARGET_CIRCUIT_VERSION
        && activation.crypto_suite == TARGET_CRYPTO_SUITE
        && activation.family_id == SHIELDED_POOL_FAMILY_ID
        && activation.action_id == TARGET_ACTION_ID
        && activation.backend_id == TARGET_BACKEND_ID
        && activation.proof_profile == TARGET_PROOF_PROFILE
        && activation.chain_id != [0; 32]
        && activation.genesis_block_id != [0; 48]
        && activation.rules_hash != [0; 48]
}

fn activation_bytes(activation: &ActivationBinding) -> [u8; PUBLIC_BYTES - OFFSET_ACTIVATION] {
    let mut bytes = Vec::with_capacity(PUBLIC_BYTES - OFFSET_ACTIVATION);
    bytes.extend_from_slice(&activation.circuit_version.to_be_bytes());
    bytes.extend_from_slice(&activation.crypto_suite.to_be_bytes());
    bytes.extend_from_slice(&activation.family_id.to_be_bytes());
    bytes.extend_from_slice(&activation.action_id.to_be_bytes());
    bytes.extend_from_slice(&activation.backend_id);
    bytes.extend_from_slice(&activation.proof_profile);
    bytes.extend_from_slice(&activation.chain_id);
    bytes.extend_from_slice(&activation.genesis_block_id);
    bytes.extend_from_slice(&activation.rules_hash);
    bytes.try_into().unwrap()
}

fn public_le_word(
    builder: &CircuitBuilder,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    assert!(byte_offset + 8 <= PUBLIC_BYTES);
    let word = byte_offset / 8;
    let shift = (byte_offset % 8) * 8;
    if shift == 0 {
        return public[word];
    }
    builder.bxor(
        builder.shr(public[word], shift as u32),
        builder.shl(public[word + 1], (64 - shift) as u32),
    )
}

fn public_words_at<const N: usize>(
    builder: &CircuitBuilder,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
) -> [Wire; N] {
    array::from_fn(|word| public_le_word(builder, public, byte_offset + word * 8))
}

fn public_byte(
    builder: &CircuitBuilder,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    builder.extract_byte(public[byte_offset / 8], (byte_offset % 8) as u32)
}

fn public_be_u64(
    builder: &CircuitBuilder,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    swap_bytes(builder, public_le_word(builder, public, byte_offset))
}

fn public_be_u32(
    builder: &CircuitBuilder,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    assert_eq!(byte_offset % 8, 0);
    builder.shr(swap_bytes(builder, public[byte_offset / 8]), 32)
}

fn assert_public_bytes_const(
    builder: &CircuitBuilder,
    name: &str,
    public: &[Wire; STATEMENT_WORDS],
    byte_offset: usize,
    expected: &[u8],
) {
    assert!(byte_offset + expected.len() <= PUBLIC_BYTES);
    let mut consumed = 0;
    while consumed < expected.len() {
        let absolute = byte_offset + consumed;
        let word = absolute / 8;
        let within = absolute % 8;
        let take = (8 - within).min(expected.len() - consumed);
        let mut expected_word = [0u8; 8];
        expected_word[within..within + take].copy_from_slice(&expected[consumed..consumed + take]);
        let mask = low_byte_mask(take) << (within * 8);
        let actual = if mask == u64::MAX {
            public[word]
        } else {
            builder.band(public[word], builder.add_constant_64(mask))
        };
        builder.assert_eq(
            format!("{name}.word[{word}]"),
            actual,
            builder.add_constant_64(u64::from_le_bytes(expected_word)),
        );
        consumed += take;
    }
}

fn assert_low_bool(builder: &CircuitBuilder, name: &str, value: Wire) {
    builder.assert_zero(
        name,
        builder.band(value, builder.add_constant_64(u64::MAX ^ 1)),
    );
}

fn low_bool_msb(builder: &CircuitBuilder, value: Wire) -> Wire {
    builder.shl(value, 63)
}

fn and_msb(builder: &CircuitBuilder, left: Wire, right: Wire) -> Wire {
    builder.band(left, right)
}

fn or_msb(builder: &CircuitBuilder, conditions: &[Wire]) -> Wire {
    conditions
        .iter()
        .copied()
        .fold(builder.add_constant_64(0), |acc, condition| {
            builder.bor(acc, condition)
        })
}

fn assert_implies(builder: &CircuitBuilder, name: &str, antecedent: Wire, consequent: Wire) {
    builder.assert_true(name, builder.bor(builder.bnot(antecedent), consequent));
}

fn assert_61_bit(builder: &CircuitBuilder, name: &str, value: Wire) {
    builder.assert_zero(format!("{name}.high3"), builder.shr(value, 61));
}

fn assert_flag_cond(
    builder: &CircuitBuilder,
    name: &str,
    flag: Wire,
    expected: bool,
    condition: Wire,
) {
    builder.assert_eq_cond(
        name,
        flag,
        builder.add_constant_64(u64::from(expected)),
        condition,
    );
}

fn assert_numeric_eq_cond(
    builder: &CircuitBuilder,
    name: &str,
    raw_be: Wire,
    expected: u64,
    condition: Wire,
) {
    builder.assert_eq_cond(
        name,
        swap_bytes(builder, raw_be),
        builder.add_constant_64(expected),
        condition,
    );
}

fn assert_words_zero_cond(builder: &CircuitBuilder, name: &str, words: &[Wire], condition: Wire) {
    let zero = builder.add_constant_64(0);
    for (index, &word) in words.iter().enumerate() {
        builder.assert_eq_cond(format!("{name}[{index}]"), word, zero, condition);
    }
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

fn assert_digest_eq_cond(
    builder: &CircuitBuilder,
    name: &str,
    actual: &[Wire; DIGEST_WORDS],
    expected: &[Wire; DIGEST_WORDS],
    condition: Wire,
) {
    for word in 0..DIGEST_WORDS {
        builder.assert_eq_cond(
            format!("{name}[{word}]"),
            actual[word],
            expected[word],
            condition,
        );
    }
}

fn assert_digest_zero_cond(
    builder: &CircuitBuilder,
    name: &str,
    digest: &[Wire; DIGEST_WORDS],
    condition: Wire,
) {
    let zero = builder.add_constant_64(0);
    for (word, &value) in digest.iter().enumerate() {
        builder.assert_eq_cond(format!("{name}[{word}]"), value, zero, condition);
    }
}

fn digest_or(builder: &CircuitBuilder, digest: &[Wire; DIGEST_WORDS]) -> Wire {
    digest[1..]
        .iter()
        .copied()
        .fold(digest[0], |acc, word| builder.bor(acc, word))
}

fn assert_digest_nonzero_cond(
    builder: &CircuitBuilder,
    name: &str,
    digest: &[Wire; DIGEST_WORDS],
    condition: Wire,
) {
    let selected = builder.select(
        condition,
        digest_or(builder, digest),
        builder.add_constant_64(1),
    );
    builder.assert_non_zero(name, selected);
}

fn assert_digest_unequal_cond(
    builder: &CircuitBuilder,
    name: &str,
    left: &[Wire; DIGEST_WORDS],
    right: &[Wire; DIGEST_WORDS],
    condition: Wire,
) {
    let differences: [Wire; DIGEST_WORDS] =
        array::from_fn(|word| builder.bxor(left[word], right[word]));
    assert_digest_nonzero_cond(builder, name, &differences, condition);
}

fn digest_eq_msb(
    builder: &CircuitBuilder,
    left: &[Wire; DIGEST_WORDS],
    right: &[Wire; DIGEST_WORDS],
) -> Wire {
    (0..DIGEST_WORDS)
        .map(|word| builder.icmp_eq(left[word], right[word]))
        .fold(builder.add_constant_64(u64::MAX), |acc, equal| {
            builder.band(acc, equal)
        })
}

fn serialize_private_witness(witness: &FullWitness) -> [u8; PRIVATE_BYTES] {
    let mut bytes = Vec::with_capacity(PRIVATE_BYTES);
    for input in &witness.inputs {
        bytes.extend_from_slice(&input.spend_key);
        push_note(&mut bytes, &input.note);
        bytes.extend_from_slice(&input.position.to_be_bytes());
        for sibling in &input.siblings {
            bytes.extend_from_slice(sibling);
        }
        push_bool_words(&mut bytes, &input.balance_slot_selectors);
    }
    for output in &witness.outputs {
        push_note(&mut bytes, &output.note);
        push_bool_words(&mut bytes, &output.balance_slot_selectors);
    }
    let mode: u64 = match witness.auth.mode {
        PrivateAuthMode::SingleKey => 0,
        PrivateAuthMode::AccumulatorInit => 1,
        PrivateAuthMode::ApprovalStep => 2,
        PrivateAuthMode::ValueLockCreation => 3,
        PrivateAuthMode::FinalThresholdSpend => 4,
    };
    bytes.extend_from_slice(&mode.to_be_bytes());
    push_accumulator(&mut bytes, &witness.auth.current);
    push_accumulator(&mut bytes, &witness.auth.next);
    for tag in &witness.auth.signer_tags {
        bytes.extend_from_slice(tag);
    }
    bytes
        .try_into()
        .expect("the full private witness is exactly 671 words")
}

fn push_note(output: &mut Vec<u8>, note: &NoteOpening) {
    let kind = match note.kind {
        NoteKind::Ordinary => 0u64,
        NoteKind::Accumulator => 1,
        NoteKind::ValueLock => 2,
    };
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&note.value.to_be_bytes());
    output.extend_from_slice(&note.asset_id.to_be_bytes());
    output.extend_from_slice(&note.pk_recipient);
    output.extend_from_slice(&note.rho);
    output.extend_from_slice(&note.randomness);
    output.extend_from_slice(&note.pk_auth);
}

fn push_bool_words<const N: usize>(output: &mut Vec<u8>, values: &[bool; N]) {
    for value in values {
        output.extend_from_slice(&u64::from(*value).to_be_bytes());
    }
}

fn push_accumulator(
    output: &mut Vec<u8>,
    opening: &hegemon_standalone_full_shake256_relation_prototype::AccumulatorOpening,
) {
    output.extend_from_slice(&opening.policy_root);
    output.extend_from_slice(&opening.intent_digest);
    output.extend_from_slice(&opening.threshold.to_be_bytes());
    output.extend_from_slice(&opening.signer_count.to_be_bytes());
    output.extend_from_slice(&opening.approval_count.to_be_bytes());
    push_bool_words(output, &opening.approved_slots);
}

fn pack_private_words(bytes: &[u8; PRIVATE_BYTES]) -> [u64; PRIVATE_WORDS] {
    array::from_fn(|word| u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap()))
}

fn generate_witness(
    built: &BuiltFullM4,
    witness: &FullWitness,
    public: &[u64; PUBLIC_WORDS],
) -> Result<WitnessM4, PopulateM4Error> {
    let private = pack_private_words(&serialize_private_witness(witness));
    built.circuit.generate_witness(|filler| {
        for (&wire, value) in built.wires.private.iter().zip(private) {
            filler[wire] = Word(value);
        }
        for (&wire, &value) in built.wires.public.iter().zip(public) {
            filler[wire] = Word(value);
        }
    })
}

/// Concrete executable adapter for the pinned upstream M4 implementation.
///
/// This type deliberately carries `ResearchWeakTransparent` in its name: the
/// pinned backend targets only 96 bits, commits unmasked witness oracles, and
/// has no release authorization. It exists to make the prospective full
/// relation executable once the disk/build gate opens, not to satisfy the
/// strict PQ128 or complete-ZK acceptance gates.
#[cfg(feature = "prototype-weak")]
pub struct ResearchWeakTransparentM4Backend {
    built: BuiltFullM4,
    verifier: VerifierM4<StdHashSuite>,
    expected_activation: ActivationBinding,
}

#[cfg(feature = "prototype-weak")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FullM4BackendError {
    InvalidActivation,
    BindingStatement(String),
    BindingActivationMismatch,
    EmptyProof,
    ProofTooLarge { observed: usize, maximum: usize },
    Setup(String),
    WitnessPopulation(String),
    WitnessConstraint(String),
    Prove(String),
    Verify(String),
    TrailingProof(String),
}

#[cfg(feature = "prototype-weak")]
impl fmt::Display for FullM4BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "prototype-weak")]
impl std::error::Error for FullM4BackendError {}

#[cfg(feature = "prototype-weak")]
impl ResearchWeakTransparentM4Backend {
    /// Build the private one-main circuit and its matching verifier at the
    /// single pinned weak-profile rate. No raw circuit or wire handle escapes.
    pub fn setup(expected_activation: &ActivationBinding) -> Result<Self, FullM4BackendError> {
        if !activation_is_authoritative(expected_activation) {
            return Err(FullM4BackendError::InvalidActivation);
        }
        let built = build_full_m4(expected_activation);
        let constraint_system = built.circuit.to_constraint_system();
        let verifier = VerifierM4::<StdHashSuite>::setup(&constraint_system, WEAK_LOG_INVERSE_RATE)
            .map_err(|error| FullM4BackendError::Setup(format!("{error:?}")))?;
        Ok(Self {
            built,
            verifier,
            expected_activation: expected_activation.clone(),
        })
    }

    fn check_statement(
        &self,
        statement_bytes: &[u8; CANONICAL_STATEMENT_BYTES],
    ) -> Result<(), FullM4BackendError> {
        let statement = decode_canonical_statement(statement_bytes)
            .map_err(|error| FullM4BackendError::BindingStatement(format!("{error:?}")))?;
        if statement.activation != self.expected_activation {
            return Err(FullM4BackendError::BindingActivationMismatch);
        }
        Ok(())
    }

    /// Research-only transparent prover counterpart. The byte-identical v3
    /// binding preamble is observed before the M4 protocol. The resulting
    /// proof remains non-ZK, upstream-96-bit evidence only. Constructing this
    /// prover binding exact-decodes and hashes the statement but confers no
    /// action, policy, network, or release authority.
    pub fn prove_research_only(
        &self,
        statement: &[u8; CANONICAL_STATEMENT_BYTES],
        witness: &FullWitness,
    ) -> Result<Vec<u8>, FullM4BackendError> {
        let binding = FullProofProverBinding::from_canonical_statement(statement)
            .map_err(|error| FullM4BackendError::BindingStatement(format!("{error:?}")))?;
        self.check_statement(binding.statement())?;
        let public = public_words_from_prover_binding(binding);
        let witness = generate_witness(&self.built, witness, &public)
            .map_err(|error| FullM4BackendError::WitnessPopulation(format!("{error:?}")))?;
        let constraint_system = self.built.circuit.to_constraint_system();
        witness
            .verify(&constraint_system)
            .map_err(|error| FullM4BackendError::WitnessConstraint(format!("{error:?}")))?;
        let prover = ProverM4::<OptimalPackedB128, StdHashSuite>::setup(&self.verifier);
        let mut transcript = ProverTranscript::new(StdChallenger::default());
        let mut preamble = Vec::new();
        binding.write_transcript_preamble(&mut preamble);
        transcript.observe().write_bytes(&preamble);
        prover
            .prove(&witness, &mut transcript)
            .map_err(|error| FullM4BackendError::Prove(format!("{error:?}")))?;
        let proof = transcript.finalize();
        if proof.len() > MAX_PROOF_BYTES {
            return Err(FullM4BackendError::ProofTooLarge {
                observed: proof.len(),
                maximum: MAX_PROOF_BYTES,
            });
        }
        Ok(proof)
    }

    fn verify_words_exact(
        &self,
        binding: FullProofProverBinding<'_>,
        public: &[Word; PUBLIC_WORDS],
        proof: &[u8],
    ) -> Result<(), FullM4BackendError> {
        let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
        let mut preamble = Vec::new();
        binding.write_transcript_preamble(&mut preamble);
        transcript.observe().write_bytes(&preamble);
        self.verifier
            .verify(public, &mut transcript)
            .map_err(|error| FullM4BackendError::Verify(format!("{error:?}")))?;
        transcript
            .finalize()
            .map_err(|error| FullM4BackendError::TrailingProof(format!("{error:?}")))
    }

    /// Test-only capability target used by the private composed wrapper below.
    /// No normal or feature build implements `FullProofVerifier` for this weak
    /// backend.
    #[cfg(test)]
    fn verify_bound_negative_control(
        &self,
        binding: FullProofBinding<'_>,
        proof: &[u8],
    ) -> Result<(), FullM4BackendError> {
        if proof.is_empty() {
            return Err(FullM4BackendError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(FullM4BackendError::ProofTooLarge {
                observed: proof.len(),
                maximum: MAX_PROOF_BYTES,
            });
        }
        self.check_statement(binding.statement())?;
        let public = public_words_from_binding(binding).map(Word);
        let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
        let mut preamble = Vec::new();
        binding.write_transcript_preamble(&mut preamble);
        transcript.observe().write_bytes(&preamble);
        self.verifier
            .verify(&public, &mut transcript)
            .map_err(|error| FullM4BackendError::Verify(format!("{error:?}")))?;
        transcript
            .finalize()
            .map_err(|error| FullM4BackendError::TrailingProof(format!("{error:?}")))
    }

    /// Verify only as an explicitly unsupported weak-profile negative control.
    /// This deliberately does not implement the production-shaped
    /// `FullProofVerifier` capability.
    pub fn verify_research_only(
        &self,
        statement: &[u8; CANONICAL_STATEMENT_BYTES],
        proof: &[u8],
    ) -> Result<(), FullM4BackendError> {
        if proof.is_empty() {
            return Err(FullM4BackendError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(FullM4BackendError::ProofTooLarge {
                observed: proof.len(),
                maximum: MAX_PROOF_BYTES,
            });
        }
        let binding = FullProofProverBinding::from_canonical_statement(statement)
            .map_err(|error| FullM4BackendError::BindingStatement(format!("{error:?}")))?;
        self.check_statement(binding.statement())?;
        let public = public_words_from_prover_binding(binding).map(Word);
        self.verify_words_exact(binding, &public, proof)
    }
}

/// The only exported M4 public-vector constructor consumes the sealed binding
/// created by exact action composition. Callers cannot substitute derived
/// intent words independently of the 853-byte statement.
pub fn public_words_from_binding(binding: FullProofBinding<'_>) -> [u64; PUBLIC_WORDS] {
    let transport = binding.m4_public_transport();
    array::from_fn(|word| u64::from_le_bytes(transport[word * 8..word * 8 + 8].try_into().unwrap()))
}

fn public_words_from_prover_binding(binding: FullProofProverBinding<'_>) -> [u64; PUBLIC_WORDS] {
    let transport = binding.m4_public_transport();
    array::from_fn(|word| u64::from_le_bytes(transport[word * 8..word * 8 + 8].try_into().unwrap()))
}

/// Isolated bridge from the exact one-main M4 realization to the generic
/// Binius ZK wrapper. This module deliberately exports data, not an accepting
/// verifier: production admission remains in the composed action boundary.
#[cfg(feature = "strict-baseline-material")]
pub mod strict_baseline_material {
    use super::*;
    use binius_core::constraint_system::{ConstraintSystem, ValueVec};
    use hegemon_standalone_full_shake256_relation_prototype::{
        encode_canonical_statement, mask_fixture,
    };

    /// Exact full-relation material consumed by `ZKProver` and `ZKVerifier`.
    pub struct StrictBaselineMaterial {
        pub constraint_system: ConstraintSystem,
        pub witness: ValueVec,
        pub public: [Word; PUBLIC_WORDS],
        pub statement_bytes: [u8; CANONICAL_STATEMENT_BYTES],
        pub transcript_preamble: Vec<u8>,
    }

    /// Canonical all-active maximum-relation fixture.
    pub fn canonical() -> StrictBaselineMaterial {
        let (statement, witness) = mask_fixture(0b1111);
        material(statement, witness)
    }

    /// Independently satisfiable public-statement variant used to prove that
    /// a fresh proof cannot be replayed against the canonical statement.
    pub fn ciphertext_hash_variant() -> StrictBaselineMaterial {
        let (mut statement, witness) = mask_fixture(0b1111);
        statement.ciphertext_hashes[0][0] ^= 1;
        material(statement, witness)
    }

    fn material(
        statement: hegemon_standalone_full_shake256_relation_prototype::FullStatement,
        witness: FullWitness,
    ) -> StrictBaselineMaterial {
        let statement_bytes =
            encode_canonical_statement(&statement).expect("the fixture statement is canonical");
        let binding = FullProofProverBinding::from_canonical_statement(&statement_bytes)
            .expect("the canonical fixture must create a prover binding");
        let public_words = public_words_from_prover_binding(binding);
        let built = build_full_m4(&statement.activation);
        let witness = generate_witness(&built, &witness, &public_words)
            .expect("the fixture must populate the full M4 witness");
        let public = public_words.map(Word);
        let composite = built.circuit.to_constraint_system();
        composite
            .validate()
            .expect("the full composite constraint system must validate");
        witness
            .verify(&composite)
            .expect("the fixture must satisfy the full M4 relation");
        assert!(
            composite.chips.is_empty() && witness.tables.is_empty(),
            "the strict baseline bridge accepts only one chip-free M4 main"
        );
        let constraint_system = composite.main.cs.clone();
        let witness = witness.main.clone();
        constraint_system
            .verify(&witness)
            .expect("the extracted main witness must satisfy the extracted system");
        let mut transcript_preamble = Vec::new();
        binding.write_transcript_preamble(&mut transcript_preamble);
        StrictBaselineMaterial {
            constraint_system,
            witness,
            public,
            statement_bytes,
            transcript_preamble,
        }
    }
}

#[cfg(test)]
mod source_contract_tests {
    use super::*;
    #[cfg(feature = "prototype-weak")]
    use hegemon_standalone_full_shake256_relation_prototype::action_adapter::RouteAuthority;
    #[cfg(feature = "prototype-weak")]
    use hegemon_standalone_full_shake256_relation_prototype::composed_envelope::{
        action_binding_digest, encode_envelope, reconstruct_statement, verify_composed_action,
        CanonicalCiphertextValidator, FullProofVerifier, ProspectiveFullInlineAction,
        MAX_CANONICAL_CIPHERTEXT_BYTES,
    };
    #[cfg(feature = "prototype-weak")]
    use hegemon_standalone_full_shake256_relation_prototype::expected_balance_tag;
    use hegemon_standalone_full_shake256_relation_prototype::{
        encode_canonical_statement, mask_fixture,
    };

    #[cfg(feature = "prototype-weak")]
    struct WeakComposedTestVerifier<'a>(&'a ResearchWeakTransparentM4Backend);

    #[cfg(feature = "prototype-weak")]
    impl FullProofVerifier for WeakComposedTestVerifier<'_> {
        type Error = FullM4BackendError;

        fn verify_exact(
            &self,
            binding: FullProofBinding<'_>,
            proof: &[u8],
        ) -> Result<(), Self::Error> {
            self.0.verify_bound_negative_control(binding, proof)
        }
    }

    #[cfg(feature = "prototype-weak")]
    struct ExactTestCiphertext;

    #[cfg(feature = "prototype-weak")]
    impl CanonicalCiphertextValidator for ExactTestCiphertext {
        type Error = &'static str;

        fn canonicalize_exact(
            &self,
            _slot: usize,
            encoded: &[u8],
            canonical: &mut Vec<u8>,
        ) -> Result<(), Self::Error> {
            if encoded.len() != MAX_CANONICAL_CIPHERTEXT_BYTES {
                return Err("wrong test ciphertext length");
            }
            canonical.extend_from_slice(encoded);
            Ok(())
        }
    }

    #[test]
    fn exact_layout_and_transport_packing() {
        assert_eq!(PUBLIC_BYTES, 853);
        assert_eq!(STATEMENT_WORDS, 107);
        assert_eq!(PUBLIC_WORDS, 114);
        assert_eq!(PRIVATE_WORDS, 671);
        assert_eq!(
            PRIVATE_WORDS,
            INPUT_WORDS * 2 + OUTPUT_WORDS * 2 + AUTH_WORDS
        );
        let (statement, witness) = mask_fixture(0b1111);
        let statement = encode_canonical_statement(&statement).unwrap();
        assert_eq!(statement.len(), PUBLIC_BYTES);
        assert_eq!(serialize_private_witness(&witness).len(), PRIVATE_BYTES);
        assert_eq!(
            pack_private_words(&serialize_private_witness(&witness)).len(),
            PRIVATE_WORDS
        );
        let binding = FullProofProverBinding::from_canonical_statement(&statement).unwrap();
        let public = public_words_from_prover_binding(binding);
        assert_eq!(public.len(), PUBLIC_WORDS);
        assert_eq!(public[STATEMENT_WORDS - 1] >> 40, 0);
        assert_eq!(
            &binding.m4_public_transport()[STATEMENT_WORDS * 8..],
            binding.derived_intent()
        );
    }

    #[test]
    fn prover_binding_mutations_change_the_transport_and_derived_intent() {
        let (statement, _) = mask_fixture(0b1111);
        let statement = encode_canonical_statement(&statement).unwrap();
        let binding = FullProofProverBinding::from_canonical_statement(&statement).unwrap();
        let original = public_words_from_prover_binding(binding);

        let mut changed = statement;
        changed[OFFSET_FEE + 7] ^= 1;
        let changed_binding = FullProofProverBinding::from_canonical_statement(&changed).unwrap();
        let changed_public = public_words_from_prover_binding(changed_binding);
        assert_ne!(original, changed_public);
        assert_ne!(binding.derived_intent(), changed_binding.derived_intent());

        let mut malformed = statement;
        malformed[0] ^= 1;
        assert!(FullProofProverBinding::from_canonical_statement(&malformed).is_err());
    }

    #[test]
    fn fixed_geometry_is_eighty_three_keccak_permutations() {
        let common = 4 * 2 + 2 + 64 + 2;
        let multiplexed_auth = 3 + 2 + 2;
        assert_eq!(common, 76);
        assert_eq!(common + multiplexed_auth, 83);
    }

    #[cfg(feature = "prototype-weak")]
    #[test]
    fn concrete_backend_is_permanently_weak_transparent_and_unreleased() {
        assert_eq!(WEAK_LOG_INVERSE_RATE, 2);
        assert_eq!(UPSTREAM_SECURITY_BITS, 96);
        assert!(!BACKEND_IS_ZERO_KNOWLEDGE);
        assert!(!BACKEND_IS_STRICT_PQ128);
        assert!(!BACKEND_RELEASE_AUTHORIZED);
    }

    /// Enable only after the disk gate opens. This is an executable negative
    /// control for the pinned weak backend, never production acceptance
    /// evidence.
    #[cfg(feature = "prototype-weak")]
    #[test]
    #[ignore = "requires the >=28 GiB disk gate and a full M4 prove"]
    fn weak_negative_control_composed_roundtrip_and_mutations() {
        let (statement, witness) = mask_fixture(0b1111);
        let ciphertext = vec![0x5a; MAX_CANONICAL_CIPHERTEXT_BYTES];
        let ciphertexts = [ciphertext.as_slice(), ciphertext.as_slice()];
        let mut action = ProspectiveFullInlineAction {
            input_flags: statement.input_flags,
            output_flags: statement.output_flags,
            anchor: statement.anchor,
            nullifiers: statement.nullifiers,
            commitments: statement.commitments,
            ciphertexts,
            ciphertext_sizes: [MAX_CANONICAL_CIPHERTEXT_BYTES as u32; MAX_OUTPUTS],
            balance_slot_asset_ids: statement.balance_slot_asset_ids,
            fee: statement.fee,
            value_balance: statement.value_balance,
            stablecoin: statement.stablecoin.clone(),
            balance_tag: statement.balance_tag,
            activation: statement.activation.clone(),
            statement_binding: [0; 64],
            legacy_candidate_artifact: None,
        };
        let initial_reconstruction =
            reconstruct_statement::<_, FullM4BackendError>(&action, &ExactTestCiphertext).unwrap();
        action.balance_tag = expected_balance_tag(&initial_reconstruction);
        let reconstructed =
            reconstruct_statement::<_, FullM4BackendError>(&action, &ExactTestCiphertext).unwrap();
        let encoded = encode_canonical_statement(&reconstructed).unwrap();
        action.statement_binding = action_binding_digest(&encoded);
        let authority =
            RouteAuthority::from_active_snapshot(&action.activation, 7, 11, &[]).unwrap();
        let backend = ResearchWeakTransparentM4Backend::setup(&statement.activation).unwrap();
        let proof = backend.prove_research_only(&encoded, &witness).unwrap();
        assert!(!proof.is_empty());
        let envelope = encode_envelope(&proof).unwrap();
        let verifier = WeakComposedTestVerifier(&backend);
        let adapted = verify_composed_action(
            &envelope,
            &action,
            &authority,
            &ExactTestCiphertext,
            &verifier,
        )
        .unwrap();
        assert_eq!(adapted.statement(), &reconstructed);

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 1;
        let mut changed_action = action.clone();
        changed_action.ciphertexts[0] = changed_ciphertext.as_slice();
        assert!(verify_composed_action(
            &envelope,
            &changed_action,
            &authority,
            &ExactTestCiphertext,
            &verifier,
        )
        .is_err());

        let mut changed_proof = proof.clone();
        let midpoint = changed_proof.len() / 2;
        changed_proof[midpoint] ^= 1;
        let changed_envelope = encode_envelope(&changed_proof).unwrap();
        assert!(verify_composed_action(
            &changed_envelope,
            &action,
            &authority,
            &ExactTestCiphertext,
            &verifier,
        )
        .is_err());

        let mut trailing = envelope;
        trailing.push(0);
        assert!(verify_composed_action(
            &trailing,
            &action,
            &authority,
            &ExactTestCiphertext,
            &verifier,
        )
        .is_err());
    }
}
