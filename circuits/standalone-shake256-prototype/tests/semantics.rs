use hegemon_standalone_shake256_prototype::{
    derive_spend_key_material, encode_frame, encode_spend_key_derivation_frame, evaluate_pay1x2,
    hash_fields, spend_key_material_matches, HashError, MerkleNode, NoteOpening, NullifierKey,
    Pay1x2HashWorkload, SemanticDigest, SemanticRole, SpendAuthKey, MERKLE_PARENT_FRAME_BYTES,
    SEMANTIC_DIGEST_BYTES, SPEND_KEY_DERIVATION_FRAME_BYTES, SPEND_KEY_OUTPUT_ORDER_TAG,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const DEPTH: usize = 4;

fn repeated32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn repeated48(byte: u8) -> [u8; 48] {
    [byte; 48]
}

fn repeated56(byte: u8) -> [u8; 56] {
    [byte; 56]
}

fn digest_pattern(seed: u8) -> SemanticDigest {
    SemanticDigest::from_bytes(core::array::from_fn(|index| seed.wrapping_add(index as u8)))
}

fn fixture() -> Pay1x2HashWorkload<DEPTH> {
    let spend_key = repeated48(0x55);
    let spend_keys = derive_spend_key_material(&spend_key);
    Pay1x2HashWorkload {
        input_note: NoteOpening {
            value: 50,
            asset_id: 7,
            pk_recipient: repeated32(0x11),
            rho: repeated48(0x22),
            randomness: repeated48(0x33),
            pk_auth: spend_keys.spend_auth_key.into_bytes(),
        },
        spend_key,
        position: 5,
        merkle_siblings: core::array::from_fn(|index| {
            MerkleNode::from_digest(digest_pattern(0x60 + index as u8))
        }),
        output_notes: [
            NoteOpening {
                value: 19,
                asset_id: 7,
                pk_recipient: repeated32(0x71),
                rho: repeated48(0x72),
                randomness: repeated48(0x73),
                pk_auth: repeated56(0x74),
            },
            NoteOpening {
                value: 29,
                asset_id: 7,
                pk_recipient: repeated32(0x81),
                rho: repeated48(0x82),
                randomness: repeated48(0x83),
                pk_auth: repeated56(0x84),
            },
        ],
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

fn raw_shake256_448(frame: &[u8]) -> SemanticDigest {
    let mut hasher = Shake256::default();
    hasher.update(frame);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; SEMANTIC_DIGEST_BYTES];
    reader.read(&mut output);
    SemanticDigest::from_bytes(output)
}

fn assert_input_commitment_changed(
    baseline: &hegemon_standalone_shake256_prototype::Pay1x2HashTrace,
    mutated: &Pay1x2HashWorkload<DEPTH>,
) {
    let changed = evaluate_pay1x2(mutated).unwrap();
    assert_ne!(
        baseline.outputs.input_commitment,
        changed.outputs.input_commitment
    );
    assert_ne!(baseline.outputs.anchor, changed.outputs.anchor);
}

fn assert_output0_commitment_changed(
    baseline: &hegemon_standalone_shake256_prototype::Pay1x2HashTrace,
    mutated: &Pay1x2HashWorkload<DEPTH>,
) {
    let changed = evaluate_pay1x2(mutated).unwrap();
    assert_ne!(
        baseline.outputs.output_commitments[0],
        changed.outputs.output_commitments[0]
    );
}

#[test]
fn digest_decoder_requires_exact_width() {
    assert!(SemanticDigest::from_slice(&[0u8; SEMANTIC_DIGEST_BYTES]).is_ok());
    assert_eq!(
        SemanticDigest::from_slice(&[0u8; SEMANTIC_DIGEST_BYTES - 1]),
        Err(HashError::DigestLength {
            expected: SEMANTIC_DIGEST_BYTES,
            actual: SEMANTIC_DIGEST_BYTES - 1,
        })
    );
    assert_eq!(
        SemanticDigest::from_slice(&[0u8; SEMANTIC_DIGEST_BYTES + 1]),
        Err(HashError::DigestLength {
            expected: SEMANTIC_DIGEST_BYTES,
            actual: SEMANTIC_DIGEST_BYTES + 1,
        })
    );
}

#[test]
fn registry_rejects_wrong_arity_and_length_before_hashing() {
    let left = [0u8; 56];
    let short = [0u8; 55];

    assert_eq!(
        encode_frame(SemanticRole::MerkleNode, &[&left]),
        Err(HashError::WrongFieldCount {
            role: SemanticRole::MerkleNode,
            expected: 2,
            actual: 1,
        })
    );
    assert_eq!(
        encode_frame(SemanticRole::MerkleNode, &[&left, &short]),
        Err(HashError::WrongFieldLength {
            role: SemanticRole::MerkleNode,
            field: 1,
            expected: 56,
            actual: 55,
        })
    );
}

#[test]
fn merkle_parent_is_exactly_one_rate_block() {
    let left = [0x11u8; 56];
    let right = [0x22u8; 56];
    let frame = encode_frame(SemanticRole::MerkleNode, &[&left, &right]).unwrap();

    assert_eq!(frame.len(), MERKLE_PARENT_FRAME_BYTES);
    assert_eq!(frame.len(), 133);
    assert_eq!(&frame[..8], b"HEG-S4V2");
    assert_eq!(&frame[8..16], b"merk.nd1");
    assert_eq!(frame[16], 2);
    assert_eq!(&frame[17..19], &[0, 56]);
    assert_eq!(&frame[75..77], &[0, 56]);
    assert_eq!(SemanticRole::MerkleNode.keccak_f_permutations(), 1);
    assert_eq!(
        to_hex(
            hash_fields(SemanticRole::MerkleNode, &[&left, &right])
                .unwrap()
                .as_bytes()
        ),
        "025d0bf7d9a82b06b8ac7ba85247a34d90b26d41184dc2f0a1bff7d851fe7f8b112a5ba5519c7177a465a3d1c1b07faf9abaf808bae80dce"
    );
}

#[test]
fn spend_key_kdf_binds_output_roles_and_order() {
    let spend_key = repeated48(0x55);
    let frame = encode_spend_key_derivation_frame(&spend_key);
    let material = derive_spend_key_material(&spend_key);

    assert_eq!(frame.len(), SPEND_KEY_DERIVATION_FRAME_BYTES);
    assert_eq!(&frame[..8], b"HEG-S4V2");
    assert_eq!(&frame[8..16], b"sp.keys1");
    assert_eq!(&frame[16..24], &SPEND_KEY_OUTPUT_ORDER_TAG);
    assert_eq!(frame[24], 1);
    assert_eq!(&frame[25..27], &[0, 48]);
    assert!(spend_key_material_matches(
        &spend_key,
        material.spend_auth_key,
        material.nullifier_key,
    ));

    let swapped_auth = SpendAuthKey::from_digest(material.nullifier_key.digest());
    let swapped_nullifier = NullifierKey::from_digest(material.spend_auth_key.digest());
    assert!(!spend_key_material_matches(
        &spend_key,
        swapped_auth,
        swapped_nullifier,
    ));
}

#[test]
fn debug_output_redacts_secret_material() {
    let workload = fixture();
    let trace = evaluate_pay1x2(&workload).unwrap();
    let rendered = format!("{workload:?} {trace:?}");

    assert!(rendered.contains("REDACTED"));
    assert!(!rendered.contains(&"55".repeat(48)));
    assert!(!rendered.contains("c1c5c181a068083ea434d832af3ac18e31348167737bc32a5d95ff68410d8f67"));
}

#[test]
fn python_hashlib_known_answer_vectors_match() {
    let trace = evaluate_pay1x2(&fixture()).unwrap();

    // Generated independently with Python 3 hashlib.shake_256 over the byte
    // grammar documented in README.md, then frozen here.
    assert_eq!(
        to_hex(trace.outputs.spend_keys.spend_auth_key.as_bytes()),
        "c1c5c181a068083ea434d832af3ac18e31348167737bc32a5d95ff68410d8f67db172714907ea294273fe53b1fc84aaa1ae7553505ab3661"
    );
    assert_eq!(
        to_hex(trace.outputs.spend_keys.nullifier_key.as_bytes()),
        "0fe5b53c318b9fc87027df8b4ba0184ec51fcc11afb1fc38b24937a21b05634a337c8e4f507890b365f833a58fb5c5b5cedc4c7eb53b1e25"
    );
    assert_eq!(
        to_hex(trace.outputs.input_commitment.as_bytes()),
        "77e04fcd18e1fb5fe3211fe16d850c7071f0a15ea1fd932b79ec1f3837c11c4f0e91fe32fbd7ead00a5d7069d58b74619192fb3ccb276bce"
    );
    assert_eq!(
        to_hex(trace.outputs.nullifier.as_bytes()),
        "7faadde34857654328579bf3501211a9a015defa588b1e3e6c396fb73e8b215a1f42ab171a3fb208dad8a7b05b8bf68d095915e52f0f7035"
    );
    assert_eq!(
        to_hex(trace.outputs.anchor.as_bytes()),
        "3c3e9d5e9770b844f33cc157c257c68f62213034246f65a4fa520aeda94ce50fe34afa9aea2f1e4e666f4bf396ea3bfdd9224165c52439fb"
    );
    assert_eq!(
        to_hex(trace.outputs.output_commitments[0].as_bytes()),
        "8fae301637f2ae50d0f38a3349496dd2d1148dc59a9c016067a60e7344ba7fea311dd354f9ecc830bb7d6284cd1098eeb164ac08b98f90bd"
    );
    assert_eq!(
        to_hex(trace.outputs.output_commitments[1].as_bytes()),
        "0f5beb87681f7805ee52c4845db6504b2615cc333b7eb114a851301cce1e6672309bb53a7168b8fa5744cf80ae96e996d8db977fba349b27"
    );
}

#[test]
fn pay1x2_geometry_is_exact_and_circuit_ready() {
    let trace = evaluate_pay1x2(&fixture()).unwrap();

    assert_eq!(trace.circuit_invocations.len(), DEPTH + 4);
    assert_eq!(trace.circuit_hash_invocations(), DEPTH + 5);
    assert_eq!(trace.circuit_keccak_f_permutations(), DEPTH + 8);
    assert_eq!(
        trace.circuit_absorbed_bytes(),
        75 + 3 * 229 + 135 + DEPTH * 133
    );
    assert_eq!(
        trace.circuit_invocations[0].role,
        SemanticRole::NoteCommitment
    );
    assert_eq!(trace.circuit_invocations[3].role, SemanticRole::Nullifier);
    assert!(trace.circuit_invocations[4..4 + DEPTH]
        .iter()
        .all(|entry| entry.role == SemanticRole::MerkleNode));
}

#[test]
fn one_field_mutations_change_their_bound_outputs() {
    let original = fixture();
    let baseline = evaluate_pay1x2(&original).unwrap();

    let mut input_value = original.clone();
    input_value.input_note.value ^= 1;
    assert_input_commitment_changed(&baseline, &input_value);

    let mut input_asset = original.clone();
    input_asset.input_note.asset_id ^= 1;
    assert_input_commitment_changed(&baseline, &input_asset);

    let mut input_recipient = original.clone();
    input_recipient.input_note.pk_recipient[0] ^= 1;
    assert_input_commitment_changed(&baseline, &input_recipient);

    let mut input_randomness = original.clone();
    input_randomness.input_note.randomness[31] ^= 1;
    assert_input_commitment_changed(&baseline, &input_randomness);

    let mut rho = original.clone();
    rho.input_note.rho[0] ^= 1;
    let changed = evaluate_pay1x2(&rho).unwrap();
    assert_ne!(
        baseline.outputs.input_commitment,
        changed.outputs.input_commitment
    );
    assert_ne!(baseline.outputs.nullifier, changed.outputs.nullifier);

    let mut key = original.clone();
    key.spend_key[31] ^= 1;
    let changed_keys = derive_spend_key_material(&key.spend_key);
    key.input_note.pk_auth = changed_keys.spend_auth_key.into_bytes();
    let changed = evaluate_pay1x2(&key).unwrap();
    assert_ne!(baseline.outputs.spend_keys, changed.outputs.spend_keys);
    assert_ne!(baseline.outputs.nullifier, changed.outputs.nullifier);
    assert_ne!(baseline.outputs.anchor, changed.outputs.anchor);

    let mut position = original.clone();
    position.position ^= 1;
    let changed = evaluate_pay1x2(&position).unwrap();
    assert_ne!(baseline.outputs.nullifier, changed.outputs.nullifier);
    assert_ne!(baseline.outputs.anchor, changed.outputs.anchor);

    let mut sibling = original.clone();
    let mut bytes = sibling.merkle_siblings[2].into_bytes();
    bytes[17] ^= 1;
    sibling.merkle_siblings[2] = MerkleNode::from_digest(SemanticDigest::from_bytes(bytes));
    let changed = evaluate_pay1x2(&sibling).unwrap();
    assert_ne!(baseline.outputs.anchor, changed.outputs.anchor);

    let mut output = original.clone();
    output.output_notes[1].pk_auth[8] ^= 1;
    let changed = evaluate_pay1x2(&output).unwrap();
    assert_ne!(
        baseline.outputs.output_commitments[1],
        changed.outputs.output_commitments[1]
    );

    let mut output_mutations = Vec::new();
    let mut output_value = original.clone();
    output_value.output_notes[0].value ^= 1;
    output_mutations.push(output_value);
    let mut output_asset = original.clone();
    output_asset.output_notes[0].asset_id ^= 1;
    output_mutations.push(output_asset);
    let mut output_recipient = original.clone();
    output_recipient.output_notes[0].pk_recipient[1] ^= 1;
    output_mutations.push(output_recipient);
    let mut output_rho = original.clone();
    output_rho.output_notes[0].rho[2] ^= 1;
    output_mutations.push(output_rho);
    let mut output_randomness = original.clone();
    output_randomness.output_notes[0].randomness[3] ^= 1;
    output_mutations.push(output_randomness);
    let mut output_auth = original.clone();
    output_auth.output_notes[0].pk_auth[4] ^= 1;
    output_mutations.push(output_auth);
    for mutation in output_mutations {
        assert_output0_commitment_changed(&baseline, &mutation);
    }

    let mut wrong_auth = original;
    wrong_auth.input_note.pk_auth[0] ^= 1;
    assert_eq!(
        evaluate_pay1x2(&wrong_auth),
        Err(HashError::SpendAuthorizationMismatch)
    );
}

#[test]
fn changing_registered_role_tag_changes_digest() {
    let left = [0xabu8; 56];
    let right = [0xcdu8; 56];
    let merkle = hash_fields(SemanticRole::MerkleNode, &[&left, &right]).unwrap();
    let mut frame = encode_frame(SemanticRole::MerkleNode, &[&left, &right]).unwrap();
    frame[8] ^= 1;
    let wrong_role = raw_shake256_448(&frame);

    // A raw mutated frame is intentionally not accepted by the public API, but
    // the primitive-level comparison proves that the role byte is absorbed.
    assert_ne!(merkle, wrong_role);
}

#[test]
fn merkle_depth_above_position_width_fails_closed() {
    let workload = Pay1x2HashWorkload::<65> {
        input_note: fixture().input_note,
        spend_key: [0u8; 48],
        position: 0,
        merkle_siblings: [MerkleNode::from_digest(SemanticDigest::ZERO); 65],
        output_notes: fixture().output_notes,
    };
    assert_eq!(
        evaluate_pay1x2(&workload),
        Err(HashError::UnsupportedMerkleDepth {
            depth: 65,
            maximum: 64,
        })
    );
}

#[test]
fn merkle_position_outside_fixed_depth_fails_closed() {
    let mut workload = fixture();
    workload.position = 1 << DEPTH;
    assert_eq!(
        evaluate_pay1x2(&workload),
        Err(HashError::PositionOutOfRange {
            position: 1 << DEPTH,
            depth: DEPTH,
        })
    );
}
