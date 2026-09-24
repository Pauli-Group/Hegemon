use hegemon_standalone_shake256_prototype::{
    derive_spend_key_material, evaluate_pay1x2, MerkleNode, NoteOpening, Pay1x2HashWorkload,
    SemanticDigest,
};

const DEPTH: usize = 32;

fn main() {
    let spend_key = [0x20; 48];
    let mut input_note = note(50, 0x10);
    input_note.pk_auth = derive_spend_key_material(&spend_key)
        .spend_auth_key
        .into_bytes();
    let workload = Pay1x2HashWorkload::<DEPTH> {
        input_note,
        spend_key,
        position: 5,
        merkle_siblings: core::array::from_fn(|level| {
            let bytes = core::array::from_fn(|index| {
                0x30u8.wrapping_add(level as u8).wrapping_add(index as u8)
            });
            MerkleNode::from_digest(SemanticDigest::from_bytes(bytes))
        }),
        output_notes: [note(19, 0x40), note(29, 0x50)],
    };

    let trace = evaluate_pay1x2(&workload).expect("fixed fixture must evaluate");
    println!("profile=standalone-shake256-448-prototype-v2");
    println!("depth={DEPTH}");
    println!("semantic_digest_bytes=56");
    println!(
        "circuit_hash_invocations={}",
        trace.circuit_hash_invocations()
    );
    println!("circuit_absorbed_bytes={}", trace.circuit_absorbed_bytes());
    println!(
        "circuit_keccak_f_permutations={}",
        trace.circuit_keccak_f_permutations()
    );
    println!("merkle_parent_frame_bytes=133");
    println!("anchor={}", hex(trace.outputs.anchor.as_bytes()));
}

fn note(value: u64, seed: u8) -> NoteOpening {
    NoteOpening {
        value,
        asset_id: 7,
        pk_recipient: [seed; 32],
        rho: [seed.wrapping_add(1); 48],
        randomness: [seed.wrapping_add(2); 48],
        pk_auth: [seed.wrapping_add(3); 56],
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}
