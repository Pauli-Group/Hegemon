//! Native-word M4 prototype for the exact HEG-S4V2 Merkle-parent frame.
//!
//! This crate deliberately proves one complete 133-byte Merkle-parent SHAKE256-448 invocation
//! before the same construction is repeated inside the full Pay1x2 relation. The two 56-byte
//! children are private witness words. The seven 64-bit output words are the only public in/out
//! values of the main circuit, so `VerifierM4::verify` binds all 56 output bytes.
//!
//! The upstream M4 prover is transparent and uses the upstream 96-bit/SHA-256/B128 profile. A
//! successful proof here is therefore implementation evidence only, not zero-knowledge or PQ128
//! security evidence.

#![forbid(unsafe_code)]

use binius_circuits::keccak::permutation::keccak_f1600;
use binius_core::{constraint_system::m4::WitnessM4, word::Word};
use binius_frontend::{CircuitBuilder, CircuitM4, CircuitStat, Wire};
use binius_hash::StdHashSuite;
use binius_m4_prover::ProverM4;
use binius_m4_verifier::VerifierM4;
use binius_prover::OptimalPackedB128;
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::config::StdChallenger;
use hegemon_standalone_shake256_prototype::{merkle_parent, MerkleNode, SemanticDigest};

pub const CHILD_BYTES: usize = 56;
pub const CHILD_WORDS: usize = CHILD_BYTES / 8;
pub const OUTPUT_BYTES: usize = 56;
pub const OUTPUT_WORDS: usize = OUTPUT_BYTES / 8;
pub const FRAME_BYTES: usize = 133;
pub const RATE_BYTES: usize = 136;
pub const RATE_WORDS: usize = RATE_BYTES / 8;

/// SHAKE's domain separator and final padding bit in the final little-endian rate word.
const SHAKE256_FINAL_WORD_PADDING: u64 = 0x8000_1f00_0000_0000;

pub const KAT_LEFT: [u8; CHILD_BYTES] = sequence::<0>();
pub const KAT_RIGHT: [u8; CHILD_BYTES] = sequence::<128>();
pub const KAT_OUTPUT: [u8; OUTPUT_BYTES] = [
    0x95, 0x16, 0xd2, 0x0f, 0x58, 0x7a, 0x6a, 0x03, 0x7b, 0xa7, 0xfa, 0x9f, 0x93, 0x21, 0xa9, 0xd3,
    0xfa, 0x45, 0xfa, 0xf7, 0x86, 0xaa, 0x48, 0xb9, 0x27, 0xf6, 0xd1, 0x8e, 0x95, 0xc3, 0x6b, 0x39,
    0x0f, 0xa8, 0xf3, 0x8f, 0x52, 0x92, 0xed, 0xe5, 0x53, 0xbd, 0xc1, 0x18, 0x8b, 0xc5, 0x18, 0x78,
    0x25, 0x67, 0xc0, 0x4e, 0x1e, 0xc4, 0xdb, 0x0c,
];

const fn sequence<const START: u8>() -> [u8; CHILD_BYTES] {
    let mut bytes = [0u8; CHILD_BYTES];
    let mut i = 0;
    while i < CHILD_BYTES {
        bytes[i] = START.wrapping_add(i as u8);
        i += 1;
    }
    bytes
}

pub struct MerkleParentCircuit {
    pub circuit: CircuitM4,
    left: [Wire; CHILD_WORDS],
    right: [Wire; CHILD_WORDS],
    output: [Wire; OUTPUT_WORDS],
}

impl MerkleParentCircuit {
    pub fn build() -> Self {
        let builder = CircuitBuilder::new();
        let left = std::array::from_fn(|_| builder.add_witness());
        let right = std::array::from_fn(|_| builder.add_witness());

        let frame = frame_words(&builder, &left, &right);
        let zero = builder.add_constant_64(0);
        let mut state = [zero; 25];
        state[..RATE_WORDS].copy_from_slice(&frame);
        state[RATE_WORDS - 1] = builder.bxor(
            state[RATE_WORDS - 1],
            builder.add_constant_64(SHAKE256_FINAL_WORD_PADDING),
        );
        keccak_f1600(&builder, &mut state);

        let output = std::array::from_fn(|i| state[i]);
        for word in output {
            builder.mark_inout(word);
        }

        let circuit = builder.build_m4();
        assert_eq!(
            circuit.main.circuit.inout(),
            &output,
            "public statement order must be SHAKE output lanes 0 through 6"
        );

        Self {
            circuit,
            left,
            right,
            output,
        }
    }

    pub fn generate_witness(
        &self,
        left: &[u8; CHILD_BYTES],
        right: &[u8; CHILD_BYTES],
    ) -> WitnessM4 {
        self.circuit
            .generate_witness(|filler| {
                populate_words(filler, &self.left, left);
                populate_words(filler, &self.right, right);
            })
            .expect("fixed Merkle-parent witness must populate")
    }

    pub fn output_from_witness(&self, witness: &WitnessM4) -> [u8; OUTPUT_BYTES] {
        let mut bytes = [0u8; OUTPUT_BYTES];
        for (i, wire) in self.output.iter().enumerate() {
            let index = self.circuit.main.circuit.witness_index(*wire);
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&witness.main[index].as_u64().to_le_bytes());
        }
        bytes
    }

    pub fn stats(&self) -> String {
        CircuitStat::collect(&self.circuit.main.circuit).to_string()
    }
}

fn populate_words(
    filler: &mut binius_frontend::WitnessFiller<'_>,
    wires: &[Wire; CHILD_WORDS],
    bytes: &[u8; CHILD_BYTES],
) {
    for (wire, chunk) in wires.iter().zip(bytes.chunks_exact(8)) {
        filler[*wire] = Word(u64::from_le_bytes(
            chunk.try_into().expect("eight-byte chunk"),
        ));
    }
}

/// Construct the fixed 133-byte frame as 17 little-endian words. This deliberately derives all
/// fixed bytes and length words inside the circuit. Only the child bytes are witnessed.
fn frame_words(
    builder: &CircuitBuilder,
    left: &[Wire; CHILD_WORDS],
    right: &[Wire; CHILD_WORDS],
) -> [Wire; RATE_WORDS] {
    const PREFIX: &[u8] = b"HEG-S4V2merk.nd1\x02\x00\x38";
    const RIGHT_LENGTH: &[u8] = b"\x00\x38";
    const LEFT_START: usize = PREFIX.len();
    const RIGHT_LENGTH_START: usize = LEFT_START + CHILD_BYTES;
    const RIGHT_START: usize = RIGHT_LENGTH_START + RIGHT_LENGTH.len();

    const _: () = assert!(LEFT_START == 19);
    const _: () = assert!(RIGHT_START == 77);
    const _: () = assert!(RIGHT_START + CHILD_BYTES == FRAME_BYTES);

    // Lay down the fixed bytes as constants. Child words are then shifted whole into this array.
    // Avoiding one byte mask per child byte matters: masks are AND constraints, while fixed word
    // shifts and XORs are linear in the native M4 relation.
    let mut fixed = [0u8; RATE_BYTES];
    fixed[..PREFIX.len()].copy_from_slice(PREFIX);
    fixed[RIGHT_LENGTH_START..RIGHT_START].copy_from_slice(RIGHT_LENGTH);
    let mut frame = std::array::from_fn(|word_index| {
        builder.add_constant_64(u64::from_le_bytes(
            fixed[word_index * 8..(word_index + 1) * 8]
                .try_into()
                .expect("one rate word"),
        ))
    });

    overlay_child(builder, &mut frame, left, LEFT_START);
    overlay_child(builder, &mut frame, right, RIGHT_START);
    frame
}

fn overlay_child(
    builder: &CircuitBuilder,
    frame: &mut [Wire; RATE_WORDS],
    child: &[Wire; CHILD_WORDS],
    start_byte: usize,
) {
    for (word_index, &word) in child.iter().enumerate() {
        let global_byte = start_byte + word_index * 8;
        let destination = global_byte / 8;
        let shift_bits = ((global_byte % 8) * 8) as u32;

        frame[destination] = builder.bxor(frame[destination], builder.shl(word, shift_bits));
        if shift_bits != 0 {
            frame[destination + 1] =
                builder.bxor(frame[destination + 1], builder.shr(word, 64 - shift_bits));
        }
    }
}

pub fn scalar_kat() -> [u8; OUTPUT_BYTES] {
    merkle_parent(
        MerkleNode::from_digest(SemanticDigest::from_bytes(KAT_LEFT)),
        MerkleNode::from_digest(SemanticDigest::from_bytes(KAT_RIGHT)),
    )
    .expect("fixed child lengths")
    .into_bytes()
}

pub fn prove(circuit: &MerkleParentCircuit, witness: &WitnessM4, log_inv_rate: usize) -> Vec<u8> {
    let cs = circuit.circuit.to_constraint_system();
    let verifier = VerifierM4::<StdHashSuite>::setup(&cs, log_inv_rate)
        .expect("fixed M4 constraint system must set up");
    let prover = ProverM4::<OptimalPackedB128, StdHashSuite>::setup(&verifier);
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    prover
        .prove(witness, &mut transcript)
        .expect("valid witness must prove");
    transcript.finalize()
}

pub fn verify_exact(
    circuit: &MerkleParentCircuit,
    public_output: &[Word],
    proof: Vec<u8>,
    log_inv_rate: usize,
) -> bool {
    let cs = circuit.circuit.to_constraint_system();
    let verifier = match VerifierM4::<StdHashSuite>::setup(&cs, log_inv_rate) {
        Ok(verifier) => verifier,
        Err(_) => return false,
    };
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof);
    verifier.verify(public_output, &mut transcript).is_ok() && transcript.finalize().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_scalar_kat_matches_native_m4_witness() {
        assert_eq!(scalar_kat(), KAT_OUTPUT, "the pinned scalar KAT drifted");

        let circuit = MerkleParentCircuit::build();
        circuit.circuit.validate().unwrap();
        let witness = circuit.generate_witness(&KAT_LEFT, &KAT_RIGHT);
        witness
            .verify(&circuit.circuit.to_constraint_system())
            .expect("native M4 witness satisfies every local constraint");
        assert_eq!(circuit.output_from_witness(&witness), KAT_OUTPUT);
        assert_eq!(witness.main.inout().len(), OUTPUT_WORDS);
        assert_eq!(
            witness.main.inout(),
            KAT_OUTPUT
                .chunks_exact(8)
                .map(|chunk| Word(u64::from_le_bytes(chunk.try_into().unwrap())))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[ignore = "transparent M4 proof run; use --ignored --release after the disk gate admits it"]
    fn proof_binds_public_output_and_rejects_mutation_and_trailing_bytes() {
        const LOG_INV_RATE: usize = 3;

        let circuit = MerkleParentCircuit::build();
        let witness = circuit.generate_witness(&KAT_LEFT, &KAT_RIGHT);
        let proof = prove(&circuit, &witness, LOG_INV_RATE);
        let statement = witness.main.inout().to_vec();

        assert!(verify_exact(
            &circuit,
            &statement,
            proof.clone(),
            LOG_INV_RATE
        ));

        let mut wrong_statement = statement.clone();
        wrong_statement[0] = Word(wrong_statement[0].as_u64() ^ 1);
        assert!(!verify_exact(
            &circuit,
            &wrong_statement,
            proof.clone(),
            LOG_INV_RATE
        ));

        let mut corrupted = proof.clone();
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 1;
        assert!(!verify_exact(&circuit, &statement, corrupted, LOG_INV_RATE));

        let mut trailing = proof;
        trailing.push(0);
        assert!(!verify_exact(&circuit, &statement, trailing, LOG_INV_RATE));
    }
}
