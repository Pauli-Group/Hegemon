//! Public-only fresh-process verification of retained self-contained RP06 source artifacts.
use sha2::{Digest, Sha512};
use std::{fs, path::PathBuf};
use transaction_circuit::smallwood_poseidon2_v8_rp06::{
    rp06_program_digest, rp06_program_identity_sha512, validate_rp06_transcript_bytes,
    verify_rp06_candidate_bytes, Rp06PublicStatement,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("retained directory required")?,
    );
    for stem in [
        "pair01-approval1",
        "pair01-approval2",
        "pair01",
        "pair02-approval1",
        "pair02-approval2",
        "pair02",
        "pair12-approval1",
        "pair12-approval2",
        "pair12",
    ] {
        let preamble = fs::read(directory.join(format!("{stem}.preamble")))?;
        validate_rp06_transcript_bytes(&preamble)?;
        let public = preamble[112..1136]
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().expect("eight")))
            .collect::<Vec<_>>();
        let statement = Rp06PublicStatement::try_from_public_words(&public)
            .map_err(|error| format!("invalid public statement: {error:?}"))?;
        let proof = fs::read(directory.join(format!("{stem}.smzb")))?;
        verify_rp06_candidate_bytes(&public, rp06_program_digest(), &proof, statement.chain_id)?;
        let mut mutated = public.clone();
        mutated[120] ^= 1;
        assert!(verify_rp06_candidate_bytes(
            &mutated,
            rp06_program_digest(),
            &proof,
            statement.chain_id
        )
        .is_err());
        println!(
            "{stem}: verified {} unchanged SMZB bytes, proof_sha512={}, program_sha512={}",
            proof.len(),
            hex::encode(Sha512::digest(&proof)),
            hex::encode(rp06_program_identity_sha512())
        );
    }
    Ok(())
}
