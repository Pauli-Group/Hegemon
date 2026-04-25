use anyhow::{anyhow, Result};
use codec::Encode;
use consensus_light_client::{
    bridge_checkpoint_output_wire_bytes_v1, verify_hegemon_long_range_proof,
    HegemonLongRangeProofV1, RiscZeroBridgeReceiptV1, RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1,
};
use hegemon_risc0_bridge_methods::{HEGEMON_BRIDGE_ELF, HEGEMON_BRIDGE_ID};
use risc0_zkvm::{default_prover, Digest, ExecutorEnv, ProverOpts};

pub fn hegemon_bridge_image_id() -> [u8; 32] {
    let digest = Digest::from(HEGEMON_BRIDGE_ID);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

pub fn prove_hegemon_bridge(proof: &HegemonLongRangeProofV1) -> Result<RiscZeroBridgeReceiptV1> {
    let native_output = verify_hegemon_long_range_proof(
        proof,
        proof.output.confirmations_checked,
        proof.output.min_work_checked,
    )
    .map_err(|err| anyhow!("native preflight of Hegemon bridge proof failed: {err:?}"))?;
    let input = proof.encode();
    let input_len = u32::try_from(input.len()).map_err(|_| anyhow!("bridge proof too large"))?;
    let env = ExecutorEnv::builder()
        .write_slice(&input_len.to_le_bytes())
        .write_slice(&input)
        .build()?;
    let prove_info =
        default_prover().prove_with_opts(env, HEGEMON_BRIDGE_ELF, &risc0_prover_opts()?)?;
    let image_id = hegemon_bridge_image_id();
    prove_info
        .receipt
        .verify(Digest::from(image_id))
        .map_err(|err| anyhow!("RISC Zero bridge receipt self-verification failed: {err:?}"))?;
    if prove_info.receipt.journal.bytes != bridge_checkpoint_output_wire_bytes_v1(&native_output) {
        return Err(anyhow!(
            "RISC Zero bridge journal does not match native output"
        ));
    }
    Ok(RiscZeroBridgeReceiptV1 {
        proof_system_id: RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1,
        image_id,
        journal: prove_info.receipt.journal.bytes.clone(),
        receipt: bincode::serialize(&prove_info.receipt)?,
    })
}

fn risc0_prover_opts() -> Result<ProverOpts> {
    let kind = std::env::var("HEGEMON_RISC0_RECEIPT_KIND")
        .unwrap_or_else(|_| "succinct".to_string())
        .to_ascii_lowercase();
    match kind.as_str() {
        "succinct" => Ok(ProverOpts::succinct()),
        "composite" | "fast" => Ok(ProverOpts::composite()),
        other => Err(anyhow!(
            "unsupported HEGEMON_RISC0_RECEIPT_KIND {other}; expected succinct or composite"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_light_client::HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1;

    #[test]
    fn method_image_id_matches_protocol_constant() {
        assert_eq!(hegemon_bridge_image_id(), HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1);
    }
}
