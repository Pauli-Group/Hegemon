use anyhow::{anyhow, Context, Result};
use codec::{Decode, Encode};
use consensus_light_client::HegemonLongRangeProofV1;
use hegemon_risc0_bridge_prover::prove_hegemon_bridge;
use std::path::Path;

fn main() -> Result<()> {
    let proof_hex = proof_hex_arg()?;
    let proof_bytes = hex::decode(proof_hex.trim_start_matches("0x").trim())
        .context("decode HegemonLongRangeProofV1 hex")?;
    let mut encoded = proof_bytes.as_slice();
    let proof = HegemonLongRangeProofV1::decode(&mut encoded)
        .map_err(|err| anyhow!("decode HegemonLongRangeProofV1 failed: {err:?}"))?;
    if !encoded.is_empty() {
        return Err(anyhow!("HegemonLongRangeProofV1 has trailing bytes"));
    }
    let receipt = prove_hegemon_bridge(&proof)?;
    println!("0x{}", hex::encode(receipt.encode()));
    Ok(())
}

fn proof_hex_arg() -> Result<String> {
    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or_else(|| anyhow!("usage: prove_hegemon_bridge <0x-proof> | --proof-file <path>"))?;
    if first == "--proof-file" {
        let path = args
            .next()
            .ok_or_else(|| anyhow!("--proof-file requires a path"))?;
        return std::fs::read_to_string(Path::new(&path))
            .with_context(|| format!("read proof file {path}"));
    }
    if args.next().is_some() {
        return Err(anyhow!(
            "usage: prove_hegemon_bridge <0x-proof> | --proof-file <path>"
        ));
    }
    Ok(first)
}
