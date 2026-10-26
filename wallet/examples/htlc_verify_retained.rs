//! Verify retained public HTLC candidate carriers without loading wallet state.
use anyhow::{bail, Context, Result};
use sha2::Digest;
use std::{env, fs, path::PathBuf};
use transaction_circuit::{
    smallwood_htlc,
    smallwood_htlc_transport::{decode_candidate_exact, HtlcCarrier, HtlcCarrierProfile},
};

fn verify_carrier<'a>(bytes: &'a [u8], expected_chain: &[u8; 32]) -> Result<HtlcCarrier<'a>> {
    let carrier = decode_candidate_exact(bytes).context("decode exact candidate carrier")?;
    if carrier.profile != HtlcCarrierProfile::CandidateSmzc {
        bail!("carrier is not the candidate SMZC profile");
    }
    if &carrier.statement.network_id != expected_chain {
        bail!("carrier network id does not match the expected chain");
    }
    if !carrier.proof.starts_with(b"SMZC") {
        bail!("carrier proof is not SMZC");
    }
    smallwood_htlc::verify_candidate(&carrier.statement, carrier.proof)
        .context("verify candidate proof")?;
    Ok(carrier)
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .context("usage: htlc_verify_retained <carrier.bin> <expected-chain-id-hex>")?;
    let chain_hex = args.next().context("missing expected chain id")?;
    if args.next().is_some() {
        bail!("unexpected extra arguments");
    }
    let chain_hex = chain_hex
        .into_string()
        .map_err(|_| anyhow::anyhow!("chain id must be UTF-8 hex"))?;
    let chain = hex::decode(chain_hex).context("decode expected chain id")?;
    let expected_chain: [u8; 32] = chain
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected chain id must be 32 bytes"))?;
    let bytes =
        fs::read(&path).with_context(|| format!("read public carrier {}", path.display()))?;
    let carrier = verify_carrier(&bytes, &expected_chain)?;

    let mut tampered_statement = carrier.statement.clone();
    tampered_statement.network_id[31] ^= 1;
    let public_context_tamper_rejected =
        smallwood_htlc::verify_candidate(&tampered_statement, carrier.proof).is_err();
    let wrong_chain = {
        let mut value = expected_chain;
        value[0] ^= 1;
        value
    };
    let wrong_chain_rejected = verify_carrier(&bytes, &wrong_chain).is_err();
    let mut trailing = bytes.clone();
    trailing.push(0);
    let trailing_bytes_rejected = decode_candidate_exact(&trailing).is_err();
    if !(public_context_tamper_rejected && wrong_chain_rejected && trailing_bytes_rejected) {
        bail!("public negative verification failed");
    }

    println!(
        "{}",
        serde_json::json!({
            "accepted": true,
            "action": format!("{:?}", carrier.statement.action),
            "carrier_bytes": bytes.len(),
            "proof_bytes": carrier.proof.len(),
            "carrier_sha256": hex::encode(sha2::Sha256::digest(&bytes)),
            "proof_sha256": hex::encode(sha2::Sha256::digest(carrier.proof)),
            "relation_digest": hex::encode(smallwood_htlc::relation_digest()),
            "public_context_tamper_rejected": public_context_tamper_rejected,
            "wrong_chain_rejected": wrong_chain_rejected,
            "trailing_bytes_rejected": trailing_bytes_rejected,
            "private_witness_loaded": false,
            "production_authorized": false
        })
    );
    Ok(())
}
