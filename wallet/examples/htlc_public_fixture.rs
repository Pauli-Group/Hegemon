//! Public-only Bitcoin regtest contract fixture. No signing keys or preimages.
use serde::Deserialize;
use transaction_circuit::smallwood_htlc::SecretRelease;
use wallet::htlc::{BitcoinRegtestTerms, HtlcOffer};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicTerms {
    hashlock: [u8; 32],
    bitcoin: BitcoinRegtestTerms,
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: htlc_public_fixture PUBLIC_TERMS_JSON"))?;
    let terms: PublicTerms = serde_json::from_slice(&std::fs::read(path)?)?;
    // Public deterministic fixture authorities only. This file creates no
    // funded Hegemon note and authorizes no live spend.
    let offer = HtlcOffer {
        version: 1,
        nonce: [0x21; 32],
        network_id: [0x42; 32],
        hashlock: terms.hashlock,
        value: 10_000,
        maximum_fee: 10,
        timeout_height: 10_000,
        claim_authority: [1, 2, 3, 4, 5, 6, 7],
        refund_authority: [8, 9, 10, 11, 12, 13, 14],
        claim_recipient: [1, 2, 3, 4],
        refund_recipient: [5, 6, 7, 8],
        secret_release: SecretRelease::HiddenOnHegemon,
        bitcoin: terms.bitcoin,
    };
    let fixture = serde_json::json!({"offer": offer, "witness_script_hex": hex::encode(offer.bitcoin_witness_script()?), "script_pubkey_hex": hex::encode(offer.bitcoin_script_pubkey()?), "offer_id_hex": hex::encode(offer.id()?)});
    println!("{}", serde_json::to_string_pretty(&fixture)?);
    Ok(())
}
