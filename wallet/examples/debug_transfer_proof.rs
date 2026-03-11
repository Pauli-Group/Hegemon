use pallet_shielded_pool::types::{BindingHash, StarkProof};
use pallet_shielded_pool::verifier::{ProofVerifier, ShieldedTransferInputs, StarkVerifier};
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;
use wallet::{
    AsyncWalletSyncEngine, MemoPlaintext, Recipient, SubstrateRpcClient, WalletStore,
    build_transaction,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let boot_store = std::env::var("BOOT_STORE").unwrap_or_else(|_| {
        format!(
            "{}/hegemon-boot-wallet",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        )
    });
    let boot_pass =
        std::env::var("BOOT_PASS").unwrap_or_else(|_| "hegemonboot123".to_string());
    let test_store = std::env::var("TEST_STORE").unwrap_or_else(|_| {
        format!(
            "{}/hegemon-test-wallet",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        )
    });
    let test_pass =
        std::env::var("TEST_PASS").unwrap_or_else(|_| "testwallet123".to_string());
    let ws_url = std::env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:9946".to_string());
    let value = std::env::var("SEND_VALUE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100_000_000);

    let client = std::sync::Arc::new(SubstrateRpcClient::connect(&ws_url).await?);
    let boot = WalletStore::open(&boot_store, &boot_pass)?;
    let test = WalletStore::open(&test_store, &test_pass)?;

    let store = std::sync::Arc::new(boot);
    let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
    engine.sync_once().await?;

    let recipient = Recipient {
        address: test.primary_address()?,
        value,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        memo: MemoPlaintext::new(b"debug transfer".to_vec()),
    };

    let built = build_transaction(&store, &[recipient], 0)?;
    let decoded_notes = built.bundle.decode_notes()?;
    let ciphertext_hashes = decoded_notes
        .iter()
        .map(|note| note.to_da_bytes().map(|bytes| ciphertext_hash_bytes(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;

    let inputs = ShieldedTransferInputs {
        anchor: built.bundle.anchor,
        nullifiers: built.bundle.nullifiers.clone(),
        commitments: built.bundle.commitments.clone(),
        ciphertext_hashes,
        fee: built.bundle.fee,
        value_balance: built.bundle.value_balance,
        stablecoin: if built.bundle.stablecoin.enabled {
            Some(pallet_shielded_pool::types::StablecoinPolicyBinding {
                asset_id: built.bundle.stablecoin.asset_id,
                policy_hash: built.bundle.stablecoin.policy_hash,
                oracle_commitment: built.bundle.stablecoin.oracle_commitment,
                attestation_commitment: built.bundle.stablecoin.attestation_commitment,
                issuance_delta: built.bundle.stablecoin.issuance_delta,
                policy_version: built.bundle.stablecoin.policy_version,
            })
        } else {
            None
        },
    };

    let verifier = StarkVerifier::default();
    let vk = StarkVerifier::create_verifying_key(1);
    let proof = StarkProof::from_bytes(built.bundle.proof_bytes.clone());
    let binding_hash = BindingHash {
        data: built.bundle.binding_hash,
    };

    println!("anchor=0x{}", hex::encode(inputs.anchor));
    println!("nullifiers={}", inputs.nullifiers.len());
    println!("commitments={}", inputs.commitments.len());
    println!("ciphertext_hashes={}", inputs.ciphertext_hashes.len());
    println!(
        "ciphertext_bytes={}",
        built
            .bundle
            .ciphertexts
            .iter()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>()
    );
    println!("fee={}", inputs.fee);
    println!("value_balance={}", inputs.value_balance);
    println!(
        "verify_stark={:?}",
        verifier.verify_stark(&proof, &inputs, &vk)
    );
    println!(
        "verify_binding_hash={}",
        verifier.verify_binding_hash(&binding_hash, &inputs)
    );

    Ok(())
}
