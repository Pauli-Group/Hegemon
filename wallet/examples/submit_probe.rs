use wallet::{SubstrateRpcClient, TransactionBundle};

fn parse_hex48(s: &str) -> [u8; 48] {
    let t = s.trim_start_matches("0x");
    let b = hex::decode(t).unwrap();
    let mut out = [0u8; 48];
    out.copy_from_slice(&b);
    out
}

#[tokio::main]
async fn main() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9955")
        .await
        .unwrap();

    let raw_client = jsonrpsee::ws_client::WsClientBuilder::default()
        .build("ws://127.0.0.1:9955")
        .await
        .unwrap();
    use jsonrpsee::core::client::ClientT;
    let fin: String = raw_client
        .request("chain_getFinalizedHead", jsonrpsee::rpc_params![])
        .await
        .unwrap();
    let fin_root_hex: String = raw_client
        .request(
            "state_call",
            jsonrpsee::rpc_params!["ShieldedPoolApi_merkle_root", "0x", fin],
        )
        .await
        .unwrap();

    let anchor = parse_hex48(&fin_root_hex);

    let bundle = TransactionBundle {
        proof_bytes: vec![1, 2, 3],
        nullifiers: vec![[1u8; 48]],
        commitments: vec![],
        ciphertexts: vec![],
        anchor,
        binding_hash: [3u8; 64],
        balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
        fee: 1_000_000_000,
        value_balance: 0,
        stablecoin: transaction_circuit::StablecoinPolicyBinding::default(),
    };

    let anchor_valid_best = client.is_valid_anchor(&anchor).await.unwrap();
    println!(
        "finalized_root={} best_valid={}",
        fin_root_hex, anchor_valid_best
    );
    match client.submit_shielded_transfer_unsigned(&bundle).await {
        Ok(h) => println!("submitted: 0x{}", hex::encode(h)),
        Err(e) => println!("submit error: {}", e),
    }
}
