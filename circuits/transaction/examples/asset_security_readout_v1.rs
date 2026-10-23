//! Reconstruct an existing SMZE proof; never generate a proof.
//! cargo run -p transaction-circuit --release --features private-spend-dev-artifacts \
//!   --example asset_security_readout_v1 -- asset ACTION OUTPUT.json
//! cargo run ... -- admin ADMIN-RECEIPT.json PROOF.smze OUTPUT.json
#[cfg(feature = "private-spend-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{fs, io::Write};
    use transaction_circuit::{
        asset_policy_admin_v1 as admin,
        asset_registry_v1::AssetControlsV1,
        asset_security_readout_v1 as readout,
        asset_spend_v1_wire::{decode_asset_spend_action_v1, decode_native_asset_spend_action_v1},
    };
    use transaction_core::poseidon2_width16::Felt;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (value,output) = match args.first().map(String::as_str) {
        Some("asset") if args.len() == 3 => {
            let bytes = fs::read(&args[1])?;
            let action = if bytes.starts_with(b"HGANSP01") { decode_native_asset_spend_action_v1(&bytes)? }
                else { decode_asset_spend_action_v1(&bytes)? };
            (readout::asset_readout(&action.public, action.proof)?, &args[2])
        }
        Some("admin") if args.len() == 4 => {
            let receipt: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;
            let words: Vec<u64> = serde_json::from_value(receipt.get("public_words").ok_or("public_words missing")?.clone())?;
            if words.len() != 134 || words.iter().any(|w|*w >= hegemon_field::GOLDILOCKS_MODULUS) {
                return Err("admin readout needs134 canonical public words".into());
            }
            let digest = |start:usize| -> [u64;7] { words[start..start+7].try_into().expect("checked schema") };
            let bytes32 = |start:usize| -> Result<[u8;32], Box<dyn std::error::Error>> {
                let mut bytes = [0;32];
                for i in 0..8 { bytes[4*i..4*i+4].copy_from_slice(&u32::try_from(words[start+i])?.to_le_bytes()); }
                Ok(bytes)
            };
            let boolean = |index:usize| -> Result<bool, Box<dyn std::error::Error>> {
                match words[index] {0=>Ok(false),1=>Ok(true),_=>Err("admin nonboolean control".into())}
            };
            let public = admin::PolicyAdminPublicV1 {
                chain_id: bytes32(1)?, reference_parent_hash: bytes32(9)?, parent_height:words[17],
                registry_root:digest(18), after_registry_root:digest(25), asset_id:u32::try_from(words[32])?,
                old_policy_version:u32::try_from(words[33])?,new_policy_version:u32::try_from(words[34])?,
                policy_admin_commitment:digest(35),before_policy_leaf:digest(42),after_policy_leaf:digest(49),
                controls:AssetControlsV1 {credential_root:digest(56).map(Felt::from_u64),
                    credential_depth:u8::try_from(words[63])?,frozen:boolean(64)?,mint_enabled:boolean(65)?},
                expires_at:words[66],action_intent:digest(67),
            };
            public.validate_structure()?;
            if public.words().as_slice() != words.as_slice() { return Err("admin full134 source context/padding mismatch".into()); }
            let proof = fs::read(&args[2])?;
            (readout::admin_readout(&public,&proof)?, &args[3])
        }
        _ => return Err("usage: asset_security_readout_v1 asset ACTION OUTPUT.json | admin RECEIPT.json PROOF.smze OUTPUT.json".into()),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&value)?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(feature = "private-spend-dev-artifacts"))]
fn main() {
    eprintln!("enable private-spend-dev-artifacts to reconstruct an existing SMZE proof");
    std::process::exit(2);
}
