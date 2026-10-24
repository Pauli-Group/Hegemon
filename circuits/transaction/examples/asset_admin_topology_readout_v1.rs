//! After coordinator integration: export existing admin adapter topology only.
#[cfg(feature = "private-spend-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{fs, io::Write};
    use transaction_circuit::{
        asset_admin_topology_readout_v1::admin_topology_readout, asset_policy_admin_v1 as admin,
        asset_registry_v1::AssetControlsV1,
        asset_spend_v1_wire::decode_native_asset_admin_action_v1,
    };
    use transaction_core::poseidon2_width16::Felt;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: asset_admin_topology_readout_v1 receipt RECEIPT.json OUTPUT.json | native ADMIN.carrier OUTPUT.json".into());
    }
    if fs::metadata(&args[1])?.len() > 3 * 1024 * 1024 {
        return Err("bounded admin topology input exceeds3MiB".into());
    }
    let source = fs::read(&args[1])?;
    let public = match args[0].as_str() {
        "native" => decode_native_asset_admin_action_v1(&source)?.public,
        "receipt" => {
            let receipt: serde_json::Value = serde_json::from_slice(&source)?;
            let words: Vec<u64> = serde_json::from_value(
                receipt
                    .get("public_words")
                    .ok_or("public_words missing")?
                    .clone(),
            )?;
            if words.len() != 134
                || words
                    .iter()
                    .any(|w| *w >= hegemon_field::GOLDILOCKS_MODULUS)
            {
                return Err("exact134 canonical public words required".into());
            }
            let digest = |start: usize| -> [u64; 7] { words[start..start + 7].try_into().unwrap() };
            let bytes32 = |start: usize| -> Result<[u8; 32], Box<dyn std::error::Error>> {
                let mut result = [0; 32];
                for i in 0..8 {
                    result[4 * i..4 * i + 4]
                        .copy_from_slice(&u32::try_from(words[start + i])?.to_le_bytes());
                }
                Ok(result)
            };
            let boolean = |i: usize| -> Result<bool, Box<dyn std::error::Error>> {
                match words[i] {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err("nonboolean control".into()),
                }
            };
            let value = admin::PolicyAdminPublicV1 {
                chain_id: bytes32(1)?,
                reference_parent_hash: bytes32(9)?,
                parent_height: words[17],
                registry_root: digest(18),
                after_registry_root: digest(25),
                asset_id: u32::try_from(words[32])?,
                old_policy_version: u32::try_from(words[33])?,
                new_policy_version: u32::try_from(words[34])?,
                policy_admin_commitment: digest(35),
                before_policy_leaf: digest(42),
                after_policy_leaf: digest(49),
                controls: AssetControlsV1 {
                    credential_root: digest(56).map(Felt::from_u64),
                    credential_depth: u8::try_from(words[63])?,
                    frozen: boolean(64)?,
                    mint_enabled: boolean(65)?,
                },
                expires_at: words[66],
                action_intent: digest(67),
            };
            value.validate_structure()?;
            if value.words().as_slice() != words.as_slice() {
                return Err("admin current source/context/padding mismatch".into());
            }
            value
        }
        _ => return Err("expected receipt or native mode".into()),
    };
    let value = admin_topology_readout(&public)?;
    let bytes = serde_json::to_vec_pretty(&value)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("topology output exceeds16MiB".into());
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!("admin exact CSR topology exported; no proof/witness execution or security closure");
    Ok(())
}
#[cfg(not(feature = "private-spend-dev-artifacts"))]
fn main() {
    eprintln!("enable private-spend-dev-artifacts");
    std::process::exit(2);
}
