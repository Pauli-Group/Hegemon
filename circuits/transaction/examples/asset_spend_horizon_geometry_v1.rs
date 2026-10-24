//! Source-bound geometry measurement only; never generate or admit a proof.
//! cargo build --offline --locked --profile retained-proof -p transaction-circuit \
//!   --features private-spend-dev-artifacts --example asset_spend_horizon_geometry_v1
//! Run the example with one fresh output JSON path.
#[cfg(feature = "private-spend-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{fs::OpenOptions, io::Write};
    use transaction_circuit::{
        asset_policy_admin_v1 as admin, asset_spend_v1 as spend,
        asset_spend_v1_admission as admission,
    };
    let output = std::env::args()
        .nth(1)
        .ok_or("expected fresh output JSON path")?;
    if std::env::args().len() != 2 {
        return Err("usage: asset_spend_horizon_geometry_v1 NEW_OUTPUT.json".into());
    }
    let mut measurements = Vec::new();
    for mode in [0, 1] {
        for depth in [4, 8, 16] {
            let (public, witness) = if mode == 0 {
                spend::fixtures::fixture(spend::TRANSFER, depth)?
            } else {
                spend::fixtures::combined_fixture(spend::TRANSFER, depth, 0)?
            };
            let (adapter, packed) = spend::compile(&public, &witness)?;
            if public.words().len() != 134
                || adapter.geometry().packing != 64
                || adapter.geometry().degree != 2
            {
                return Err("public schema or arithmetization changed".into());
            }
            let packed_words = packed.len();
            drop(packed);
            drop(adapter);
            let geometry = spend::geometry_receipt(&public)?;
            let projected = geometry["projected_inner_bytes"]
                .as_u64()
                .ok_or("geometry lacks exact projected ceiling")?;
            measurements.push(serde_json::json!({
                "policy_mode": mode, "credential_depth": depth,
                "parent_height": public.parent_height,
                "credential_horizon": spend::credential_validity_horizon(public.parent_height)?,
                "public_words": public.words().as_slice(),
                "packed_witness_words": packed_words,
                "disclosed_fixture_constraints_satisfied": true,
                "native_cap_fit": projected <= admission::NATIVE_INNER_PROOF_CAP_BYTES as u64,
                "native_profile_gate": format!("{:?}", admission::spend_profile_upper_bound_v1(mode, depth)),
                "geometry": geometry,
            }));
        }
    }
    let report = serde_json::json!({
        "schema": "hegemon.asset-horizon.actual-geometry.v1",
        "scope": "Actual source/backend adapter geometry and disclosed fixture checks; no proof generation, verification, admission or security qualification",
        "relation_id": spend::RELATION_ID,
        "relation_source_sha512": hex::encode(spend::relation_digest()),
        "wire_relation_digest48": hex::encode(&spend::relation_digest()[..48]),
        "admin_relation_source_sha512": hex::encode(admin::relation_digest()),
        "retained_qualified_spend_source_sha512": admission::QUALIFIED_SPEND_SOURCE_SHA512,
        "reference_window": spend::ASSET_REFERENCE_WINDOW,
        "native_inner_proof_cap_bytes": admission::NATIVE_INNER_PROOF_CAP_BYTES,
        "public_word_count": spend::PUBLIC_WORDS,
        "proofs_generated": false,
        "production_authorized": false,
        "measurements": measurements,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!("measured six source-bound asset profiles into {output}");
    Ok(())
}

#[cfg(not(feature = "private-spend-dev-artifacts"))]
fn main() {
    eprintln!("enable private-spend-dev-artifacts for disclosed candidate geometry");
    std::process::exit(2);
}
