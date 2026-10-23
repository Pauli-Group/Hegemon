//! Fresh adapter CSR bindings only: no proof, source interpreter or extraction.
#[cfg(feature = "private-spend-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use hegemon_field::GOLDILOCKS_MODULUS as P;
    use sha2::{Digest as _, Sha256};
    use std::{fs::OpenOptions, io::Write};
    use transaction_circuit::{asset_spend_v1 as spend, SmallwoodConstraintAdapter};
    let output = std::env::args()
        .nth(1)
        .ok_or("fresh output path required")?;
    if std::env::args().len() != 2 {
        return Err("usage: asset_spend_horizon_binding_v1 NEW_OUTPUT.json".into());
    }
    let mut profiles = Vec::new();
    for mode in [0, 1] {
        for depth in [4, 8, 16] {
            let (public, _) = if mode == 0 {
                spend::fixtures::fixture(spend::TRANSFER, depth)?
            } else {
                spend::fixtures::combined_fixture(spend::TRANSFER, depth, 0)?
            };
            // The public adapter does not read a witness. No assignment is used
            // for any row identity below.
            let adapter = spend::AssetSpendAdapter::from_public(&public)?;
            let g = adapter.geometry();
            let offsets = adapter.linear_constraint_offsets();
            let indices = adapter.linear_constraint_indices();
            let coefficients = adapter.linear_constraint_coefficients();
            let targets = adapter.linear_targets();
            if offsets.len() != targets.len() + 1
                || offsets.first() != Some(&0)
                || offsets.last().map(|x| *x as usize) != Some(indices.len())
                || indices.len() != coefficients.len()
                || g.linear_equations != targets.len()
                || g.packing != 64
                || g.degree != 2
                || g.rows != g.canonical_wires.div_ceil(64) + 3 * g.nonlinear_batches
                || indices.iter().any(|x| *x as usize >= 64 * g.rows)
                || coefficients.iter().any(|x| *x == 0 || *x >= P)
                || targets.iter().any(|x| *x >= P)
            {
                return Err("fresh CSR buffer geometry or field encoding mismatch".into());
            }
            for row in 0..targets.len() {
                let start = offsets[row] as usize;
                let end = offsets[row + 1] as usize;
                if start > end
                    || end > indices.len()
                    || indices[start..end].windows(2).any(|p| p[0] >= p[1])
                {
                    return Err("CSR row offsets or canonical index order mismatch".into());
                }
            }
            let row_data = |row: usize| -> serde_json::Value {
                let start = offsets[row] as usize;
                let end = offsets[row + 1] as usize;
                serde_json::json!({"row":row,"offset_begin":start,"offset_end":end,
                    "entries": indices[start..end].iter().zip(&coefficients[start..end])
                        .map(|(i,c)| [u64::from(*i),*c]).collect::<Vec<_>>(),
                    "target": targets[row]})
            };
            // Before this new linear node:134 public Input nodes, sixteen
            // range32 gadgets (158 nodes/63 linear rows each), one range48
            // gadget (238 nodes/95 linear rows). This is allocator arithmetic;
            // the following complete raw-row comparison is actual adapter data.
            const HORIZON_WIRE: usize = 134 + 16 * 158 + 238;
            const HORIZON_ROW: usize = 16 * 63 + 95;
            let start = offsets[HORIZON_ROW] as usize;
            let end = offsets[HORIZON_ROW + 1] as usize;
            if indices[start..end] != [16, HORIZON_WIRE as u32]
                || coefficients[start..end] != [P - 1, 1]
                || targets[HORIZON_ROW] != spend::ASSET_REFERENCE_WINDOW
            {
                return Err("actual H+12 CSR row differs from source allocation".into());
            }
            let suffix = targets
                .len()
                .checked_sub(134)
                .ok_or("public suffix absent")?;
            let words = public.words();
            let mut public_rows = Vec::new();
            for (i, value) in words.into_iter().enumerate() {
                let row = suffix + i;
                let begin = offsets[row] as usize;
                let finish = offsets[row + 1] as usize;
                if indices[begin..finish] != [i as u32]
                    || coefficients[begin..finish] != [1]
                    || targets[row] != value
                {
                    return Err("fresh134 public unit-row identity failed".into());
                }
                public_rows.push(row_data(row));
            }
            // Exact mixed-width little-endian raw-buffer identity. This digest
            // is evidence identity; it is not a Lean equality premise.
            let mut raw = Sha256::new();
            raw.update(b"Hegemon.AssetHorizon.RawCSR.mixed-width-le.v1");
            for value in [
                g.canonical_wires,
                g.rows,
                g.nonlinear_batches,
                targets.len(),
            ] {
                raw.update((value as u64).to_le_bytes());
            }
            for values in [offsets, indices] {
                raw.update((values.len() as u64).to_le_bytes());
                for value in values {
                    raw.update(value.to_le_bytes());
                }
            }
            for values in [coefficients, targets] {
                raw.update((values.len() as u64).to_le_bytes());
                for value in values {
                    raw.update(value.to_le_bytes());
                }
            }
            profiles.push(serde_json::json!({
                "policy_mode":mode,"credential_depth":depth,
                "raw_csr_sha256":hex::encode(raw.finalize()),
                "all_raw_offsets_indices_coefficients_targets_checked":true,
                "horizon_wire":HORIZON_WIRE,"horizon_row":row_data(HORIZON_ROW),
                "public_rows":public_rows,"public_words":public.words().as_slice(),
                "geometry":spend::geometry_receipt(&public)?,
                "primitive_call_locator_exported":false,
                "primitive_locator_transport":"source allocator: old wire>=2900 shifts +1; public0..133 unchanged; retained compiler interpretation",
                "all_product_residuals_or_source_semantics_proved":false,
            }));
        }
    }
    let report = serde_json::json!({
        "schema":"hegemon.asset-horizon.actual-csr-binding.v1",
        "relation_id":spend::RELATION_ID,
        "relation_source_sha512":hex::encode(spend::relation_digest()),
        "reference_window":spend::ASSET_REFERENCE_WINDOW,
        "profiles":profiles,"witness_used_for_row_checks":false,
        "proofs_generated":false,"accepted_proof_extraction":false,
        "retained_compiler_source_interpretation_required":true,
        "production_authorized":false,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(feature = "private-spend-dev-artifacts"))]
fn main() {
    eprintln!("enable private-spend-dev-artifacts");
    std::process::exit(2);
}
