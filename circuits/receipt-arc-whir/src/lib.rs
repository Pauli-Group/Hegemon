use anyhow::{ensure, Result};
use crypto::hashes::blake3_384;
use p3_field::{coset::TwoAdicMultiplicativeCoset, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

pub const RECEIPT_ARC_WHIR_ARTIFACT_KIND_BYTES: [u8; 16] = *b"rcpt_arc_whir_v1";
pub const RECEIPT_ARC_WHIR_ARTIFACT_VERSION: u16 = 1;

const ROW_HASH_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:row:v1";
const ROW_COMMITMENT_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:rows:v1";
const ROW_FIELD_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:field:v1";
const ARC_CHALLENGE_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:arc_challenge:v2";
const CODEWORD_LEAF_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:leaf:v2";
const CODEWORD_NODE_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:node:v2";
const QUERY_SEED_DOMAIN: &[u8] = b"hegemon:receipt_arc_whir:queries:v2";

const DEFAULT_LOG_BLOWUP: u8 = 2;
const DEFAULT_QUERY_COUNT: u8 = 8;
const DEFAULT_FOLDING_ROUNDS: u8 = 4;
const MAX_LOG_BLOWUP: u8 = 6;
const MAX_QUERY_COUNT: u8 = 64;
const MAX_FOLDING_ROUNDS: u8 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRow {
    pub statement_hash: [u8; 48],
    pub proof_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: [u8; 48],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptArcWhirParams {
    pub log_blowup: u8,
    pub query_count: u8,
    pub folding_rounds: u8,
}

impl Default for ReceiptArcWhirParams {
    fn default() -> Self {
        Self {
            log_blowup: DEFAULT_LOG_BLOWUP,
            query_count: DEFAULT_QUERY_COUNT,
            folding_rounds: DEFAULT_FOLDING_ROUNDS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptResidualArtifact {
    pub version: u16,
    pub receipt_commitment: [u8; 48],
    pub codeword_len: u32,
    pub arc_bytes: Vec<u8>,
    pub whir_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptResidualVerifyReport {
    pub row_count: usize,
    pub artifact_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArcResidual {
    layer_roots: Vec<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoundQueryProof {
    left_value: u64,
    right_value: u64,
    left_siblings: Vec<[u8; 48]>,
    right_siblings: Vec<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryProof {
    rounds: Vec<RoundQueryProof>,
    final_value: u64,
    final_siblings: Vec<[u8; 48]>,
}

#[derive(Clone, Debug)]
struct LayerCommitment {
    values: Vec<Goldilocks>,
    tree: MerkleTree,
}

#[derive(Clone, Debug)]
struct MerkleTree {
    layers: Vec<Vec<[u8; 48]>>,
}

pub fn canonical_receipt_row_hash(row: &ReceiptRow) -> [u8; 48] {
    let mut bytes = Vec::with_capacity(ROW_HASH_DOMAIN.len() + (48 * 4));
    bytes.extend_from_slice(ROW_HASH_DOMAIN);
    bytes.extend_from_slice(&row.statement_hash);
    bytes.extend_from_slice(&row.proof_digest);
    bytes.extend_from_slice(&row.public_inputs_digest);
    bytes.extend_from_slice(&row.verifier_profile);
    blake3_384(&bytes)
}

pub fn receipt_rows_commitment(rows: &[ReceiptRow]) -> [u8; 48] {
    let row_hashes = row_hashes(rows);
    let mut bytes = Vec::with_capacity(ROW_COMMITMENT_DOMAIN.len() + 4 + (row_hashes.len() * 48));
    bytes.extend_from_slice(ROW_COMMITMENT_DOMAIN);
    bytes.extend_from_slice(&(row_hashes.len() as u32).to_le_bytes());
    for row_hash in &row_hashes {
        bytes.extend_from_slice(row_hash);
    }
    blake3_384(&bytes)
}

pub fn prove_receipt_arc_whir(
    rows: &[ReceiptRow],
    params: &ReceiptArcWhirParams,
) -> Result<Vec<u8>> {
    validate_params(rows, params)?;
    let receipt_commitment = receipt_rows_commitment(rows);
    let artifact = build_artifact(rows, params, receipt_commitment)?;
    let encoded = encode_receipt_residual_artifact(&artifact);
    ensure!(
        encoded.len() <= max_receipt_arc_whir_artifact_bytes_with_params(rows.len(), params),
        "receipt-arc-whir artifact size {} exceeds {}",
        encoded.len(),
        max_receipt_arc_whir_artifact_bytes_with_params(rows.len(), params)
    );
    Ok(encoded)
}

pub fn verify_receipt_arc_whir(
    rows: &[ReceiptRow],
    artifact_bytes: &[u8],
    params: &ReceiptArcWhirParams,
) -> Result<ReceiptResidualVerifyReport> {
    validate_params(rows, params)?;
    ensure!(
        artifact_bytes.len() <= max_receipt_arc_whir_artifact_bytes_with_params(rows.len(), params),
        "receipt-arc-whir artifact size {} exceeds {}",
        artifact_bytes.len(),
        max_receipt_arc_whir_artifact_bytes_with_params(rows.len(), params)
    );

    let artifact = decode_receipt_residual_artifact(artifact_bytes)?;
    let receipt_commitment = receipt_rows_commitment(rows);
    ensure!(
        artifact.receipt_commitment == receipt_commitment,
        "receipt-arc-whir receipt commitment mismatch"
    );

    let expected_codeword_len = codeword_len(rows.len(), params.log_blowup)?;
    ensure!(
        artifact.codeword_len == expected_codeword_len as u32,
        "receipt-arc-whir codeword length mismatch"
    );

    let rounds = effective_folding_rounds(expected_codeword_len, params.folding_rounds);
    let query_count = effective_query_count(expected_codeword_len, params.query_count);
    let arc = decode_arc_bytes(&artifact.arc_bytes, rounds)?;
    let query_proofs = decode_whir_bytes(
        &artifact.whir_bytes,
        expected_codeword_len,
        query_count,
        rounds,
    )?;

    verify_query_proofs(
        rows,
        params,
        receipt_commitment,
        expected_codeword_len,
        &arc,
        &query_proofs,
    )?;

    Ok(ReceiptResidualVerifyReport {
        row_count: rows.len(),
        artifact_bytes: artifact_bytes.len(),
    })
}

pub fn max_receipt_arc_whir_artifact_bytes(row_count: usize) -> usize {
    max_receipt_arc_whir_artifact_bytes_with_params(row_count, &ReceiptArcWhirParams::default())
}

fn build_artifact(
    rows: &[ReceiptRow],
    params: &ReceiptArcWhirParams,
    receipt_commitment: [u8; 48],
) -> Result<ReceiptResidualArtifact> {
    let base_len = base_domain_len(rows.len());
    let codeword_len = codeword_len(rows.len(), params.log_blowup)?;
    let rounds = effective_folding_rounds(codeword_len, params.folding_rounds);
    let base_values = padded_row_field_values(rows, base_len);
    let codeword = reed_solomon_codeword(&base_values, codeword_len)?;
    let layers = build_fold_layers(codeword, receipt_commitment, rounds)?;
    let query_count = effective_query_count(codeword_len, params.query_count);
    let arc = ArcResidual {
        layer_roots: layers.iter().map(|layer| layer.tree.root()).collect(),
    };
    let query_proofs = build_query_proofs(
        &layers,
        receipt_commitment,
        params,
        codeword_len,
        query_count,
    );

    Ok(ReceiptResidualArtifact {
        version: RECEIPT_ARC_WHIR_ARTIFACT_VERSION,
        receipt_commitment,
        codeword_len: codeword_len as u32,
        arc_bytes: encode_arc_bytes(&arc),
        whir_bytes: encode_whir_bytes(&query_proofs, codeword_len, rounds),
    })
}

fn verify_query_proofs(
    rows: &[ReceiptRow],
    params: &ReceiptArcWhirParams,
    receipt_commitment: [u8; 48],
    codeword_len: usize,
    arc: &ArcResidual,
    query_proofs: &[QueryProof],
) -> Result<()> {
    let rounds = effective_folding_rounds(codeword_len, params.folding_rounds);
    ensure!(
        arc.layer_roots.len() == rounds + 1,
        "receipt-arc-whir expected {} layer roots, got {}",
        rounds + 1,
        arc.layer_roots.len()
    );
    let query_count = effective_query_count(codeword_len, params.query_count);
    ensure!(
        query_proofs.len() == query_count,
        "receipt-arc-whir expected {} query proofs, got {}",
        query_count,
        query_proofs.len()
    );

    let base_len = base_domain_len(rows.len());
    let base_values = padded_row_field_values(rows, base_len);
    let base_domain_points = domain_points(base_len)?;
    let bary_weights = barycentric_weights(&base_domain_points)?;
    let query_positions = derive_query_positions(
        receipt_commitment,
        &arc.layer_roots,
        params,
        codeword_len,
        query_count,
    );
    let codeword_log_size = log2_pow2(codeword_len)?;

    for (query_idx, (position, query_proof)) in query_positions.iter().zip(query_proofs).enumerate()
    {
        ensure!(
            query_proof.rounds.len() == rounds,
            "receipt-arc-whir query {query_idx} expected {rounds} rounds, got {}",
            query_proof.rounds.len()
        );
        let codeword_point = domain_element(codeword_log_size, *position)?;
        let mut expected = barycentric_evaluate(
            codeword_point,
            &base_domain_points,
            &base_values,
            &bary_weights,
        );
        let mut current_position = *position;
        let mut layer_len = codeword_len;

        for round in 0..rounds {
            let round_proof = &query_proof.rounds[round];
            let half = layer_len / 2;
            let pair_index = current_position % half;
            let left_index = pair_index;
            let right_index = pair_index + half;
            let left_value = Goldilocks::new(round_proof.left_value);
            let right_value = Goldilocks::new(round_proof.right_value);

            verify_merkle_path(
                round as u32,
                left_index,
                left_value,
                &round_proof.left_siblings,
                arc.layer_roots[round],
            )?;
            verify_merkle_path(
                round as u32,
                right_index,
                right_value,
                &round_proof.right_siblings,
                arc.layer_roots[round],
            )?;

            let opened = if current_position < half {
                left_value
            } else {
                right_value
            };
            ensure!(
                opened == expected,
                "receipt-arc-whir query {query_idx} round {round} opened value mismatch"
            );

            let alpha =
                derive_round_challenge(receipt_commitment, arc.layer_roots[round], round as u32);
            let x0 = domain_element(log2_pow2(layer_len)?, pair_index)?;
            expected = fold_pair(x0, left_value, right_value, alpha);
            current_position = pair_index;
            layer_len = half;
        }

        let final_value = Goldilocks::new(query_proof.final_value);
        verify_merkle_path(
            rounds as u32,
            current_position,
            final_value,
            &query_proof.final_siblings,
            arc.layer_roots[rounds],
        )?;
        ensure!(
            final_value == expected,
            "receipt-arc-whir query {query_idx} final value mismatch"
        );
    }

    Ok(())
}

fn validate_params(rows: &[ReceiptRow], params: &ReceiptArcWhirParams) -> Result<()> {
    ensure!(
        !rows.is_empty(),
        "receipt-arc-whir requires at least one receipt row"
    );
    ensure!(
        params.log_blowup <= MAX_LOG_BLOWUP,
        "receipt-arc-whir log_blowup {} exceeds {}",
        params.log_blowup,
        MAX_LOG_BLOWUP
    );
    ensure!(
        params.query_count > 0 && params.query_count <= MAX_QUERY_COUNT,
        "receipt-arc-whir query_count {} is outside 1..={}",
        params.query_count,
        MAX_QUERY_COUNT
    );
    ensure!(
        params.folding_rounds <= MAX_FOLDING_ROUNDS,
        "receipt-arc-whir folding_rounds {} exceeds {}",
        params.folding_rounds,
        MAX_FOLDING_ROUNDS
    );
    let codeword_len = codeword_len(rows.len(), params.log_blowup)?;
    ensure!(
        effective_query_count(codeword_len, params.query_count) > 0,
        "receipt-arc-whir query_count {} collapsed to zero",
        params.query_count
    );
    Ok(())
}

fn base_domain_len(row_count: usize) -> usize {
    row_count.next_power_of_two()
}

fn codeword_len(row_count: usize, log_blowup: u8) -> Result<usize> {
    ensure!(row_count > 0, "receipt-arc-whir row_count must be non-zero");
    let base = base_domain_len(row_count);
    let blowup = 1usize
        .checked_shl(u32::from(log_blowup))
        .ok_or_else(|| anyhow::anyhow!("receipt-arc-whir blowup overflow"))?;
    base.checked_mul(blowup)
        .ok_or_else(|| anyhow::anyhow!("receipt-arc-whir codeword length overflow"))
}

fn effective_folding_rounds(codeword_len: usize, requested: u8) -> usize {
    requested.min(codeword_len.trailing_zeros() as u8) as usize
}

fn effective_query_count(codeword_len: usize, requested: u8) -> usize {
    usize::from(requested).min(codeword_len)
}

fn row_hashes(rows: &[ReceiptRow]) -> Vec<[u8; 48]> {
    rows.iter().map(canonical_receipt_row_hash).collect()
}

fn row_field_values(rows: &[ReceiptRow]) -> Vec<Goldilocks> {
    row_hashes(rows).iter().map(row_hash_to_field).collect()
}

fn padded_row_field_values(rows: &[ReceiptRow], base_len: usize) -> Vec<Goldilocks> {
    let mut values = row_field_values(rows);
    values.resize(base_len, Goldilocks::ZERO);
    values
}

fn row_hash_to_field(row_hash: &[u8; 48]) -> Goldilocks {
    let mut material = Vec::with_capacity(ROW_FIELD_DOMAIN.len() + 48);
    material.extend_from_slice(ROW_FIELD_DOMAIN);
    material.extend_from_slice(row_hash);
    let digest = blake3_384(&material);
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&digest[..8]);
    Goldilocks::new(u64::from_le_bytes(limb))
}

fn reed_solomon_codeword(values: &[Goldilocks], codeword_len: usize) -> Result<Vec<Goldilocks>> {
    ensure!(
        values.len().is_power_of_two(),
        "receipt-arc-whir base domain must be a power of two"
    );
    let base_points = domain_points(values.len())?;
    let barycentric_weights = barycentric_weights(&base_points)?;
    let codeword_points = domain_points(codeword_len)?;
    Ok(codeword_points
        .into_iter()
        .map(|point| barycentric_evaluate(point, &base_points, values, &barycentric_weights))
        .collect())
}

fn domain_points(size: usize) -> Result<Vec<Goldilocks>> {
    Ok(subgroup_domain(log2_pow2(size)?)?.iter().collect())
}

fn domain_element(log_size: usize, index: usize) -> Result<Goldilocks> {
    let mut domain = subgroup_domain(log_size)?;
    Ok(domain.element(index))
}

fn subgroup_domain(log_size: usize) -> Result<TwoAdicMultiplicativeCoset<Goldilocks>> {
    TwoAdicMultiplicativeCoset::new(Goldilocks::ONE, log_size).ok_or_else(|| {
        anyhow::anyhow!("receipt-arc-whir unsupported subgroup of size 2^{log_size}")
    })
}

fn log2_pow2(size: usize) -> Result<usize> {
    ensure!(
        size.is_power_of_two(),
        "receipt-arc-whir expected power-of-two size, got {size}"
    );
    Ok(size.trailing_zeros() as usize)
}

fn barycentric_weights(xs: &[Goldilocks]) -> Result<Vec<Goldilocks>> {
    let mut weights = Vec::with_capacity(xs.len());
    for (idx, x_i) in xs.iter().enumerate() {
        let mut denom = Goldilocks::ONE;
        for (jdx, x_j) in xs.iter().enumerate() {
            if idx == jdx {
                continue;
            }
            denom *= *x_i - *x_j;
        }
        ensure!(
            denom != Goldilocks::ZERO,
            "receipt-arc-whir interpolation encountered a duplicate domain point"
        );
        weights.push(denom.inverse());
    }
    Ok(weights)
}

fn barycentric_evaluate(
    x: Goldilocks,
    xs: &[Goldilocks],
    ys: &[Goldilocks],
    weights: &[Goldilocks],
) -> Goldilocks {
    for (idx, domain_x) in xs.iter().enumerate() {
        if x == *domain_x {
            return ys[idx];
        }
    }
    let mut numerator = Goldilocks::ZERO;
    let mut denominator = Goldilocks::ZERO;
    for idx in 0..xs.len() {
        let term = weights[idx] * (x - xs[idx]).inverse();
        numerator += term * ys[idx];
        denominator += term;
    }
    numerator * denominator.inverse()
}

impl LayerCommitment {
    fn new(layer_index: u32, values: Vec<Goldilocks>) -> Self {
        let tree = MerkleTree::build(layer_index, &values);
        Self { values, tree }
    }
}

impl MerkleTree {
    fn build(layer_index: u32, values: &[Goldilocks]) -> Self {
        let mut layers = Vec::new();
        let mut current = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                codeword_leaf_hash(layer_index, index as u32, value.as_canonical_u64())
            })
            .collect::<Vec<_>>();
        layers.push(current.clone());
        while current.len() > 1 {
            let next = current
                .chunks_exact(2)
                .map(|chunk| codeword_node_hash(layer_index, &chunk[0], &chunk[1]))
                .collect::<Vec<_>>();
            layers.push(next.clone());
            current = next;
        }
        Self { layers }
    }

    fn root(&self) -> [u8; 48] {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or([0u8; 48])
    }

    fn path(&self, mut index: usize) -> Vec<[u8; 48]> {
        let mut path = Vec::with_capacity(self.layers.len().saturating_sub(1));
        for layer in &self.layers[..self.layers.len().saturating_sub(1)] {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            path.push(layer[sibling_index]);
            index /= 2;
        }
        path
    }
}

fn build_fold_layers(
    codeword: Vec<Goldilocks>,
    receipt_commitment: [u8; 48],
    rounds: usize,
) -> Result<Vec<LayerCommitment>> {
    ensure!(
        codeword.len().is_power_of_two(),
        "receipt-arc-whir codeword must be a power of two"
    );

    let mut layers = Vec::with_capacity(rounds + 1);
    let mut current = codeword;
    layers.push(LayerCommitment::new(0, current.clone()));

    for round in 0..rounds {
        let layer_root = layers[round].tree.root();
        let alpha = derive_round_challenge(receipt_commitment, layer_root, round as u32);
        let log_size = log2_pow2(current.len())?;
        current = fold_layer(&current, log_size, alpha)?;
        layers.push(LayerCommitment::new((round + 1) as u32, current.clone()));
    }

    Ok(layers)
}

fn fold_layer(
    values: &[Goldilocks],
    log_size: usize,
    alpha: Goldilocks,
) -> Result<Vec<Goldilocks>> {
    ensure!(
        values.len() > 1 && values.len().is_power_of_two(),
        "receipt-arc-whir fold layer requires a power-of-two layer longer than 1"
    );
    let half = values.len() / 2;
    (0..half)
        .map(|index| {
            let x0 = domain_element(log_size, index)?;
            Ok(fold_pair(x0, values[index], values[index + half], alpha))
        })
        .collect()
}

fn fold_pair(
    x0: Goldilocks,
    left_value: Goldilocks,
    right_value: Goldilocks,
    alpha: Goldilocks,
) -> Goldilocks {
    let neg_two_inv = -(Goldilocks::new(2).inverse());
    let inv = neg_two_inv * x0.inverse();
    left_value + (alpha - x0) * (right_value - left_value) * inv
}

fn build_query_proofs(
    layers: &[LayerCommitment],
    receipt_commitment: [u8; 48],
    params: &ReceiptArcWhirParams,
    codeword_len: usize,
    query_count: usize,
) -> Vec<QueryProof> {
    let layer_roots = layers
        .iter()
        .map(|layer| layer.tree.root())
        .collect::<Vec<_>>();
    let query_positions = derive_query_positions(
        receipt_commitment,
        &layer_roots,
        params,
        codeword_len,
        query_count,
    );
    query_positions
        .into_iter()
        .map(|mut position| {
            let mut rounds = Vec::with_capacity(layers.len().saturating_sub(1));
            for layer in &layers[..layers.len().saturating_sub(1)] {
                let half = layer.values.len() / 2;
                let pair_index = position % half;
                let left_index = pair_index;
                let right_index = pair_index + half;
                rounds.push(RoundQueryProof {
                    left_value: layer.values[left_index].as_canonical_u64(),
                    right_value: layer.values[right_index].as_canonical_u64(),
                    left_siblings: layer.tree.path(left_index),
                    right_siblings: layer.tree.path(right_index),
                });
                position = pair_index;
            }
            let final_layer = layers.last().expect("at least one fold layer");
            QueryProof {
                rounds,
                final_value: final_layer.values[position].as_canonical_u64(),
                final_siblings: final_layer.tree.path(position),
            }
        })
        .collect()
}

fn derive_round_challenge(
    receipt_commitment: [u8; 48],
    layer_root: [u8; 48],
    round: u32,
) -> Goldilocks {
    let mut material = Vec::with_capacity(ARC_CHALLENGE_DOMAIN.len() + 48 + 48 + 4);
    material.extend_from_slice(ARC_CHALLENGE_DOMAIN);
    material.extend_from_slice(&receipt_commitment);
    material.extend_from_slice(&layer_root);
    material.extend_from_slice(&round.to_le_bytes());
    let digest = blake3_384(&material);
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&digest[..8]);
    let challenge = Goldilocks::new(u64::from_le_bytes(limb));
    if challenge == Goldilocks::ZERO {
        Goldilocks::ONE
    } else {
        challenge
    }
}

fn derive_query_positions(
    receipt_commitment: [u8; 48],
    layer_roots: &[[u8; 48]],
    params: &ReceiptArcWhirParams,
    codeword_len: usize,
    query_count: usize,
) -> Vec<usize> {
    let mut out = Vec::with_capacity(query_count);
    let mut counter = 0u32;
    while out.len() < query_count {
        let mut material =
            Vec::with_capacity(QUERY_SEED_DOMAIN.len() + 48 + 4 + 3 + (layer_roots.len() * 48) + 4);
        material.extend_from_slice(QUERY_SEED_DOMAIN);
        material.extend_from_slice(&receipt_commitment);
        material.extend_from_slice(&(layer_roots.len() as u32).to_le_bytes());
        for root in layer_roots {
            material.extend_from_slice(root);
        }
        material.extend_from_slice(&(codeword_len as u32).to_le_bytes());
        material.push(params.log_blowup);
        material.push(params.query_count);
        material.push(params.folding_rounds);
        material.extend_from_slice(&counter.to_le_bytes());
        let digest = blake3_384(&material);
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&digest[..8]);
        let position = (u64::from_le_bytes(limb) % codeword_len as u64) as usize;
        if !out.contains(&position) {
            out.push(position);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

fn verify_merkle_path(
    layer_index: u32,
    mut index: usize,
    value: Goldilocks,
    siblings: &[[u8; 48]],
    expected_root: [u8; 48],
) -> Result<()> {
    let mut hash = codeword_leaf_hash(layer_index, index as u32, value.as_canonical_u64());
    for sibling in siblings {
        hash = if index % 2 == 0 {
            codeword_node_hash(layer_index, &hash, sibling)
        } else {
            codeword_node_hash(layer_index, sibling, &hash)
        };
        index /= 2;
    }
    ensure!(
        hash == expected_root,
        "receipt-arc-whir merkle path mismatch for layer {layer_index}"
    );
    Ok(())
}

fn encode_receipt_residual_artifact(artifact: &ReceiptResidualArtifact) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        2 + 48 + 4 + 4 + 4 + artifact.arc_bytes.len() + artifact.whir_bytes.len(),
    );
    bytes.extend_from_slice(&artifact.version.to_le_bytes());
    bytes.extend_from_slice(&artifact.receipt_commitment);
    bytes.extend_from_slice(&artifact.codeword_len.to_le_bytes());
    bytes.extend_from_slice(&(artifact.arc_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(artifact.whir_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&artifact.arc_bytes);
    bytes.extend_from_slice(&artifact.whir_bytes);
    bytes
}

fn decode_receipt_residual_artifact(bytes: &[u8]) -> Result<ReceiptResidualArtifact> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor, "receipt-arc-whir artifact")?;
    ensure!(
        version == RECEIPT_ARC_WHIR_ARTIFACT_VERSION,
        "unsupported receipt-arc-whir artifact version {version}"
    );
    let receipt_commitment = read_array::<48>(bytes, &mut cursor, "receipt-arc-whir artifact")?;
    let codeword_len = read_u32(bytes, &mut cursor, "receipt-arc-whir artifact")?;
    let arc_len = read_u32(bytes, &mut cursor, "receipt-arc-whir artifact")? as usize;
    let whir_len = read_u32(bytes, &mut cursor, "receipt-arc-whir artifact")? as usize;
    let arc_bytes = read_bytes(bytes, &mut cursor, arc_len, "receipt-arc-whir artifact")?;
    let whir_bytes = read_bytes(bytes, &mut cursor, whir_len, "receipt-arc-whir artifact")?;
    ensure!(
        cursor == bytes.len(),
        "receipt-arc-whir artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(ReceiptResidualArtifact {
        version,
        receipt_commitment,
        codeword_len,
        arc_bytes,
        whir_bytes,
    })
}

fn encode_arc_bytes(arc: &ArcResidual) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(arc.layer_roots.len() * 48);
    for root in &arc.layer_roots {
        bytes.extend_from_slice(root);
    }
    bytes
}

fn decode_arc_bytes(bytes: &[u8], rounds: usize) -> Result<ArcResidual> {
    let expected_len = (rounds + 1) * 48;
    ensure!(
        bytes.len() == expected_len,
        "receipt-arc-whir arc bytes length {} did not match expected {}",
        bytes.len(),
        expected_len
    );
    let mut cursor = 0usize;
    let mut layer_roots = Vec::with_capacity(rounds + 1);
    for _ in 0..=rounds {
        layer_roots.push(read_array::<48>(
            bytes,
            &mut cursor,
            "receipt-arc-whir arc bytes",
        )?);
    }
    Ok(ArcResidual { layer_roots })
}

fn encode_whir_bytes(query_proofs: &[QueryProof], codeword_len: usize, rounds: usize) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(query_proofs.len() * query_proof_bytes_per_query(codeword_len, rounds));
    for query_proof in query_proofs {
        let mut layer_len = codeword_len;
        for round in &query_proof.rounds {
            bytes.extend_from_slice(&round.left_value.to_le_bytes());
            bytes.extend_from_slice(&round.right_value.to_le_bytes());
            for sibling in &round.left_siblings {
                bytes.extend_from_slice(sibling);
            }
            for sibling in &round.right_siblings {
                bytes.extend_from_slice(sibling);
            }
            layer_len /= 2;
        }
        debug_assert_eq!(
            query_proof.final_siblings.len(),
            layer_depth(layer_len),
            "final query proof sibling depth mismatch"
        );
        bytes.extend_from_slice(&query_proof.final_value.to_le_bytes());
        for sibling in &query_proof.final_siblings {
            bytes.extend_from_slice(sibling);
        }
    }
    bytes
}

fn decode_whir_bytes(
    bytes: &[u8],
    codeword_len: usize,
    query_count: usize,
    rounds: usize,
) -> Result<Vec<QueryProof>> {
    let expected_len = query_count * query_proof_bytes_per_query(codeword_len, rounds);
    ensure!(
        bytes.len() == expected_len,
        "receipt-arc-whir whir bytes length {} did not match expected {}",
        bytes.len(),
        expected_len
    );

    let mut cursor = 0usize;
    let mut proofs = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        let mut layer_len = codeword_len;
        let mut round_proofs = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let depth = layer_depth(layer_len);
            let left_value = u64::from_le_bytes(read_array::<8>(
                bytes,
                &mut cursor,
                "receipt-arc-whir whir bytes",
            )?);
            let right_value = u64::from_le_bytes(read_array::<8>(
                bytes,
                &mut cursor,
                "receipt-arc-whir whir bytes",
            )?);
            let left_siblings = (0..depth)
                .map(|_| read_array::<48>(bytes, &mut cursor, "receipt-arc-whir whir bytes"))
                .collect::<Result<Vec<_>>>()?;
            let right_siblings = (0..depth)
                .map(|_| read_array::<48>(bytes, &mut cursor, "receipt-arc-whir whir bytes"))
                .collect::<Result<Vec<_>>>()?;
            round_proofs.push(RoundQueryProof {
                left_value,
                right_value,
                left_siblings,
                right_siblings,
            });
            layer_len /= 2;
        }
        let final_depth = layer_depth(layer_len);
        let final_value = u64::from_le_bytes(read_array::<8>(
            bytes,
            &mut cursor,
            "receipt-arc-whir whir bytes",
        )?);
        let final_siblings = (0..final_depth)
            .map(|_| read_array::<48>(bytes, &mut cursor, "receipt-arc-whir whir bytes"))
            .collect::<Result<Vec<_>>>()?;
        proofs.push(QueryProof {
            rounds: round_proofs,
            final_value,
            final_siblings,
        });
    }

    ensure!(
        cursor == bytes.len(),
        "receipt-arc-whir whir bytes had {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(proofs)
}

fn query_proof_bytes_per_query(codeword_len: usize, rounds: usize) -> usize {
    let mut layer_len = codeword_len;
    let mut total = 0usize;
    for _ in 0..rounds {
        let depth = layer_depth(layer_len);
        total += 8 + 8 + (depth * 48 * 2);
        layer_len /= 2;
    }
    total + 8 + (layer_depth(layer_len) * 48)
}

fn layer_depth(layer_len: usize) -> usize {
    debug_assert!(layer_len.is_power_of_two());
    layer_len.trailing_zeros() as usize
}

fn codeword_leaf_hash(layer_index: u32, index: u32, value: u64) -> [u8; 48] {
    let mut material = Vec::with_capacity(CODEWORD_LEAF_DOMAIN.len() + 4 + 4 + 8);
    material.extend_from_slice(CODEWORD_LEAF_DOMAIN);
    material.extend_from_slice(&layer_index.to_le_bytes());
    material.extend_from_slice(&index.to_le_bytes());
    material.extend_from_slice(&value.to_le_bytes());
    blake3_384(&material)
}

fn codeword_node_hash(layer_index: u32, left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    let mut material = Vec::with_capacity(CODEWORD_NODE_DOMAIN.len() + 4 + 96);
    material.extend_from_slice(CODEWORD_NODE_DOMAIN);
    material.extend_from_slice(&layer_index.to_le_bytes());
    material.extend_from_slice(left);
    material.extend_from_slice(right);
    blake3_384(&material)
}

fn max_receipt_arc_whir_artifact_bytes_with_params(
    row_count: usize,
    params: &ReceiptArcWhirParams,
) -> usize {
    let Ok(codeword_len) = codeword_len(row_count.max(1), params.log_blowup) else {
        return usize::MAX;
    };
    let rounds = effective_folding_rounds(codeword_len, params.folding_rounds);
    let arc_len = (rounds + 1) * 48;
    let whir_len = effective_query_count(codeword_len, params.query_count)
        * query_proof_bytes_per_query(codeword_len, rounds);
    2 + 48 + 4 + 4 + 4 + arc_len + whir_len
}

fn read_u16(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor, context)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor, context)?))
}

fn read_bytes(bytes: &[u8], cursor: &mut usize, len: usize, context: &str) -> Result<Vec<u8>> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= len,
        "{context} ended early while reading {len} bytes"
    );
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<[u8; N]> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= N,
        "{context} ended early while reading {N} bytes"
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(seed: u8) -> ReceiptRow {
        ReceiptRow {
            statement_hash: [seed; 48],
            proof_digest: [seed.wrapping_add(1); 48],
            public_inputs_digest: [seed.wrapping_add(2); 48],
            verifier_profile: [seed.wrapping_add(3); 48],
        }
    }

    fn sample_rows() -> Vec<ReceiptRow> {
        vec![
            sample_row(11),
            sample_row(22),
            sample_row(33),
            sample_row(44),
        ]
    }

    fn sample_rows_with_len(len: usize) -> Vec<ReceiptRow> {
        (0..len)
            .map(|index| sample_row(index as u8))
            .collect::<Vec<_>>()
    }

    #[test]
    fn receipt_arc_whir_accepts_canonical_rows() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let report = verify_receipt_arc_whir(&rows, &artifact, &params).expect("verify rows");
        assert_eq!(report.row_count, rows.len());
        assert_eq!(report.artifact_bytes, artifact.len());
        assert!(artifact.len() <= max_receipt_arc_whir_artifact_bytes(rows.len()));
    }

    #[test]
    fn receipt_arc_whir_rejects_reordered_rows() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let mut reordered = rows.clone();
        reordered.swap(0, 1);
        let err = verify_receipt_arc_whir(&reordered, &artifact, &params)
            .expect_err("reordered rows must fail");
        assert!(err.to_string().contains("receipt commitment mismatch"));
    }

    #[test]
    fn receipt_arc_whir_query_count_does_not_wrap_at_large_codewords() {
        assert_eq!(effective_query_count(256, 8), 8);
        assert_eq!(effective_query_count(512, 8), 8);
    }

    #[test]
    fn receipt_arc_whir_accepts_large_codeword_rows() {
        let rows = sample_rows_with_len(64);
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove large rows");
        let report = verify_receipt_arc_whir(&rows, &artifact, &params).expect("verify large rows");
        assert_eq!(report.row_count, rows.len());
        assert_eq!(report.artifact_bytes, artifact.len());
    }

    #[test]
    fn receipt_arc_whir_rejects_mutated_receipt_metadata() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let mut mutated = rows.clone();
        mutated[1].verifier_profile[0] ^= 0x5A;
        let err = verify_receipt_arc_whir(&mutated, &artifact, &params)
            .expect_err("mutated row must fail");
        assert!(err.to_string().contains("receipt commitment mismatch"));
    }

    #[test]
    fn receipt_arc_whir_rejects_tampered_query_value() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let mut decoded = decode_receipt_residual_artifact(&artifact).expect("decode artifact");
        decoded.whir_bytes[0] ^= 0x01;
        let tampered = encode_receipt_residual_artifact(&decoded);
        let err = verify_receipt_arc_whir(&rows, &tampered, &params)
            .expect_err("tampered query value must fail");
        assert!(
            err.to_string().contains("opened value mismatch")
                || err.to_string().contains("merkle path mismatch")
        );
    }

    #[test]
    fn receipt_arc_whir_rejects_tampered_arc_root() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let mut decoded = decode_receipt_residual_artifact(&artifact).expect("decode artifact");
        decoded.arc_bytes[0] ^= 0x01;
        let tampered = encode_receipt_residual_artifact(&decoded);
        let err = verify_receipt_arc_whir(&rows, &tampered, &params)
            .expect_err("tampered layer root must fail");
        assert!(err.to_string().contains("merkle path mismatch"));
    }

    #[test]
    fn receipt_arc_whir_rejects_truncated_artifact() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        let truncated = artifact[..artifact.len() - 1].to_vec();
        let err = verify_receipt_arc_whir(&rows, &truncated, &params)
            .expect_err("truncated artifact must fail");
        assert!(err.to_string().contains("ended early") || err.to_string().contains("length"));
    }

    #[test]
    fn receipt_arc_whir_rejects_oversized_artifact() {
        let rows = sample_rows();
        let params = ReceiptArcWhirParams::default();
        let mut artifact = prove_receipt_arc_whir(&rows, &params).expect("prove rows");
        artifact.push(0u8);
        let err = verify_receipt_arc_whir(&rows, &artifact, &params)
            .expect_err("oversized artifact must fail");
        assert!(err.to_string().contains("exceeds"));
    }
}
