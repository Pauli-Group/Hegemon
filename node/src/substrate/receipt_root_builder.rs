use crate::substrate::proof_boundary::pallet_receipt_from_consensus;
use consensus::backend_interface::{
    native_receipt_root_build_cache_stats, native_receipt_root_mini_root_size,
    NativeReceiptRootBuildCacheStats,
};
use consensus::proof_interface::build_experimental_native_receipt_root_artifact;
use crypto::hashes::blake3_384;
use parking_lot::Mutex as ParkingMutex;
use rayon::ThreadPoolBuilder;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct MiniRootCacheKey([u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptRootMiniRootPlan {
    pub(crate) leaf_start: u32,
    pub(crate) leaf_count: u32,
    pub(crate) cache_key: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptRootWorkPlan {
    pub(crate) leaf_count: usize,
    pub(crate) mini_root_size: usize,
    pub(crate) mini_root_count: usize,
    pub(crate) chunk_internal_fold_nodes: usize,
    pub(crate) upper_tree_fold_nodes: usize,
    pub(crate) upper_tree_level_widths: Vec<usize>,
    pub(crate) mini_roots: Vec<ReceiptRootMiniRootPlan>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeReceiptRootBuildCacheDelta {
    pub(crate) leaf_cache_hits: u64,
    pub(crate) leaf_cache_misses: u64,
    pub(crate) chunk_cache_hits: u64,
    pub(crate) chunk_cache_misses: u64,
}

impl NativeReceiptRootBuildCacheDelta {
    fn between(
        before: NativeReceiptRootBuildCacheStats,
        after: NativeReceiptRootBuildCacheStats,
    ) -> Self {
        Self {
            leaf_cache_hits: after.leaf_cache_hits.saturating_sub(before.leaf_cache_hits),
            leaf_cache_misses: after
                .leaf_cache_misses
                .saturating_sub(before.leaf_cache_misses),
            chunk_cache_hits: after
                .chunk_cache_hits
                .saturating_sub(before.chunk_cache_hits),
            chunk_cache_misses: after
                .chunk_cache_misses
                .saturating_sub(before.chunk_cache_misses),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeReceiptRootBuildReport {
    pub(crate) workers: usize,
    pub(crate) leaf_count: usize,
    pub(crate) mini_root_size: usize,
    pub(crate) mini_root_count: usize,
    pub(crate) chunk_internal_fold_nodes: usize,
    pub(crate) upper_tree_fold_nodes: usize,
    pub(crate) upper_tree_level_widths: Vec<usize>,
    pub(crate) cache_delta: NativeReceiptRootBuildCacheDelta,
}

static RECEIPT_ROOT_THREAD_POOLS: once_cell::sync::Lazy<
    ParkingMutex<HashMap<usize, Arc<rayon::ThreadPool>>>,
> = once_cell::sync::Lazy::new(|| ParkingMutex::new(HashMap::new()));

pub(crate) fn load_receipt_root_workers(default_workers: usize) -> usize {
    std::env::var("HEGEMON_RECEIPT_ROOT_WORKERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| {
            std::env::var("HEGEMON_AGG_STAGE_LOCAL_PARALLELISM")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .or_else(|| {
            std::env::var("HEGEMON_PROVER_WORKERS")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
        })
        .unwrap_or(default_workers.max(1))
        .clamp(1, 256)
}

fn receipt_root_thread_pool(workers: usize) -> Result<Arc<rayon::ThreadPool>, String> {
    let workers = workers.max(1);
    let mut guard = RECEIPT_ROOT_THREAD_POOLS.lock();
    if let Some(pool) = guard.get(&workers) {
        return Ok(Arc::clone(pool));
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(move |index| format!("hegemon-receipt-root-{workers}-{index}"))
        .build()
        .map_err(|error| {
            format!("failed to build receipt-root worker pool ({workers} threads): {error}")
        })?;
    let pool = Arc::new(pool);
    guard.insert(workers, Arc::clone(&pool));
    Ok(pool)
}

fn receipt_root_upper_tree_level_widths(mini_root_count: usize) -> Vec<usize> {
    let mut widths = Vec::new();
    let mut current = mini_root_count.max(1);
    loop {
        widths.push(current);
        if current == 1 {
            break;
        }
        current = current.div_ceil(2);
    }
    widths
}

fn make_receipt_root_mini_root_cache_key(child_hashes: &[[u8; 48]]) -> MiniRootCacheKey {
    let mut material = Vec::with_capacity(64 + (child_hashes.len() * 48));
    material.extend_from_slice(b"hegemon.native-receipt-root.chunk.v1");
    material.extend_from_slice(&consensus::experimental_native_receipt_root_params_fingerprint());
    material.extend_from_slice(&(child_hashes.len() as u32).to_le_bytes());
    for child_hash in child_hashes {
        material.extend_from_slice(child_hash);
    }
    MiniRootCacheKey(blake3_384(&material))
}

pub(crate) fn build_receipt_root_work_plan(
    tx_artifacts: &[consensus::TxValidityArtifact],
) -> Result<ReceiptRootWorkPlan, String> {
    if tx_artifacts.is_empty() {
        return Err("candidate tx set has no receipt-root proof material".to_string());
    }

    let mini_root_size = native_receipt_root_mini_root_size();
    let artifact_hashes = tx_artifacts
        .iter()
        .map(|artifact| {
            artifact
                .proof
                .as_ref()
                .map(|proof| blake3_384(&proof.artifact_bytes))
                .ok_or_else(|| {
                    "native receipt_root requires proof envelopes for all txs".to_string()
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mini_roots = artifact_hashes
        .chunks(mini_root_size)
        .enumerate()
        .map(|(index, chunk)| ReceiptRootMiniRootPlan {
            leaf_start: (index * mini_root_size) as u32,
            leaf_count: chunk.len() as u32,
            cache_key: make_receipt_root_mini_root_cache_key(chunk).0,
        })
        .collect::<Vec<_>>();

    let chunk_internal_fold_nodes = tx_artifacts
        .chunks(mini_root_size)
        .map(|chunk| chunk.len().saturating_sub(1))
        .sum();
    let mini_root_count = mini_roots.len().max(1);

    Ok(ReceiptRootWorkPlan {
        leaf_count: tx_artifacts.len(),
        mini_root_size,
        mini_root_count: mini_roots.len(),
        chunk_internal_fold_nodes,
        upper_tree_fold_nodes: mini_root_count.saturating_sub(1),
        upper_tree_level_widths: receipt_root_upper_tree_level_widths(mini_root_count),
        mini_roots,
    })
}

pub(crate) fn pallet_receipt_root_payload_from_consensus_receipts(
    receipts: &[consensus::types::TxValidityReceipt],
    built: consensus::ExperimentalReceiptRootArtifact,
) -> pallet_shielded_pool::types::ReceiptRootProofPayload {
    pallet_shielded_pool::types::ReceiptRootProofPayload {
        root_proof: pallet_shielded_pool::types::StarkProof::from_bytes(built.artifact_bytes),
        metadata: pallet_shielded_pool::types::ReceiptRootMetadata {
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
        receipts: receipts
            .iter()
            .cloned()
            .map(pallet_receipt_from_consensus)
            .collect(),
    }
}

#[cfg(test)]
pub(crate) fn build_receipt_root_proof_from_materials(
    tx_artifacts: &[consensus::TxValidityArtifact],
) -> Result<pallet_shielded_pool::types::ReceiptRootProofPayload, String> {
    if tx_artifacts.is_empty() {
        return Err("candidate tx set has no receipt-root proof material".to_string());
    }
    if tx_artifacts.iter().any(|artifact| {
        artifact
            .proof
            .as_ref()
            .map(|proof| {
                proof.kind != consensus::ProofArtifactKind::TxLeaf
                    || proof.verifier_profile
                        != consensus::experimental_native_tx_leaf_verifier_profile()
            })
            .unwrap_or(true)
    }) {
        return Err("receipt-root requires native tx-leaf artifacts for every tx".to_string());
    }
    let built = build_experimental_native_receipt_root_artifact(tx_artifacts)
        .map_err(|err| format!("native receipt-root artifact generation failed: {err}"))?;
    let receipts = tx_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    Ok(pallet_receipt_root_payload_from_consensus_receipts(
        &receipts, built,
    ))
}

pub(crate) fn build_receipt_root_proof_from_materials_with_plan(
    tx_artifacts: &[consensus::TxValidityArtifact],
    work_plan: &ReceiptRootWorkPlan,
    default_workers: usize,
) -> Result<
    (
        pallet_shielded_pool::types::ReceiptRootProofPayload,
        NativeReceiptRootBuildReport,
    ),
    String,
> {
    let workers = load_receipt_root_workers(default_workers);
    let before = native_receipt_root_build_cache_stats();
    let built = if workers <= 1 {
        build_experimental_native_receipt_root_artifact(tx_artifacts)
    } else {
        receipt_root_thread_pool(workers)?
            .install(|| build_experimental_native_receipt_root_artifact(tx_artifacts))
    }
    .map_err(|err| format!("native receipt-root artifact generation failed: {err}"))?;
    let after = native_receipt_root_build_cache_stats();
    let receipts = tx_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();

    Ok((
        pallet_receipt_root_payload_from_consensus_receipts(&receipts, built),
        NativeReceiptRootBuildReport {
            workers,
            leaf_count: work_plan.leaf_count,
            mini_root_size: work_plan.mini_root_size,
            mini_root_count: work_plan.mini_root_count,
            chunk_internal_fold_nodes: work_plan.chunk_internal_fold_nodes,
            upper_tree_fold_nodes: work_plan.upper_tree_fold_nodes,
            upper_tree_level_widths: work_plan.upper_tree_level_widths.clone(),
            cache_delta: NativeReceiptRootBuildCacheDelta::between(before, after),
        },
    ))
}
