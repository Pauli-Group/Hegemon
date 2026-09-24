//! Sled persistence, genesis, startup reload, and state publication.

use super::*;

const SLED_DEFAULT_TREE_NAME: &[u8] = b"__sled__default";
pub(crate) const NATIVE_PERSISTENT_TREE_NAMES: [&[u8]; 12] = [
    b"meta",
    b"block_hash_by_height",
    b"block_meta_by_hash",
    b"mempool_actions",
    b"shielded_nullifiers",
    b"shielded_commitments",
    b"bridge_inbound_messages",
    b"shielded_ciphertext_index",
    b"shielded_ciphertexts_by_index",
    b"da_pending_ciphertexts",
    b"da_pending_proofs",
    poseidon2_v8_state::POSEIDON2_V8_STATE_TREE_NAME,
];

/// SCALE collection prefixes are at most five bytes for the bounded u32
/// lengths used by `Vec<Vec<u8>>`.  The limit admits every consensus-valid
/// action body and rejects a corrupt length before allocating its vectors.
pub(crate) const MAX_NATIVE_ACTION_BODY_V3_BYTES: usize =
    MAX_NATIVE_BLOCK_ACTION_BYTES + 5 * (MAX_NATIVE_BLOCK_ACTIONS + 1);

/// Immutable, self-authenticating result of one exact V3 full-body encoding.
/// Its fields are private to this storage codec module, so persistence and
/// transport can share the bytes but cannot forge or mutate the provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedNativeBlockBodyV3 {
    hash: BodyHash48,
    len: u64,
    bytes: Arc<[u8]>,
    /// Exact SCALE binding of every fixed metadata field, including the
    /// action count and action root.
    meta_fixed_binding: Vec<u8>,
}

impl EncodedNativeBlockBodyV3 {
    pub(crate) const fn hash(&self) -> BodyHash48 {
        self.hash
    }

    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
}

fn decode_canonical_compact_u32(cursor: &mut &[u8], label: &str) -> Result<u32> {
    let bytes = *cursor;
    let first = *bytes
        .first()
        .ok_or_else(|| anyhow!("decode {label} failed: empty compact integer"))?;
    let (value, consumed) = match first & 0b11 {
        0 => (u32::from(first >> 2), 1),
        1 => {
            let encoded = bytes.get(..2).ok_or_else(|| {
                anyhow!("decode {label} failed: truncated two-byte compact integer")
            })?;
            let value = u16::from_le_bytes([encoded[0], encoded[1]]) as u32 >> 2;
            if value < 1 << 6 {
                return Err(anyhow!("{label} is not canonical SCALE compact-u32"));
            }
            (value, 2)
        }
        2 => {
            let encoded = bytes.get(..4).ok_or_else(|| {
                anyhow!("decode {label} failed: truncated four-byte compact integer")
            })?;
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) >> 2;
            if value < 1 << 14 {
                return Err(anyhow!("{label} is not canonical SCALE compact-u32"));
            }
            (value, 4)
        }
        _ => {
            if first != 0b11 {
                return Err(anyhow!(
                    "decode {label} failed: compact-u32 length exceeds four bytes"
                ));
            }
            let encoded = bytes.get(1..5).ok_or_else(|| {
                anyhow!("decode {label} failed: truncated five-byte compact integer")
            })?;
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
            if value <= 0x3fff_ffff {
                return Err(anyhow!("{label} is not canonical SCALE compact-u32"));
            }
            (value, 5)
        }
    };
    *cursor = &bytes[consumed..];
    Ok(value)
}

fn preflight_native_action_body_v3(bytes: &[u8]) -> Result<usize> {
    if bytes.len() > MAX_NATIVE_ACTION_BODY_V3_BYTES {
        return Err(anyhow!(
            "native V3 action body bytes exceed limit: {} > {}",
            bytes.len(),
            MAX_NATIVE_ACTION_BODY_V3_BYTES
        ));
    }
    let mut cursor = bytes;
    let action_count = decode_canonical_compact_u32(&mut cursor, "native V3 action count")?;
    let action_count = usize::try_from(action_count)
        .map_err(|_| anyhow!("native V3 action count exceeds usize"))?;
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "native V3 action body count exceeds limit: {} > {}",
            action_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }

    let mut payload_bytes = 0usize;
    for index in 0..action_count {
        let payload_len = decode_canonical_compact_u32(&mut cursor, "native V3 action length")?;
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| anyhow!("native V3 action {index} length exceeds usize"))?;
        if payload_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "native V3 action {index} payload exceeds limit: {} > {}",
                payload_len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        payload_bytes = payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("native V3 action payload byte total overflow"))?;
        if payload_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "native V3 action payload bytes exceed aggregate limit: {} > {}",
                payload_bytes,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
        let Some(remaining) = cursor.get(payload_len..) else {
            return Err(anyhow!(
                "native V3 action {index} payload is truncated: declared {}, remaining {}",
                payload_len,
                cursor.len()
            ));
        };
        cursor = remaining;
    }
    if !cursor.is_empty() {
        return Err(anyhow!(
            "native V3 action body has {} trailing bytes",
            cursor.len()
        ));
    }
    Ok(action_count)
}

/// Return one exact action payload from the canonical SCALE action-body blob
/// without allocating or decoding any sibling payload. The full outer/inner
/// framing is still scanned and canonicality/budgets/trailing bytes are
/// checked before the borrowed slice is released.
pub(crate) fn native_action_body_v3_action_at(
    encoded_body: &[u8],
    action_index: u32,
) -> Result<&[u8]> {
    if encoded_body.len() > MAX_NATIVE_ACTION_BODY_V3_BYTES {
        return Err(anyhow!(
            "native V3 action body bytes exceed limit: {} > {}",
            encoded_body.len(),
            MAX_NATIVE_ACTION_BODY_V3_BYTES
        ));
    }
    let mut cursor = encoded_body;
    let action_count = decode_canonical_compact_u32(&mut cursor, "native V3 action count")?;
    let action_count_usize = usize::try_from(action_count)
        .map_err(|_| anyhow!("native V3 action count exceeds usize"))?;
    if action_count_usize > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "native V3 action body count exceeds limit: {} > {}",
            action_count_usize,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }
    if action_index >= action_count {
        return Err(anyhow!(
            "native V3 action index {} is out of range for {} actions",
            action_index,
            action_count
        ));
    }

    let mut selected = None;
    let mut payload_bytes = 0usize;
    for index in 0..action_count_usize {
        let payload_len = decode_canonical_compact_u32(&mut cursor, "native V3 action length")?;
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| anyhow!("native V3 action {index} length exceeds usize"))?;
        if payload_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "native V3 action {index} payload exceeds limit: {} > {}",
                payload_len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        payload_bytes = payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("native V3 action payload byte total overflow"))?;
        if payload_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "native V3 action payload bytes exceed aggregate limit: {} > {}",
                payload_bytes,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
        let payload = cursor.get(..payload_len).ok_or_else(|| {
            anyhow!(
                "native V3 action {index} payload is truncated: declared {}, remaining {}",
                payload_len,
                cursor.len()
            )
        })?;
        if u32::try_from(index).ok() == Some(action_index) {
            selected = Some(payload);
        }
        cursor = &cursor[payload_len..];
    }
    if !cursor.is_empty() {
        return Err(anyhow!(
            "native V3 action body has {} trailing bytes",
            cursor.len()
        ));
    }
    selected.ok_or_else(|| anyhow!("native V3 action index disappeared during exact preflight"))
}

/// Encode and bind the internal action-body blob once.  The hash input is the
/// exact canonical SCALE encoding of `Vec<Vec<u8>>`; the generic hash384 frame
/// commits its byte length, so callers must not add a competing length frame.
pub(crate) fn encode_native_action_body_v3(
    action_bytes: &[Vec<u8>],
) -> Result<EncodedNativeActionBodyV3> {
    let action_count = u32::try_from(action_bytes.len())
        .map_err(|_| anyhow!("native V3 action count exceeds u32"))?;
    validate_block_action_byte_budget(
        action_count,
        action_bytes.len(),
        action_bytes.iter().map(Vec::len),
    )?;
    let bytes = action_bytes.encode();
    preflight_native_action_body_v3(&bytes)?;
    let len = u64::try_from(bytes.len())
        .map_err(|_| anyhow!("native V3 action body length exceeds u64"))?;
    let hash = ActionBodyHash48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_ACTION_BODY_V3,
        [bytes.as_slice()],
    ));
    Ok(EncodedNativeActionBodyV3 { hash, len, bytes })
}

pub(crate) fn decode_native_action_body_v3(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let expected_count = preflight_native_action_body_v3(bytes)?;
    let decoded = decode_scale_exact::<Vec<Vec<u8>>>(bytes, "native V3 action body")?;
    if decoded.len() != expected_count {
        return Err(anyhow!(
            "native V3 action body preflight/decode count mismatch"
        ));
    }
    Ok(decoded)
}

pub(crate) fn native_block_body_hash_v3(canonical_body: &[u8]) -> BodyHash48 {
    BodyHash48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_BLOCK_BODY_V3,
        [canonical_body],
    ))
}

/// Fixed-int bincode offsets in `NativeBlockMetaV3`. Every V3 digest/root is a
/// fixed tuple, including the domain-typed 48-byte V3 state root.
pub(crate) const NATIVE_BLOCK_META_V3_STATE_ROOT_OFFSET: usize = 32 + 48 + 8 + 48 + 48;
pub(crate) const NATIVE_BLOCK_META_V3_ACTION_BYTES_OFFSET: usize = 32
    + 48
    + 8
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 48
    + 4
    + 48
    + 8
    + 8
    + 4
    + 32
    + 48
    + 64
    + 16
    + 4;

/// Fixed bytes after the V3 action vector: DA root plus exact tier metadata.
const NATIVE_BLOCK_META_V3_AFTER_ACTION_BYTES: usize = 48 + 4 + 4 + 8 + 4;

fn validate_native_block_meta_v3_bincode_budget(bytes: &[u8], label: &str) -> Result<()> {
    if bytes.len() > MAX_NATIVE_BLOCK_META_BYTES {
        return Err(anyhow!(
            "{label} bytes exceed native V3 block metadata limit: {} > {}",
            bytes.len(),
            MAX_NATIVE_BLOCK_META_BYTES
        ));
    }
    let Some(action_count) =
        read_bincode_fixint_len(bytes, NATIVE_BLOCK_META_V3_ACTION_BYTES_OFFSET)?
    else {
        return Ok(());
    };
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "{label} action byte count exceeds limit before V3 bincode decode: {} > {}",
            action_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }
    let mut cursor = NATIVE_BLOCK_META_V3_ACTION_BYTES_OFFSET
        .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
        .ok_or_else(|| anyhow!("{label} V3 bincode action cursor overflow"))?;
    let mut total_action_bytes = 0usize;
    for index in 0..action_count {
        let Some(action_len) = read_bincode_fixint_len(bytes, cursor)? else {
            return Ok(());
        };
        if action_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "{label} action payload {index} exceeds limit before V3 bincode decode: {} > {}",
                action_len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        total_action_bytes = total_action_bytes
            .checked_add(action_len)
            .ok_or_else(|| anyhow!("{label} V3 action byte total overflow"))?;
        if total_action_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "{label} action bytes exceed aggregate limit before V3 bincode decode: {} > {}",
                total_action_bytes,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
        cursor = cursor
            .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
            .and_then(|next| next.checked_add(action_len))
            .ok_or_else(|| anyhow!("{label} V3 bincode action cursor overflow"))?;
        if cursor > bytes.len() {
            return Ok(());
        }
    }
    let expected_len = cursor
        .checked_add(NATIVE_BLOCK_META_V3_AFTER_ACTION_BYTES)
        .ok_or_else(|| anyhow!("{label} V3 bincode body length overflow"))?;
    if expected_len != bytes.len() {
        return Err(anyhow!(
            "{label} V3 bincode structural length mismatch: expected {}, got {}",
            expected_len,
            bytes.len()
        ));
    }
    Ok(())
}

fn serialize_native_block_meta_v3(meta: &NativeBlockMetaV3) -> Result<Vec<u8>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(meta)
        .context("encode canonical native V3 block body")
}

/// Bounded, fixed-int, trailing-byte-rejecting decoder for the full V3
/// network/canonical body. Fixed-width scalar fields have a unique bincode
/// representation; the structural preflight fixes every vector boundary; and
/// action-root validation below exact-reencodes each SCALE action. Therefore
/// canonicality is established without allocating and serializing a second
/// potentially 67 MiB full body. No default bincode decoder is permitted on
/// this consensus surface.
pub(crate) fn decode_native_block_meta_v3_exact(
    bytes: &[u8],
    label: &str,
) -> Result<NativeBlockMetaV3> {
    validate_native_block_meta_v3_bincode_budget(bytes, label)?;
    let meta: NativeBlockMetaV3 = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_NATIVE_BLOCK_META_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|err| anyhow!("decode {label} failed: {err}"))?;
    if usize::try_from(meta.tx_count).ok() != Some(meta.action_bytes.len()) {
        return Err(anyhow!(
            "native V3 metadata action count mismatch: declared {}, bodies {}",
            meta.tx_count,
            meta.action_bytes.len()
        ));
    }
    if native_action_root_v3_from_action_bytes(&meta.action_bytes)? != meta.extrinsics_root {
        return Err(anyhow!("native V3 metadata action root mismatch"));
    }
    Ok(meta)
}

/// Decode and seal an exact received V3 body while computing its BodyHash48
/// exactly once. The returned immutable token can be shared with transport
/// and passed into persistence preparation without a rehash or reserialization.
pub(crate) fn decode_and_bind_native_block_body_v3_exact(
    bytes: Arc<[u8]>,
    expected_hash: BodyHash48,
    label: &str,
) -> Result<(NativeBlockMetaV3, EncodedNativeBlockBodyV3)> {
    let actual_hash = native_block_body_hash_v3(&bytes);
    if actual_hash != expected_hash {
        return Err(anyhow!("{label} BodyHash48 mismatch"));
    }
    let meta = decode_native_block_meta_v3_exact(&bytes, label)?;
    let len = u64::try_from(bytes.len()).map_err(|_| anyhow!("{label} length exceeds u64"))?;
    let meta_fixed_binding = native_block_meta_fixed_binding_v3(&meta);
    let encoded = EncodedNativeBlockBodyV3 {
        hash: actual_hash,
        len,
        bytes,
        meta_fixed_binding,
    };
    Ok((meta, encoded))
}

/// Allocation-bounded identity for all V3 metadata outside `action_bytes`.
/// `extrinsics_root` and `tx_count` bind the omitted vector after its exact
/// canonical actions have been decoded and their embedded ActionId48 values
/// recomputed. Keeping this token beside the once-serialized full body lets a
/// persistence worker prove it is storing the same metadata without encoding
/// the full body again.
#[derive(Encode)]
struct NativeBlockMetaFixedBindingV3<'a> {
    schema_version: u16,
    chain_id: &'a [u8; 32],
    rules_hash: &'a RulesHash48,
    height: u64,
    hash: &'a BlockId48,
    parent_hash: &'a BlockId48,
    state_root: &'a StateRoot48,
    kernel_root: &'a KernelRoot48,
    nullifier_root: &'a NullifierAccumulatorRoot48,
    proof_commitment: &'a ProofCommitment48,
    extrinsics_root: &'a ActionRoot48,
    tx_statements_commitment: &'a TransactionStatementsCommitment48,
    version_commitment: &'a VersionCommitment48,
    fee_commitment: &'a FeeCommitment48,
    message_root: &'a BridgeMessageRoot48,
    message_count: u32,
    header_mmr_root: &'a HeaderMmrHash48,
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: &'a [u8; 32],
    work_hash: &'a WorkHash48,
    cumulative_work: &'a Work64,
    supply_digest: u128,
    tx_count: u32,
    da_root: &'a DaRoot48,
    da_chunk_size: u32,
    da_sample_count: u32,
    da_blob_len: u64,
    da_chunk_count: u32,
}

fn native_block_meta_fixed_binding_v3(meta: &NativeBlockMetaV3) -> Vec<u8> {
    NativeBlockMetaFixedBindingV3 {
        schema_version: NATIVE_STORED_BLOCK_META_SCHEMA_V3,
        chain_id: &meta.chain_id,
        rules_hash: &meta.rules_hash,
        height: meta.height,
        hash: &meta.hash,
        parent_hash: &meta.parent_hash,
        state_root: &meta.state_root,
        kernel_root: &meta.kernel_root,
        nullifier_root: &meta.nullifier_root,
        proof_commitment: &meta.proof_commitment,
        extrinsics_root: &meta.extrinsics_root,
        tx_statements_commitment: &meta.tx_statements_commitment,
        version_commitment: &meta.version_commitment,
        fee_commitment: &meta.fee_commitment,
        message_root: &meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: &meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        nonce: &meta.nonce,
        work_hash: &meta.work_hash,
        cumulative_work: &meta.cumulative_work,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        da_root: &meta.da_root,
        da_chunk_size: meta.da_chunk_size,
        da_sample_count: meta.da_sample_count,
        da_blob_len: meta.da_blob_len,
        da_chunk_count: meta.da_chunk_count,
    }
    .encode()
}

/// Serialize and hash a full self-contained V3 network/canonical body once.
/// The action root is recomputed from the exact embedded action bytes before
/// either the body bytes or their locator identity can be published.
pub(crate) fn encode_native_block_body_v3(
    meta: &NativeBlockMetaV3,
) -> Result<EncodedNativeBlockBodyV3> {
    if usize::try_from(meta.tx_count).ok() != Some(meta.action_bytes.len()) {
        return Err(anyhow!(
            "native V3 metadata action count mismatch: declared {}, bodies {}",
            meta.tx_count,
            meta.action_bytes.len()
        ));
    }
    let action_root = native_action_root_v3_from_action_bytes(&meta.action_bytes)?;
    if action_root != meta.extrinsics_root {
        return Err(anyhow!("native V3 metadata action root mismatch"));
    }
    let bytes = serialize_native_block_meta_v3(meta)?;
    if bytes.len() > MAX_NATIVE_BLOCK_META_BYTES {
        return Err(anyhow!(
            "canonical native V3 block body exceeds limit: {} > {}",
            bytes.len(),
            MAX_NATIVE_BLOCK_META_BYTES
        ));
    }
    let len = u64::try_from(bytes.len())
        .map_err(|_| anyhow!("native V3 block body length exceeds u64"))?;
    let hash = native_block_body_hash_v3(&bytes);
    let meta_fixed_binding = native_block_meta_fixed_binding_v3(meta);
    Ok(EncodedNativeBlockBodyV3 {
        hash,
        len,
        bytes: Arc::from(bytes),
        meta_fixed_binding,
    })
}

/// Build the slim sled row and content-addressed action blob from a canonical
/// full body that was already serialized during transport or verification.
///
/// The full bytes are length/hash checked, every fixed metadata field is
/// compared against the provenance captured by the canonical encoder, and the
/// exact action count/root is independently recomputed from `meta`. Therefore
/// this path cannot pair a body with different metadata while avoiding a
/// second full-body serialization.
pub(crate) fn store_native_block_meta_v3_with_canonical_body(
    meta: &NativeBlockMetaV3,
    canonical_body: &EncodedNativeBlockBodyV3,
) -> Result<(StoredNativeBlockMetaV3, EncodedNativeActionBodyV3)> {
    let actual_body_len = u64::try_from(canonical_body.bytes.len())
        .map_err(|_| anyhow!("canonical native V3 block body length exceeds u64"))?;
    if canonical_body.bytes.len() > MAX_NATIVE_BLOCK_META_BYTES {
        return Err(anyhow!(
            "canonical native V3 block body exceeds limit: {} > {}",
            canonical_body.bytes.len(),
            MAX_NATIVE_BLOCK_META_BYTES
        ));
    }
    if actual_body_len != canonical_body.len {
        return Err(anyhow!(
            "canonical native V3 block body length binding mismatch: expected {}, got {}",
            canonical_body.len,
            actual_body_len
        ));
    }
    // `canonical_body` is sealed by this module: its hash, length, immutable
    // bytes, and fixed-field provenance were created in the same one-pass
    // encoder. Rehashing here would add a redundant 67 MiB pass.
    if native_block_meta_fixed_binding_v3(meta) != canonical_body.meta_fixed_binding {
        return Err(anyhow!(
            "canonical native V3 block body fixed metadata binding mismatch"
        ));
    }
    if usize::try_from(meta.tx_count).ok() != Some(meta.action_bytes.len()) {
        return Err(anyhow!(
            "native V3 metadata action count mismatch: declared {}, bodies {}",
            meta.tx_count,
            meta.action_bytes.len()
        ));
    }
    let action_root = native_action_root_v3_from_action_bytes(&meta.action_bytes)?;
    if action_root != meta.extrinsics_root {
        return Err(anyhow!("native V3 metadata action root mismatch"));
    }
    let body = encode_native_action_body_v3(&meta.action_bytes)?;
    let stored = StoredNativeBlockMetaV3 {
        schema_version: NATIVE_STORED_BLOCK_META_SCHEMA_V3,
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        hash: meta.hash,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: meta.proof_commitment,
        extrinsics_root: meta.extrinsics_root,
        tx_statements_commitment: meta.tx_statements_commitment,
        version_commitment: meta.version_commitment,
        fee_commitment: meta.fee_commitment,
        message_root: meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        nonce: meta.nonce,
        work_hash: meta.work_hash,
        cumulative_work: meta.cumulative_work,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        body_hash: canonical_body.hash,
        body_len: canonical_body.len,
        action_body_hash: body.hash,
        action_body_len: body.len,
        da_root: meta.da_root,
        da_chunk_size: meta.da_chunk_size,
        da_sample_count: meta.da_sample_count,
        da_blob_len: meta.da_blob_len,
        da_chunk_count: meta.da_chunk_count,
    };
    Ok((stored, body))
}

pub(crate) fn store_native_block_meta_v3(
    meta: &NativeBlockMetaV3,
) -> Result<(
    StoredNativeBlockMetaV3,
    EncodedNativeActionBodyV3,
    EncodedNativeBlockBodyV3,
)> {
    let canonical_body = encode_native_block_body_v3(meta)?;
    let (stored, body) = store_native_block_meta_v3_with_canonical_body(meta, &canonical_body)?;
    Ok((stored, body, canonical_body))
}

pub(crate) fn restore_native_block_meta_v3(
    stored: &StoredNativeBlockMetaV3,
    action_body: &[u8],
) -> Result<NativeBlockMetaV3> {
    if stored.schema_version != NATIVE_STORED_BLOCK_META_SCHEMA_V3 {
        return Err(anyhow!(
            "stored native block metadata schema mismatch: expected {}, got {}",
            NATIVE_STORED_BLOCK_META_SCHEMA_V3,
            stored.schema_version
        ));
    }
    let body_len = u64::try_from(action_body.len())
        .map_err(|_| anyhow!("stored native V3 action body length exceeds u64"))?;
    if body_len != stored.action_body_len {
        return Err(anyhow!(
            "stored native V3 action body length mismatch: expected {}, got {}",
            stored.action_body_len,
            body_len
        ));
    }
    let body_hash = ActionBodyHash48::new(crypto::hash384::blake2b_384_domain_hash(
        crypto::hash384::domains::NATIVE_ACTION_BODY_V3,
        [action_body],
    ));
    if body_hash != stored.action_body_hash {
        return Err(anyhow!("stored native V3 action body hash mismatch"));
    }
    let action_bytes = decode_native_action_body_v3(action_body)?;
    if usize::try_from(stored.tx_count).ok() != Some(action_bytes.len()) {
        return Err(anyhow!(
            "stored native V3 metadata action count mismatch: declared {}, bodies {}",
            stored.tx_count,
            action_bytes.len()
        ));
    }
    let action_root = native_action_root_v3_from_action_bytes(&action_bytes)?;
    if action_root != stored.extrinsics_root {
        return Err(anyhow!("stored native V3 metadata action root mismatch"));
    }
    let meta = NativeBlockMetaV3 {
        chain_id: stored.chain_id,
        rules_hash: stored.rules_hash,
        height: stored.height,
        hash: stored.hash,
        parent_hash: stored.parent_hash,
        state_root: stored.state_root,
        kernel_root: stored.kernel_root,
        nullifier_root: stored.nullifier_root,
        proof_commitment: stored.proof_commitment,
        extrinsics_root: stored.extrinsics_root,
        tx_statements_commitment: stored.tx_statements_commitment,
        version_commitment: stored.version_commitment,
        fee_commitment: stored.fee_commitment,
        message_root: stored.message_root,
        message_count: stored.message_count,
        header_mmr_root: stored.header_mmr_root,
        header_mmr_len: stored.header_mmr_len,
        timestamp_ms: stored.timestamp_ms,
        pow_bits: stored.pow_bits,
        nonce: stored.nonce,
        work_hash: stored.work_hash,
        cumulative_work: stored.cumulative_work,
        supply_digest: stored.supply_digest,
        tx_count: stored.tx_count,
        action_bytes,
        da_root: stored.da_root,
        da_chunk_size: stored.da_chunk_size,
        da_sample_count: stored.da_sample_count,
        da_blob_len: stored.da_blob_len,
        da_chunk_count: stored.da_chunk_count,
    };
    let canonical_body = encode_native_block_body_v3(&meta)?;
    if canonical_body.len != stored.body_len {
        return Err(anyhow!(
            "stored native V3 full body length mismatch: expected {}, got {}",
            stored.body_len,
            canonical_body.len
        ));
    }
    if canonical_body.hash != stored.body_hash {
        return Err(anyhow!("stored native V3 full body hash mismatch"));
    }
    Ok(meta)
}

/// Classify the sled namespace before any `open_tree` call can create a name.
/// A fresh database has no named trees and an empty default tree. An existing
/// database must have the exact current native namespace, so a legacy, partial,
/// renamed, or unknown tree cannot be mutated during a failed V2 startup.
pub(crate) fn validate_native_tree_namespace_before_open(db: &sled::Db) -> Result<()> {
    let observed = db
        .tree_names()
        .into_iter()
        .filter(|name| name.as_ref() != SLED_DEFAULT_TREE_NAME)
        .map(|name| name.to_vec())
        .collect::<BTreeSet<_>>();
    if observed.is_empty() && db.is_empty() {
        return Ok(());
    }
    if !db.is_empty() {
        return Err(anyhow!(
            "native sled default tree is nonempty; V2 requires an untouched fresh database or the exact native tree namespace"
        ));
    }

    let expected = NATIVE_PERSISTENT_TREE_NAMES
        .iter()
        .map(|name| name.to_vec())
        .collect::<BTreeSet<_>>();
    let pre_v8_expected = expected
        .iter()
        .filter(|name| name.as_slice() != poseidon2_v8_state::POSEIDON2_V8_STATE_TREE_NAME)
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed == expected || observed == pre_v8_expected {
        return Ok(());
    }
    let missing = expected
        .difference(&observed)
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect::<Vec<_>>();
    let unexpected = observed
        .difference(&expected)
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect::<Vec<_>>();
    Err(anyhow!(
        "native sled tree namespace is partial, legacy, or unknown; refusing to create trees before V2 startup validation (missing={missing:?}, unexpected={unexpected:?})"
    ))
}

pub(crate) fn publish_mined_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

pub(crate) fn publish_reorganized_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

pub(crate) fn publish_staged_ciphertexts(
    state: &mut NativeState,
    staged_ciphertexts: BTreeMap<String, u32>,
) {
    state.staged_ciphertexts = staged_ciphertexts;
}

pub(crate) fn publish_staged_proofs(
    state: &mut NativeState,
    staged_proofs: BTreeMap<String, Vec<u8>>,
) {
    state.staged_proofs = staged_proofs;
}

pub(crate) fn collect_tree_keys(tree: &sled::Tree, tree_name: &str) -> Result<Vec<Vec<u8>>> {
    tree.iter()
        .keys()
        .map(|key| {
            key.map(|key| key.to_vec())
                .with_context(|| format!("collect {tree_name} tree keys"))
        })
        .collect()
}

pub(crate) fn load_best_or_genesis(
    db: &sled::Db,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<NativeBlockMeta> {
    if let Some(bytes) = meta_tree.get(META_BEST_KEY)? {
        let best = bincode_deserialize_native_block_meta_exact(&bytes, "native best metadata")?;
        if best.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
            let profile = if best.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1 {
                "legacy V1"
            } else {
                "unknown"
            };
            return Err(anyhow!(
                "stored native database uses {profile} consensus rules; adaptive-DA V2 requires a fresh genesis and a new base path (stored rules_hash={}, active rules_hash={})",
                hex32(&best.rules_hash),
                hex32(&HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE),
            ));
        }
        return Ok(best);
    }

    // A missing best pointer is not proof of a fresh database.  Refuse to
    // bootstrap V2 over partial/legacy canonical rows; doing so would mutate
    // evidence before startup validation can diagnose the required reset.
    let mut nonempty_tree = (!db.is_empty()).then_some("__sled__default".to_string());
    if nonempty_tree.is_none() {
        for name in db.tree_names() {
            if name.as_ref() == SLED_DEFAULT_TREE_NAME {
                continue;
            }
            let tree = db.open_tree(&name)?;
            if !tree.is_empty() {
                nonempty_tree = Some(String::from_utf8_lossy(&name).into_owned());
                break;
            }
        }
    }
    if nonempty_tree.is_some()
        || !meta_tree.is_empty()
        || !height_tree.is_empty()
        || !block_tree.is_empty()
    {
        return Err(anyhow!(
            "stored native database has canonical rows but no best pointer; V2 fresh genesis requires every persistent tree to be empty and a new base path (nonempty tree: {})",
            nonempty_tree.as_deref().unwrap_or("core canonical tree")
        ));
    }

    let genesis = genesis_meta(pow_bits)?;
    let genesis_record = bincode::serialize(&genesis)?;
    let empty_nullifier_accumulator = NullifierAccumulator::new()
        .encode()
        .map_err(|err| anyhow!("encode genesis nullifier accumulator failed: {err}"))?;
    let genesis_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
        (meta_tree, height_tree, block_tree).transaction(|(meta_tree, height_tree, block_tree)| {
            block_tree.insert(genesis.hash.to_vec(), genesis_record.clone())?;
            height_tree.insert(height_key(0).to_vec(), genesis.hash.to_vec())?;
            meta_tree.insert(META_BEST_KEY.to_vec(), genesis_record.clone())?;
            meta_tree.insert(META_GENESIS_KEY.to_vec(), genesis.hash.to_vec())?;
            meta_tree.insert(
                META_NULLIFIER_ACCUMULATOR_KEY.to_vec(),
                empty_nullifier_accumulator.clone(),
            )?;
            Ok(())
        });
    genesis_result.map_err(|err| anyhow!("atomic native genesis bootstrap failed: {err}"))?;
    flush_native_db_durability_barrier(
        db,
        "native genesis bootstrap",
        NativeStorageDurabilityOperation::GenesisBootstrap,
    )?;
    Ok(genesis)
}

pub(crate) struct ValidatedCanonicalChainSnapshot {
    blocks: Vec<NativeBlockMeta>,
    block_index_reload_admission: NativeBlockIndexReloadAdmission,
}

impl ValidatedCanonicalChainSnapshot {
    pub(crate) fn blocks(&self) -> &[NativeBlockMeta] {
        &self.blocks
    }

    pub(crate) const fn block_index_reload_admission(&self) -> NativeBlockIndexReloadAdmission {
        self.block_index_reload_admission
    }
}

pub(crate) fn load_header_mmr_peaks_for_best(
    canonical_chain: &ValidatedCanonicalChainSnapshot,
    best: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let chain = canonical_chain.blocks();
    if chain.last() != Some(best) {
        return Err(anyhow!(
            "native header MMR peak state best metadata mismatch"
        ));
    }
    let chain_len = u64::try_from(chain.len())
        .map_err(|_| anyhow!("native header MMR peak state chain length overflow"))?;
    if chain_len != header_mmr_leaf_count_after_best(best)? {
        return Err(anyhow!(
            "native header MMR peak state chain length mismatch"
        ));
    }
    let hashes = chain.iter().map(|meta| meta.hash).collect::<Vec<_>>();
    Ok(header_mmr_peaks_from_hashes(&hashes))
}

pub(crate) fn header_mmr_leaf_count_after_best(best: &NativeBlockMeta) -> Result<u64> {
    best.height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native header MMR leaf count overflow"))
}

pub(crate) fn header_mmr_commitment_after_best(
    best: &NativeBlockMeta,
    peaks: &[Hash32],
) -> Result<(Hash32, u64)> {
    let leaf_count = header_mmr_leaf_count_after_best(best)?;
    let expected_peak_count = leaf_count.count_ones() as usize;
    if peaks.len() != expected_peak_count {
        return Err(anyhow!(
            "native header MMR peak state shape mismatch after height {}: expected {} peaks for {} leaves, got {}",
            best.height,
            expected_peak_count,
            leaf_count,
            peaks.len()
        ));
    }
    Ok((header_mmr_root_from_peaks(leaf_count, peaks), leaf_count))
}

pub(crate) fn append_header_mmr_peak_state(
    state: &NativeState,
    meta: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let leaf_count = header_mmr_leaf_count_after_best(&state.best)?;
    header_mmr_append_peaks(leaf_count, &state.header_mmr_peaks, meta.hash)
        .map_err(|err| anyhow!("native header MMR peak append failed: {err:?}"))
}

pub(crate) fn genesis_meta(pow_bits: u32) -> Result<NativeBlockMeta> {
    let state_root = CommitmentTreeState::default().root();
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let nullifier_root = NullifierAccumulator::new().root();
    let timestamp_ms = NATIVE_GENESIS_TIMESTAMP_MS;
    let extrinsics_root = empty_extrinsics_root(0);
    let message_root = empty_bridge_message_root();
    let da_params = native_da_params_for_transactions(&[])?;
    let da_encoding = consensus::encode_da_blob(&[], da_params)
        .map_err(|err| anyhow!("encode native genesis DA blob failed: {err}"))?;
    let da_blob_len = u64::try_from(da_encoding.data_len())
        .map_err(|_| anyhow!("native genesis DA blob length exceeds u64"))?;
    let da_chunk_count = u32::try_from(da_encoding.chunks().len())
        .map_err(|_| anyhow!("native genesis DA chunk count exceeds u32"))?;
    let hash = hash32_with_parts(&[
        b"hegemon-native-genesis-v2",
        &HEGEMON_CHAIN_ID_V1,
        &HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        &pow_bits.to_le_bytes(),
    ]);

    Ok(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        height: 0,
        hash,
        parent_hash: [0u8; 32],
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count: 0,
        header_mmr_root: empty_header_mmr_root(),
        header_mmr_len: 0,
        timestamp_ms,
        pow_bits,
        nonce: [0u8; 32],
        work_hash: hash,
        cumulative_work: [0u8; 48],
        supply_digest: 0,
        tx_count: 0,
        action_bytes: Vec::new(),
        da_root: da_encoding.root(),
        da_chunk_size: da_params.chunk_size,
        da_sample_count: da_params.sample_count,
        da_blob_len,
        da_chunk_count,
    })
}

#[cfg(test)]
pub(crate) fn persist_block(
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    meta: &NativeBlockMeta,
) -> Result<()> {
    persist_block_record(block_tree, meta)?;
    height_tree.insert(height_key(meta.height), meta.hash.as_slice())?;
    meta_tree.insert(META_BEST_KEY, bincode::serialize(meta)?)?;
    meta_tree.flush()?;
    height_tree.flush()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn persist_block_record(block_tree: &sled::Tree, meta: &NativeBlockMeta) -> Result<()> {
    block_tree.insert(meta.hash.as_slice(), bincode::serialize(meta)?)?;
    block_tree.flush()?;
    Ok(())
}

pub(crate) fn load_block_meta_by_hash(
    block_tree: &sled::Tree,
    hash: &[u8; 32],
) -> Result<Option<NativeBlockMeta>> {
    match block_tree.get(hash)? {
        Some(bytes) => {
            let meta =
                bincode_deserialize_native_block_meta_exact(&bytes, "native block metadata")?;
            if meta.hash != *hash {
                return Err(anyhow!(
                    "stored native block hash mismatch: key={} embedded={}",
                    hex32(hash),
                    hex32(&meta.hash)
                ));
            }
            if meta.hash != meta.work_hash {
                return Err(anyhow!(
                    "stored native block work-hash mismatch: hash={} work_hash={}",
                    hex32(&meta.hash),
                    hex32(&meta.work_hash)
                ));
            }
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeChainLoadError {
    #[error("missing native block {hash_hex}")]
    MissingAncestor { hash_hex: String },
    #[error(transparent)]
    Corrupt(#[from] anyhow::Error),
}

pub(crate) fn load_chain_to_hash(
    block_tree: &sled::Tree,
    hash: [u8; 32],
) -> std::result::Result<Vec<NativeBlockMeta>, NativeChainLoadError> {
    #[cfg(test)]
    record_native_chain_load_call();
    let mut chain = Vec::new();
    let mut cursor = hash;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor) {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "stored native block parent cycle at {}",
                hex32(&cursor)
            )));
        }
        let meta = load_block_meta_by_hash(block_tree, &cursor)
            .map_err(NativeChainLoadError::Corrupt)?
            .ok_or_else(|| NativeChainLoadError::MissingAncestor {
                hash_hex: hex32(&cursor),
            })?;
        #[cfg(test)]
        record_native_chain_load_decoded_meta();
        if meta.hash != cursor {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "stored native block hash mismatch: key={} embedded={}",
                hex32(&cursor),
                hex32(&meta.hash)
            )));
        }
        let parent = meta.parent_hash;
        let is_genesis = meta.height == 0;
        chain.push(meta);
        if is_genesis {
            break;
        }
        cursor = parent;
    }
    chain.reverse();
    Ok(chain)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeChainLoadMetrics {
    pub(crate) calls: u64,
    pub(crate) decoded_metas: u64,
}

#[cfg(test)]
std::thread_local! {
    static NATIVE_CHAIN_LOAD_METRICS: std::cell::Cell<NativeChainLoadMetrics> =
        const { std::cell::Cell::new(NativeChainLoadMetrics {
            calls: 0,
            decoded_metas: 0,
        }) };
}

#[cfg(test)]
pub(crate) fn reset_native_chain_load_metrics() {
    NATIVE_CHAIN_LOAD_METRICS.with(|metrics| metrics.set(Default::default()));
}

#[cfg(test)]
pub(crate) fn native_chain_load_metrics() -> NativeChainLoadMetrics {
    NATIVE_CHAIN_LOAD_METRICS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn update_native_chain_load_metrics(update: impl FnOnce(&mut NativeChainLoadMetrics)) {
    NATIVE_CHAIN_LOAD_METRICS.with(|metrics| {
        let mut observed = metrics.get();
        update(&mut observed);
        metrics.set(observed);
    });
}

#[cfg(test)]
fn record_native_chain_load_call() {
    update_native_chain_load_metrics(|metrics| {
        metrics.calls = metrics.calls.saturating_add(1);
    });
}

#[cfg(test)]
fn record_native_chain_load_decoded_meta() {
    update_native_chain_load_metrics(|metrics| {
        metrics.decoded_metas = metrics.decoded_metas.saturating_add(1);
    });
}

pub(crate) fn evaluate_native_block_index_reload(
    input: NativeBlockIndexReloadInput,
) -> Result<NativeBlockIndexReloadAdmission, NativeBlockIndexReloadRejection> {
    if !input.chain_reconstructed {
        Err(NativeBlockIndexReloadRejection::ChainReconstructionFailed)
    } else if !input.chain_nonempty {
        Err(NativeBlockIndexReloadRejection::ChainEmpty)
    } else if !input.genesis_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMismatch)
    } else if !input.best_metadata_matches_chain {
        Err(NativeBlockIndexReloadRejection::BestMetadataMismatch)
    } else if !input.canonical_heights_contiguous {
        Err(NativeBlockIndexReloadRejection::CanonicalHeightMismatch)
    } else if !input.canonical_chain_ids_match {
        Err(NativeBlockIndexReloadRejection::ChainIdMismatch)
    } else if !input.canonical_rules_hashes_match {
        Err(NativeBlockIndexReloadRejection::RulesHashMismatch)
    } else if !input.canonical_hashes_match_work_hashes {
        Err(NativeBlockIndexReloadRejection::HashWorkHashMismatch)
    } else if !input.canonical_parent_hashes_contiguous {
        Err(NativeBlockIndexReloadRejection::ParentHashMismatch)
    } else if !input.height_keys_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightKey)
    } else if !input.height_values_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightValue)
    } else if !input.no_extra_height_indexes {
        Err(NativeBlockIndexReloadRejection::ExtraHeightIndex)
    } else if !input.height_index_heights_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightIndexMismatch)
    } else if !input.height_index_hashes_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightHashMismatch)
    } else if !input.all_canonical_heights_indexed {
        Err(NativeBlockIndexReloadRejection::MissingHeightIndex)
    } else if !input.genesis_marker_present {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: true,
        })
    } else if !input.genesis_marker_length_valid {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength)
    } else if !input.genesis_marker_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerMismatch)
    } else {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: false,
        })
    }
}

pub(crate) fn native_block_index_reload_error(
    rejection: NativeBlockIndexReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeBlockIndexReloadRejection::ChainReconstructionFailed => anyhow!(
            "stored native canonical chain reconstruction failed ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainEmpty => anyhow!(
            "stored native canonical chain is empty ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMismatch => {
            anyhow!("stored native genesis mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::BestMetadataMismatch => {
            anyhow!("stored best metadata mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::CanonicalHeightMismatch => anyhow!(
            "stored canonical block height mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainIdMismatch => anyhow!(
            "stored canonical block chain id mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::RulesHashMismatch => anyhow!(
            "stored canonical block rules hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HashWorkHashMismatch => anyhow!(
            "stored canonical block hash/work-hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ParentHashMismatch => anyhow!(
            "stored canonical block parent mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightKey => anyhow!(
            "stored canonical height key has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightValue => anyhow!(
            "stored canonical height value has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ExtraHeightIndex => anyhow!(
            "stored extra canonical height index ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightIndexMismatch => anyhow!(
            "stored canonical height index mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightHashMismatch => anyhow!(
            "stored canonical height hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MissingHeightIndex => anyhow!(
            "stored canonical height index missing ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength => anyhow!(
            "stored native genesis marker has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerMismatch => anyhow!(
            "stored native genesis marker mismatch ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn evaluate_native_canonical_state_reload(
    input: NativeCanonicalStateReloadInput,
) -> Result<(), NativeCanonicalStateReloadRejection> {
    if !input.nullifier_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedNullifierKey)
    } else if !input.nullifier_markers_valid {
        Err(NativeCanonicalStateReloadRejection::InvalidNullifierMarker)
    } else if !input.commitment_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentKey)
    } else if !input.commitment_values_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentValue)
    } else if !input.commitment_indexes_contiguous {
        Err(NativeCanonicalStateReloadRejection::CommitmentIndexGap)
    } else if !input.commitment_tree_rebuilt {
        Err(NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed)
    } else if !input.commitment_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::CommitmentRootMismatch)
    } else if !input.nullifier_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::NullifierRootMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_canonical_state_reload_error(
    rejection: NativeCanonicalStateReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeCanonicalStateReloadRejection::MalformedNullifierKey => anyhow!(
            "stored nullifier key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::InvalidNullifierMarker => {
            anyhow!("stored nullifier marker is invalid ({})", rejection.label())
        }
        NativeCanonicalStateReloadRejection::MalformedCommitmentKey => anyhow!(
            "stored commitment key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::MalformedCommitmentValue => anyhow!(
            "stored commitment value has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentIndexGap => anyhow!(
            "stored commitment index is not contiguous ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed => anyhow!(
            "rebuild native commitment tree failed ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentRootMismatch => anyhow!(
            "stored commitment tree root mismatch ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::NullifierRootMismatch => {
            anyhow!("stored nullifier root mismatch ({})", rejection.label())
        }
    }
}

pub(crate) fn evaluate_native_bridge_replay_reload(
    input: NativeBridgeReplayReloadInput,
) -> Result<(), NativeBridgeReplayReloadRejection> {
    if !input.replay_keys_well_formed {
        Err(NativeBridgeReplayReloadRejection::MalformedReplayKey)
    } else if !input.replay_markers_valid {
        Err(NativeBridgeReplayReloadRejection::InvalidReplayMarker)
    } else if !input.canonical_replay_keys_unique {
        Err(NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate)
    } else if !input.no_missing_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::MissingConsumedReplayKey)
    } else if !input.no_extra_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey)
    } else {
        Ok(())
    }
}

pub(crate) fn native_bridge_replay_reload_error(
    rejection: NativeBridgeReplayReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeReplayReloadRejection::MalformedReplayKey => anyhow!(
            "stored bridge replay key has invalid length ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::InvalidReplayMarker => anyhow!(
            "stored bridge replay marker is invalid ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => anyhow!(
            "canonical chain contains duplicate inbound bridge replay key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::MissingConsumedReplayKey => anyhow!(
            "stored bridge replay set missing consumed key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => anyhow!(
            "stored bridge replay set has extra consumed key ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn evaluate_native_pending_action_reload(
    input: NativePendingActionReloadInput,
) -> Result<(), NativePendingActionReloadRejection> {
    if !input.key_well_formed {
        Err(NativePendingActionReloadRejection::MalformedActionKey)
    } else if !input.embedded_hash_matches_key {
        Err(NativePendingActionReloadRejection::KeyHashMismatch)
    } else if !input.recomputed_hash_matches_embedded {
        Err(NativePendingActionReloadRejection::RecomputedHashMismatch)
    } else if !input.action_hash_unique {
        Err(NativePendingActionReloadRejection::DuplicatePendingAction)
    } else {
        Ok(())
    }
}

pub(crate) fn native_pending_action_reload_error(
    rejection: NativePendingActionReloadRejection,
    hash: Option<ActionId48>,
    action: Option<&PendingAction>,
) -> anyhow::Error {
    match rejection {
        NativePendingActionReloadRejection::MalformedActionKey => anyhow!(
            "stored pending action key has invalid length ({})",
            rejection.label()
        ),
        NativePendingActionReloadRejection::KeyHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            let action = action.expect("pending action exists after decode");
            anyhow!(
                "stored pending action key/hash mismatch: key={} embedded={} ({})",
                hex48(hash.as_bytes()),
                hex48(action.tx_hash.as_bytes()),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::RecomputedHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "stored pending action hash mismatch: key={} ({})",
                hex48(hash.as_bytes()),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::DuplicatePendingAction => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "duplicate stored pending action {} ({})",
                hex48(hash.as_bytes()),
                rejection.label()
            )
        }
    }
}

pub(crate) fn evaluate_native_staged_ciphertext_reload(
    input: NativeStagedCiphertextReloadInput,
) -> Result<(), NativeStagedCiphertextReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedCiphertextReloadRejection::MalformedCiphertextKey)
    } else if !input.ciphertext_within_limit {
        Err(NativeStagedCiphertextReloadRejection::OversizedCiphertext)
    } else if !input.ciphertext_hash_matches_key {
        Err(NativeStagedCiphertextReloadRejection::CiphertextHashMismatch)
    } else if !input.capacity_available {
        Err(NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_staged_proof_reload(
    input: NativeStagedProofReloadInput,
) -> Result<(), NativeStagedProofReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedProofReloadRejection::MalformedProofKey)
    } else if !input.proof_nonempty {
        Err(NativeStagedProofReloadRejection::EmptyProof)
    } else if !input.proof_within_limit {
        Err(NativeStagedProofReloadRejection::OversizedProof)
    } else if !input.capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofCapacityReached)
    } else if !input.byte_capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofByteCapacityReached)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeStagedProofReloadRejection::ProofBindingHashMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_loaded_block_indexes(
    best: &NativeBlockMeta,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<ValidatedCanonicalChainSnapshot> {
    let expected_genesis = genesis_meta(pow_bits)?;
    let chain = load_chain_to_hash(block_tree, best.hash)?;

    let chain_nonempty = !chain.is_empty();
    let genesis_matches_expected = chain
        .first()
        .map(|genesis| genesis == &expected_genesis)
        .unwrap_or(false);
    let best_metadata_matches_chain = chain
        .last()
        .map(|canonical_best| canonical_best == best)
        .unwrap_or(false);
    let mut canonical_heights_contiguous = true;
    let mut canonical_chain_ids_match = true;
    let mut canonical_rules_hashes_match = true;
    let mut canonical_hashes_match_work_hashes = true;
    let mut canonical_parent_hashes_contiguous = true;
    for (index, meta) in chain.iter().enumerate() {
        let expected_height =
            u64::try_from(index).map_err(|_| anyhow!("stored native chain height overflow"))?;
        if meta.height != expected_height {
            canonical_heights_contiguous = false;
        }
        if meta.chain_id != HEGEMON_CHAIN_ID_V1 {
            canonical_chain_ids_match = false;
        }
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
            canonical_rules_hashes_match = false;
        }
        if meta.hash != meta.work_hash {
            canonical_hashes_match_work_hashes = false;
        }
        if index > 0 {
            let parent = &chain[index - 1];
            if meta.parent_hash != parent.hash {
                canonical_parent_hashes_contiguous = false;
            }
        }
    }

    let mut height_keys_well_formed = true;
    let mut height_values_well_formed = true;
    let mut no_extra_height_indexes = true;
    let mut height_index_heights_match_chain = true;
    let mut height_index_hashes_match_chain = true;
    for item in height_tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            height_keys_well_formed = false;
            continue;
        }
        if value.len() != 32 {
            height_values_well_formed = false;
            continue;
        }
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(key.as_ref());
        let height = u64::from_be_bytes(height_bytes);
        let Some(meta) = usize::try_from(height)
            .ok()
            .and_then(|index| chain.get(index))
        else {
            no_extra_height_indexes = false;
            continue;
        };
        if height != meta.height {
            height_index_heights_match_chain = false;
        }
        if value.as_ref() != meta.hash.as_slice() {
            height_index_hashes_match_chain = false;
        }
    }

    let mut all_canonical_heights_indexed = true;
    for meta in &chain {
        match height_tree.get(height_key(meta.height))? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    height_values_well_formed = false;
                } else if bytes.as_ref() != meta.hash.as_slice() {
                    height_index_hashes_match_chain = false;
                }
            }
            None => {
                all_canonical_heights_indexed = false;
            }
        }
    }

    let genesis_marker = meta_tree.get(META_GENESIS_KEY)?;
    let genesis_marker_present = genesis_marker.is_some();
    let mut genesis_marker_length_valid = true;
    let mut genesis_marker_matches_expected = true;
    if let Some(bytes) = genesis_marker.as_ref() {
        genesis_marker_length_valid = bytes.len() == 32;
        genesis_marker_matches_expected =
            genesis_marker_length_valid && bytes.as_ref() == expected_genesis.hash.as_slice();
    }

    let admission = evaluate_native_block_index_reload(NativeBlockIndexReloadInput {
        chain_reconstructed: true,
        chain_nonempty,
        genesis_matches_expected,
        best_metadata_matches_chain,
        canonical_heights_contiguous,
        canonical_chain_ids_match,
        canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous,
        height_keys_well_formed,
        height_values_well_formed,
        no_extra_height_indexes,
        height_index_heights_match_chain,
        height_index_hashes_match_chain,
        all_canonical_heights_indexed,
        genesis_marker_present,
        genesis_marker_length_valid,
        genesis_marker_matches_expected,
    })
    .map_err(native_block_index_reload_error)?;

    for index in 0..chain.len() {
        let parent = if index == 0 {
            None
        } else {
            chain.get(index - 1)
        };
        let meta = &chain[index];
        let expected_pow_bits = if index == 0 {
            None
        } else {
            Some(native_expected_child_pow_bits_for_chain_index(
                &chain,
                index - 1,
                pow_bits,
            )?)
        };
        verify_native_block_meta_projection(parent, meta, expected_pow_bits).with_context(
            || {
                format!(
                    "validate stored canonical native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            },
        )?;
    }

    Ok(ValidatedCanonicalChainSnapshot {
        blocks: chain,
        block_index_reload_admission: admission,
    })
}

pub(crate) fn apply_native_block_index_reload_repairs(
    db: &sled::Db,
    meta_tree: &sled::Tree,
    pow_bits: u32,
    admission: NativeBlockIndexReloadAdmission,
) -> Result<()> {
    if !admission.repair_missing_genesis_marker {
        return Ok(());
    }
    let expected_genesis = genesis_meta(pow_bits)?;
    meta_tree.insert(META_GENESIS_KEY, expected_genesis.hash.as_slice())?;
    flush_native_db_durability_barrier(
        db,
        "native genesis marker repair",
        NativeStorageDurabilityOperation::GenesisMarkerRepair,
    )
}

pub(crate) fn load_staged_sizes(db: &sled::Db, tree: &sled::Tree) -> Result<BTreeMap<String, u32>> {
    load_staged_sizes_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_CIPHERTEXTS,
        MAX_CIPHERTEXT_BYTES,
    )
}

pub(crate) fn load_staged_sizes_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_ciphertext_bytes: usize,
) -> Result<BTreeMap<String, u32>> {
    let mut entries = BTreeMap::new();
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: key.len() == 48,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::MalformedCiphertextKey
            );
            warn!(
                key_len = key.len(),
                "dropping malformed staged ciphertext sidecar key during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let mut hash = [0u8; 48];
        hash.copy_from_slice(&key);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: value.len() <= max_ciphertext_bytes,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::OversizedCiphertext
            );
            warn!(
                hash = %hex48(&hash),
                size = value.len(),
                max = max_ciphertext_bytes,
                "dropping oversized staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let observed = ciphertext_hash_bytes(&value);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: observed == hash,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::CiphertextHashMismatch
            );
            warn!(
                key_hash = %hex48(&hash),
                observed_hash = %hex48(&observed),
                "dropping hash-mismatched staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let capacity_available = evaluate_native_ciphertext_sidecar_capacity_admission(
            NativeSidecarCapacityAdmissionInput {
                staged_count: entries.len(),
                max_staged_count,
                replaces_existing: false,
            },
        )
        .is_ok();
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached
            );
            warn!(
                hash = %hex48(&hash),
                max = max_staged_count,
                "dropping staged ciphertext sidecar beyond reload capacity"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let size = u32::try_from(value.len()).unwrap_or(u32::MAX);
        entries.insert(hex48(&hash), size);
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(
            db,
            "native startup staged ciphertext repair",
            NativeStorageDurabilityOperation::StartupStagedCiphertextRepair,
        )?;
    }
    Ok(entries)
}

pub(crate) fn load_staged_proofs(
    db: &sled::Db,
    tree: &sled::Tree,
) -> Result<BTreeMap<String, Vec<u8>>> {
    load_staged_proofs_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_PROOFS,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
}

pub(crate) fn load_staged_proofs_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_proof_bytes: usize,
    max_total_bytes: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    let mut total_bytes = 0usize;
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        let key_well_formed = key.len() == 64;
        let proof_nonempty = !value.is_empty();
        let proof_within_limit = value.len() <= max_proof_bytes;
        let capacity_available = entries.len() < max_staged_count;
        let next_total_bytes = total_bytes.saturating_add(value.len());
        let byte_capacity_available = next_total_bytes <= max_total_bytes;
        let mut binding_hash = [0u8; 64];
        if key_well_formed {
            binding_hash.copy_from_slice(&key);
        }
        let proof_binding_hash_matches_key = key_well_formed
            && proof_nonempty
            && proof_within_limit
            && capacity_available
            && byte_capacity_available
            && native_tx_leaf_artifact_binding_hash_matches_key(binding_hash, &value);
        if let Err(rejection) = evaluate_native_staged_proof_reload(NativeStagedProofReloadInput {
            key_well_formed,
            proof_nonempty,
            proof_within_limit,
            capacity_available,
            byte_capacity_available,
            proof_binding_hash_matches_key,
        }) {
            match rejection {
                NativeStagedProofReloadRejection::MalformedProofKey => warn!(
                    key_len = key.len(),
                    "dropping malformed staged proof sidecar key during reload"
                ),
                NativeStagedProofReloadRejection::EmptyProof => {
                    warn!("dropping empty staged proof sidecar during reload")
                }
                NativeStagedProofReloadRejection::OversizedProof => warn!(
                    proof_bytes = value.len(),
                    max = max_proof_bytes,
                    "dropping oversized staged proof sidecar during reload"
                ),
                NativeStagedProofReloadRejection::StagedProofCapacityReached => warn!(
                    max = max_staged_count,
                    "dropping staged proof sidecar beyond reload capacity"
                ),
                NativeStagedProofReloadRejection::StagedProofByteCapacityReached => warn!(
                    total_bytes = next_total_bytes,
                    max = max_total_bytes,
                    "dropping staged proof sidecar beyond reload byte capacity"
                ),
                NativeStagedProofReloadRejection::ProofBindingHashMismatch => warn!(
                    binding_hash = %hex64(&binding_hash),
                    "dropping binding-mismatched staged proof sidecar during reload"
                ),
            }
            stale_keys.push(key.to_vec());
            continue;
        }

        total_bytes = next_total_bytes;
        entries.insert(hex64(&binding_hash), value.to_vec());
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(
            db,
            "native startup staged proof repair",
            NativeStorageDurabilityOperation::StartupStagedProofRepair,
        )?;
    }
    Ok(entries)
}

pub(crate) fn load_pending_actions(
    tree: &sled::Tree,
) -> Result<BTreeMap<ActionId48, PendingAction>> {
    let mut actions = BTreeMap::new();
    let mut semantic_hashes = BTreeSet::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            return Err(native_pending_action_reload_error(
                evaluate_native_pending_action_reload(NativePendingActionReloadInput {
                    key_well_formed: false,
                    embedded_hash_matches_key: false,
                    recomputed_hash_matches_embedded: false,
                    action_hash_unique: false,
                })
                .expect_err("malformed pending action key must reject"),
                None,
                None,
            ));
        }
        let hash = ActionId48::try_from(key.as_ref())
            .map_err(|_| anyhow!("stored pending action key has invalid length"))?;
        let action = decode_pending_action_v3_exact(&value, "persisted pending action")?;
        validate_active_pending_action_canonicality(&action)?;
        if action.encode().as_slice() != value.as_ref() {
            return Err(anyhow!(
                "pending action {} has noncanonical SCALE encoding",
                hex48(hash.as_bytes())
            ));
        }
        validate_loaded_pending_action_hash(hash, &action, !actions.contains_key(&hash))?;
        if !semantic_hashes.insert(pending_action_semantic_hash(&action)) {
            return Err(anyhow!(
                "duplicate semantic stored pending action {}",
                hex48(hash.as_bytes())
            ));
        }
        actions.insert(hash, action);
    }
    Ok(actions)
}

pub(crate) fn validate_loaded_pending_action_hash(
    hash: ActionId48,
    action: &PendingAction,
    action_hash_unique: bool,
) -> Result<()> {
    validate_active_pending_action_canonicality(action)?;
    evaluate_native_pending_action_reload(NativePendingActionReloadInput {
        key_well_formed: true,
        embedded_hash_matches_key: action.tx_hash == hash,
        recomputed_hash_matches_embedded: action.tx_hash == pending_action_hash(action),
        action_hash_unique,
    })
    .map_err(|rejection| native_pending_action_reload_error(rejection, Some(hash), Some(action)))
}

pub(crate) fn build_validated_startup_state(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<ActionId48, PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: PersistentKeySet48,
    nullifier_accumulator: NullifierAccumulator,
    consumed_bridge_messages: PersistentKeySet48,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    _prune_persisted_coinbase_actions: bool,
) -> Result<NativeState> {
    build_validated_startup_state_with_limits(
        db,
        action_tree,
        best,
        header_mmr_peaks,
        pending_actions,
        commitment_tree,
        nullifiers,
        nullifier_accumulator,
        consumed_bridge_messages,
        staged_ciphertexts,
        staged_proofs,
        true,
        MAX_NATIVE_MEMPOOL_ACTIONS,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    )
}

pub(crate) fn build_validated_startup_state_with_limits(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<ActionId48, PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: PersistentKeySet48,
    nullifier_accumulator: NullifierAccumulator,
    consumed_bridge_messages: PersistentKeySet48,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    _prune_persisted_coinbase_actions: bool,
    max_pending_actions: usize,
    max_pending_action_bytes: usize,
) -> Result<NativeState> {
    let mut state = NativeState {
        best,
        header_mmr_peaks,
        pending_actions: BTreeMap::new(),
        pending_action_semantic_index: BTreeMap::new(),
        pending_action_order_index: BTreeSet::new(),
        pending_nullifiers: BTreeSet::new(),
        pending_bridge_replay_keys: PersistentKeySet48::new(),
        pending_mempool_bytes: 0,
        commitment_tree,
        nullifiers,
        nullifier_accumulator,
        consumed_bridge_messages,
        stablecoin_policy_authorizations: BTreeSet::new(),
        staged_ciphertexts,
        staged_proofs,
    };
    let (non_coinbase_actions, coinbase_actions): (Vec<_>, Vec<_>) = pending_actions
        .into_iter()
        .partition(|(_, action)| !is_coinbase_action(action));
    let mut dropped_pending = Vec::new();
    for (hash, action) in non_coinbase_actions.into_iter().chain(coinbase_actions) {
        if is_coinbase_action(&action) {
            debug!(
                tx_hash = %hex48(hash.as_bytes()),
                "dropping persisted coinbase action before startup mempool budgeting"
            );
            dropped_pending.push(hash);
            continue;
        }
        if state.pending_actions.len() >= max_pending_actions {
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) = validate_startup_pending_action_against_mempool_state(&state, &action) {
            debug!(
                tx_hash = %hex48(hash.as_bytes()),
                error = %err,
                "dropping semantically invalid persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) =
            validate_startup_mempool_byte_budget(&state, &action, max_pending_action_bytes)
        {
            debug!(
                tx_hash = %hex48(hash.as_bytes()),
                error = %err,
                "dropping over-budget persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        insert_pending_action_into_state(&mut state, action)?;
    }
    let pending_before_transfer_candidate_prune =
        state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_candidate_artifacts_when_transfers_pending(&mut state, "startup");
    for hash in pending_before_transfer_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    let pending_before_candidate_prune = state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_unselected_candidate_artifacts_from_pending(&mut state, "startup");
    for hash in pending_before_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    let pending_before_coinbase_prune = state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_auto_coinbase_actions_from_pending(&mut state, "startup");
    for hash in pending_before_coinbase_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    if !dropped_pending.is_empty() {
        for hash in dropped_pending {
            action_tree.remove(hash.as_ref()).with_context(|| {
                format!(
                    "remove invalid persisted pending action {}",
                    hex48(hash.as_bytes())
                )
            })?;
        }
        flush_native_db_durability_barrier(
            db,
            "native startup pending action repair",
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;
    }
    Ok(state)
}

pub(crate) fn validate_startup_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    validate_pending_action_against_mempool_state(state, action)
}

pub(crate) fn validate_startup_mempool_byte_budget(
    state: &NativeState,
    candidate: &PendingAction,
    max_bytes: usize,
) -> Result<()> {
    validate_mempool_byte_budget_for_state(state, candidate, max_bytes)
}

pub(crate) fn validate_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    validate_pending_action_against_mempool_state_inner(state, action, true)
}

#[cfg(test)]
pub(crate) fn validate_pending_action_against_mempool_state_for_group_engine_test(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    validate_pending_action_against_mempool_state_inner(state, action, false)
}

fn validate_pending_action_against_mempool_state_inner(
    state: &NativeState,
    action: &PendingAction,
    enforce_active_route: bool,
) -> Result<()> {
    if enforce_active_route {
        ensure_native_v3_active_action_route(action, false)?;
    }
    // The only caller that disables active-route enforcement is the cfg(test)
    // group-engine seam. It must also bypass the outer proof-authority gate so
    // batching, durability, and publication can be tested while every
    // production proof route remains fail closed.
    #[cfg(test)]
    let skip_group_engine_authoring_policy = !enforce_active_route;
    #[cfg(not(test))]
    let skip_group_engine_authoring_policy = false;
    if !skip_group_engine_authoring_policy {
        validate_native_action_authoring_version_policy(
            state.best.height,
            action.binding,
            action.family_id,
            action.action_id,
        )?;
    }
    match evaluate_native_action_scope_admission(native_action_scope_admission_input(action))
        .map_err(native_action_scope_admission_error)?
    {
        NativeActionScopeAdmissionRoute::Bridge => {
            if action.family_id == FAMILY_BRIDGE && action.action_id == ACTION_BRIDGE_INBOUND {
                let mut replay_state = inbound_replay_state_for_mempool(state)?;
                validate_bridge_action_payload_with_replay_state(action, Some(&replay_state))?;
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
                    match replay_state.stage(replay_key) {
                        Ok(()) => {}
                        Err(InboundReplayReject::AlreadyConsumed) => {
                            return Err(anyhow!("inbound bridge message already consumed"));
                        }
                        Err(InboundReplayReject::AlreadyPending) => {
                            return Err(anyhow!("inbound bridge message already pending"));
                        }
                    }
                }
            } else {
                validate_bridge_action_payload(action)?;
            }
            Ok(())
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact => Err(anyhow!(
            "candidate artifact submissions are retired; blocks carry independent SmallWood transaction proofs"
        )),
        NativeActionScopeAdmissionRoute::Coinbase => {
            validate_coinbase_action_payload(action)?;
            Ok(())
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            validate_transfer_action_payload(action)?;
            if is_poseidon2_v8_action(action) {
                let pending_v8_count = state
                    .pending_actions
                    .values()
                    .filter(|pending| is_poseidon2_v8_action(pending))
                    .count();
                if pending_v8_count >= MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK {
                    return Err(anyhow!(
                        "native mempool already contains the source-owned maximum of {MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK} Poseidon2 V8 actions"
                    ));
                }
                #[cfg(test)]
                if !enforce_active_route {
                    // The direct group-engine test seam supplies an exact
                    // verified-tip token but deliberately has no production
                    // capability. This lets concurrency tests reach the
                    // authoritative aggregate V8 count/byte checks without making a
                    // test boolean an authorization path in production.
                    return Ok(());
                }
                let height = state
                    .best
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("native V8 mempool candidate height overflow"))?;
                let production =
                    poseidon2_v8_verifier::Poseidon2V8ProductionBinding::require_source_at(height)
                        .map_err(|error| {
                            anyhow!("native V8 mempool authority rejected: {error}")
                        })?;
                poseidon2_v8_verifier::Poseidon2V8ActionView::from_pending(
                    production, height, action,
                )
                .map_err(|error| anyhow!("native V8 mempool action rejected: {error}"))?;

                // The caller additionally runs the proof and typed-state
                // preflight before group commit. The historical 48-byte
                // anchor/nullifier state below is never a projection of the
                // seven-limb V8 relation.
                return Ok(());
            }
            let input = native_transfer_state_admission_input_for_mempool(state, action);
            evaluate_native_transfer_state_admission(input).map_err(|rejection| {
                native_transfer_state_admission_error(
                    NativeTransferStateAdmissionContext::Mempool,
                    rejection,
                )
            })?;
            Ok(())
        }
    }
}

pub(crate) struct LoadedNullifierState {
    pub(crate) nullifiers: PersistentKeySet48,
    pub(crate) accumulator: NullifierAccumulator,
}

pub(crate) fn load_nullifiers(
    tree: &sled::Tree,
    meta_tree: &sled::Tree,
) -> Result<LoadedNullifierState> {
    let row_count =
        u64::try_from(tree.len()).map_err(|_| anyhow!("stored nullifier row count exceeds u64"))?;
    let mut indexed = BTreeMap::new();
    let mut nullifier_keys_well_formed = true;
    let mut nullifier_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            nullifier_keys_well_formed = false;
            continue;
        }
        if value.len() != 8 {
            nullifier_markers_valid = false;
            continue;
        }

        let mut nullifier = [0u8; 48];
        nullifier.copy_from_slice(&key);
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&value);
        let index = u64::from_be_bytes(index_bytes);
        if index >= row_count || indexed.insert(index, nullifier).is_some() {
            nullifier_markers_valid = false;
        }
    }
    if indexed.len() as u64 != row_count
        || indexed
            .keys()
            .copied()
            .enumerate()
            .any(|(expected, observed)| u64::try_from(expected).ok() != Some(observed))
    {
        nullifier_markers_valid = false;
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed,
        nullifier_markers_valid,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;

    let mut nullifiers = PersistentKeySet48::new();
    let mut rebuilt = NullifierAccumulator::new();
    for nullifier in indexed.into_values() {
        if !nullifiers.insert(nullifier) {
            return Err(anyhow!("stored nullifier rows contain a duplicate key"));
        }
        rebuilt
            .append(nullifier)
            .map_err(|err| anyhow!("rebuild stored nullifier accumulator failed: {err}"))?;
    }
    let encoded = meta_tree
        .get(META_NULLIFIER_ACCUMULATOR_KEY)?
        .ok_or_else(|| anyhow!("stored nullifier accumulator state is missing"))?;
    let stored = NullifierAccumulator::decode(&encoded)
        .map_err(|err| anyhow!("decode stored nullifier accumulator failed: {err}"))?;
    if stored != rebuilt {
        return Err(anyhow!(
            "stored nullifier accumulator state does not match indexed nullifier rows"
        ));
    }
    Ok(LoadedNullifierState {
        nullifiers,
        accumulator: stored,
    })
}

pub(crate) fn load_consumed_bridge_messages(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut consumed = BTreeSet::new();
    let mut replay_keys_well_formed = true;
    let mut replay_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            replay_keys_well_formed = false;
            continue;
        }
        if value.as_ref() != b"1" {
            replay_markers_valid = false;
            continue;
        }

        let mut replay_key = [0u8; 48];
        replay_key.copy_from_slice(&key);
        consumed.insert(replay_key);
    }
    evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed,
        replay_markers_valid,
        canonical_replay_keys_unique: true,
        no_missing_loaded_replay_keys: true,
        no_extra_loaded_replay_keys: true,
    })
    .map_err(native_bridge_replay_reload_error)?;
    Ok(consumed)
}

pub(crate) fn load_commitment_tree(tree: &sled::Tree) -> Result<CommitmentTreeState> {
    let mut commitments = Vec::new();
    let mut commitment_keys_well_formed = true;
    let mut commitment_values_well_formed = true;
    let mut commitment_indexes_contiguous = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            commitment_keys_well_formed = false;
            continue;
        }
        if value.len() != 48 {
            commitment_values_well_formed = false;
            continue;
        }

        let mut index = [0u8; 8];
        index.copy_from_slice(&key);
        let index = u64::from_be_bytes(index);
        let expected = u64::try_from(commitments.len())
            .map_err(|_| anyhow!("stored commitment count exceeds u64"))?;
        if index != expected {
            commitment_indexes_contiguous = false;
            continue;
        }

        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(&value);
        commitments.push(commitment);
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed,
        commitment_values_well_formed,
        commitment_indexes_contiguous,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;

    match CommitmentTreeState::from_leaves(
        COMMITMENT_TREE_DEPTH,
        consensus::DEFAULT_ROOT_HISTORY_LIMIT,
        commitments,
    ) {
        Ok(state) => Ok(state),
        Err(err) => {
            let rejection =
                evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
                    nullifier_keys_well_formed: true,
                    nullifier_markers_valid: true,
                    commitment_keys_well_formed: true,
                    commitment_values_well_formed: true,
                    commitment_indexes_contiguous: true,
                    commitment_tree_rebuilt: false,
                    commitment_root_matches_best: true,
                    nullifier_root_matches_best: true,
                })
                .expect_err("commitment tree rebuild failure must reject");
            Err(native_canonical_state_reload_error(rejection)
                .context(format!("commitment tree detail: {err}")))
        }
    }
}

pub(crate) fn validate_loaded_canonical_state(
    best: &NativeBlockMeta,
    commitment_state: &CommitmentTreeState,
    nullifiers: &PersistentKeySet48,
    nullifier_accumulator: &NullifierAccumulator,
) -> Result<()> {
    let commitment_root = commitment_state.root();
    let nullifier_root = nullifier_accumulator.root();
    let nullifier_count_matches =
        usize::try_from(nullifier_accumulator.leaf_count()).ok() == Some(nullifiers.len());
    let admission = evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: commitment_root == best.state_root,
        nullifier_root_matches_best: nullifier_count_matches
            && nullifier_root == best.nullifier_root,
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeCanonicalStateReloadRejection::CommitmentRootMismatch => Err(anyhow!(
                "stored commitment tree root mismatch: best={} loaded={} leaves={} ({})",
                hex48(&best.state_root),
                hex48(&commitment_root),
                commitment_state.leaf_count(),
                rejection.label()
            )),
            NativeCanonicalStateReloadRejection::NullifierRootMismatch => Err(anyhow!(
                "stored nullifier root mismatch: best={} loaded={} entries={} ({})",
                hex48(&best.nullifier_root),
                hex48(&nullifier_root),
                nullifiers.len(),
                rejection.label()
            )),
            _ => Err(native_canonical_state_reload_error(rejection)),
        };
    }

    Ok(())
}

pub(crate) struct ExpectedBridgeReplayReloadState {
    consumed: BTreeSet<[u8; 48]>,
    duplicate_replay_key: Option<[u8; 48]>,
}

pub(crate) fn expected_consumed_bridge_messages_from_chain(
    chain: &[NativeBlockMeta],
) -> Result<ExpectedBridgeReplayReloadState> {
    let mut consumed = BTreeSet::new();
    let mut duplicate_replay_key = None;
    for meta in chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            if let Some(replay_key) = bridge_inbound_replay_key_from_action(&action)? {
                if !consumed.insert(replay_key) && duplicate_replay_key.is_none() {
                    duplicate_replay_key = Some(replay_key);
                }
            }
        }
    }
    Ok(ExpectedBridgeReplayReloadState {
        consumed,
        duplicate_replay_key,
    })
}

pub(crate) fn validate_loaded_bridge_replay_state(
    canonical_chain: &ValidatedCanonicalChainSnapshot,
    consumed_bridge_messages: &PersistentKeySet48,
) -> Result<()> {
    let expected_state = expected_consumed_bridge_messages_from_chain(canonical_chain.blocks())?;
    let expected = &expected_state.consumed;
    let missing = expected
        .iter()
        .find(|key| !consumed_bridge_messages.contains(key))
        .copied();
    let extra = consumed_bridge_messages
        .iter()
        .find(|key| !expected.contains(*key))
        .copied();
    let admission = evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed: true,
        replay_markers_valid: true,
        canonical_replay_keys_unique: expected_state.duplicate_replay_key.is_none(),
        no_missing_loaded_replay_keys: missing.is_none(),
        no_extra_loaded_replay_keys: extra.is_none(),
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => {
                let replay_key = expected_state
                    .duplicate_replay_key
                    .map(|key| hex48(&key))
                    .unwrap_or_else(|| "unknown".to_string());
                Err(anyhow!(
                    "canonical chain contains duplicate inbound bridge replay key {} ({})",
                    replay_key,
                    rejection.label()
                ))
            }
            NativeBridgeReplayReloadRejection::MissingConsumedReplayKey
            | NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => {
                let missing = missing
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                let extra = extra
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                Err(anyhow!(
                    "stored bridge replay set mismatch: expected={} loaded={} first_missing={} first_extra={} ({})",
                    expected.len(),
                    consumed_bridge_messages.len(),
                    missing,
                    extra,
                    rejection.label()
                ))
            }
            _ => Err(native_bridge_replay_reload_error(rejection)),
        };
    }
    Ok(())
}
