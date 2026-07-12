//! CLI/base-path resolution, identity seeds, parsing, codecs, and shutdown signals.

use super::*;

pub(crate) fn resolve_base_path(cli: &NativeCli) -> Result<PathBuf> {
    if cli.tmp {
        return Ok(std::env::temp_dir().join(format!(
            "hegemon-native-{}-{}",
            std::process::id(),
            current_time_ms()
        )));
    }
    if let Some(path) = &cli.base_path {
        return Ok(path.clone());
    }
    Ok(PathBuf::from(".hegemon/native"))
}

pub(crate) fn load_native_identity_seed(config: &NativeConfig) -> Result<[u8; 32]> {
    if let Ok(raw) = std::env::var("HEGEMON_PQ_IDENTITY_SEED") {
        return parse_identity_seed_hex(&raw)
            .ok_or_else(|| anyhow!("HEGEMON_PQ_IDENTITY_SEED must be 32-byte hex"));
    }
    let path = std::env::var("HEGEMON_PQ_IDENTITY_SEED_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| config.base_path.join(PQ_IDENTITY_SEED_FILE));
    load_or_create_identity_seed(&path)
}

pub(crate) fn load_native_miner_identity(config: &NativeConfig) -> Result<NativeMinerIdentity> {
    let seed = if let Ok(raw) = std::env::var("HEGEMON_MINER_IDENTITY_SEED") {
        parse_identity_seed_hex(&raw)
            .ok_or_else(|| anyhow!("HEGEMON_MINER_IDENTITY_SEED must be 32-byte hex"))?
    } else {
        let path = std::env::var("HEGEMON_MINER_IDENTITY_SEED_PATH")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| config.base_path.join(MINER_IDENTITY_SEED_FILE));
        load_or_create_identity_seed(&path)?
    };
    Ok(NativeMinerIdentity::from_seed(&seed))
}

pub(crate) fn load_or_create_identity_seed(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        tighten_identity_seed_permissions(path)?;
        return read_identity_seed(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create identity seed directory {}", parent.display()))?;
    }
    let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let encoded = format!("{}\n", hex::encode(seed));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())
                .with_context(|| format!("write identity seed {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("sync identity seed {}", path.display()))?;
            tighten_identity_seed_permissions(path)?;
            Ok(seed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            tighten_identity_seed_permissions(path)?;
            read_identity_seed(path)
        }
        Err(err) => Err(err).with_context(|| format!("create identity seed {}", path.display())),
    }
}

pub(crate) fn read_identity_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read identity seed {}", path.display()))?;
    if bytes.len() == PQ_IDENTITY_SEED_LEN {
        let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }
    let raw = std::str::from_utf8(&bytes)
        .ok()
        .and_then(parse_identity_seed_hex)
        .ok_or_else(|| anyhow!("identity seed file must contain 32 raw bytes or 32-byte hex"))?;
    Ok(raw)
}

pub(crate) fn parse_identity_seed_hex(raw: &str) -> Option<[u8; 32]> {
    let clean = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != PQ_IDENTITY_SEED_LEN {
        return None;
    }
    let mut seed = [0u8; PQ_IDENTITY_SEED_LEN];
    seed.copy_from_slice(&bytes);
    Some(seed)
}

pub(crate) fn tighten_identity_seed_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on identity seed {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn effective_rpc_methods_label(raw: &str, rpc_external: bool) -> Result<&'static str> {
    Ok(rpc_method_policy(raw, rpc_external)?.label())
}

pub(crate) fn rpc_method_policy(raw: &str, rpc_external: bool) -> Result<RpcMethodPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "safe" => Ok(RpcMethodPolicy::Safe),
        "unsafe" => {
            if rpc_external {
                Err(anyhow!(
                    "--rpc-methods=unsafe cannot be combined with --rpc-external; use a loopback listener behind an authenticated tunnel"
                ))
            } else {
                Ok(RpcMethodPolicy::Unsafe)
            }
        }
        "auto" | "" => Ok(RpcMethodPolicy::Safe),
        other => Err(anyhow!(
            "invalid --rpc-methods value {other:?}; expected auto, safe, or unsafe"
        )),
    }
}

pub(crate) fn default_native_wallet_page_limit() -> u64 {
    DEFAULT_NATIVE_WALLET_PAGE_LIMIT
}

pub(crate) fn pagination_from_params(params: Value) -> Result<NativePagination> {
    let value = first_param(&params).cloned().unwrap_or(Value::Null);
    let mut page = if value.is_null() {
        NativePagination {
            start: 0,
            limit: DEFAULT_NATIVE_WALLET_PAGE_LIMIT,
        }
    } else {
        serde_json::from_value::<NativePagination>(value).context("decode pagination params")?
    };
    if page.limit == 0 {
        page.limit = DEFAULT_NATIVE_WALLET_PAGE_LIMIT;
    }
    page.limit = page.limit.min(MAX_NATIVE_WALLET_PAGE_LIMIT);
    Ok(page)
}

pub(crate) fn wallet_page_end(page: NativePagination, total: u64) -> Result<u64> {
    if page.start >= total {
        return Ok(page.start);
    }
    page.start
        .checked_add(page.limit)
        .map(|end| end.min(total))
        .ok_or_else(|| anyhow!("native wallet page range overflow"))
}

pub(crate) fn is_unsafe_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "hegemon_startMining"
            | "hegemon_stopMining"
            | "hegemon_submitAction"
            | "hegemon_peerGraph"
            | "hegemon_peerList"
            | "hegemon_exportBridgeWitness"
            | "system_peers"
            | "da_submitCiphertexts"
            | "da_submitProofs"
    )
}

pub(crate) fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

pub(crate) fn height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

pub(crate) fn first_param(params: &Value) -> Option<&Value> {
    match params {
        Value::Array(values) => values.first(),
        Value::Object(_) => Some(params),
        _ => None,
    }
}

pub(crate) fn parse_mining_thread_count_str(raw: &str, context: &str) -> Result<u32> {
    let requested = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{context} must be an unsigned integer"))?;
    parse_mining_thread_count_u64(requested, context)
}

pub(crate) fn parse_mining_thread_count_u64(requested: u64, context: &str) -> Result<u32> {
    if requested == 0 {
        return Err(anyhow!("{context} must be at least 1"));
    }
    if requested > u64::from(MAX_NATIVE_MINING_THREADS) {
        return Err(anyhow!(
            "{context} exceeds maximum mining threads: {} > {}",
            requested,
            MAX_NATIVE_MINING_THREADS
        ));
    }
    Ok(requested as u32)
}

pub(crate) fn native_available_parallelism() -> u32 {
    std::thread::available_parallelism()
        .ok()
        .and_then(|threads| u32::try_from(threads.get()).ok())
        .unwrap_or(1)
        .max(1)
}

pub(crate) fn effective_native_mining_threads(requested: u32, available_threads: u32) -> u32 {
    let requested = requested.max(1);
    let available = available_threads.max(1);
    let liveness_cap = available
        .saturating_sub(NATIVE_MINING_RESERVED_SERVICE_THREADS)
        .max(1);
    requested
        .min(liveness_cap)
        .min(NATIVE_MINING_BACKGROUND_THREAD_CAP)
}

pub(crate) fn start_mining_threads_from_params(params: &Value) -> Result<u32> {
    let Some(first) = first_param(params) else {
        return Ok(1);
    };
    let Value::Object(map) = first else {
        if first.is_null() {
            return Ok(1);
        }
        return Err(anyhow!(
            "hegemon_startMining params must be an object with optional threads"
        ));
    };
    let Some(value) = map.get("threads") else {
        return Ok(1);
    };
    let requested = value
        .as_u64()
        .ok_or_else(|| anyhow!("hegemon_startMining threads must be an unsigned integer"))?;
    parse_mining_thread_count_u64(requested, "hegemon_startMining threads")
}

pub(crate) fn nth_param(params: &Value, index: usize) -> Option<&Value> {
    match params {
        Value::Array(values) => values.get(index),
        _ if index == 0 => Some(params),
        _ => None,
    }
}

pub(crate) fn parse_height(raw: &str) -> Option<u64> {
    raw.strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| raw.parse::<u64>().ok())
}

pub(crate) fn parse_hash32(raw: &str) -> Option<[u8; 32]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(crate) fn parse_hex48(raw: &str) -> Option<[u8; 48]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(crate) fn parse_hex64(raw: &str) -> Option<[u8; 64]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(crate) fn decode_base64(raw: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("decode base64")
}

pub(crate) fn decode_scale_exact<T: Decode + Encode>(bytes: &[u8], label: &str) -> Result<T> {
    let mut cursor = bytes;
    let value = T::decode(&mut cursor).map_err(|err| anyhow!("decode {label} failed: {err:?}"))?;
    if !cursor.is_empty() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after SCALE decode",
            cursor.len()
        ));
    }
    let canonical = value.encode();
    if canonical.as_slice() != bytes {
        return Err(anyhow!(
            "{label} is not canonical SCALE encoding: input_len={}, canonical_len={}",
            bytes.len(),
            canonical.len()
        ));
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) fn bincode_deserialize_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
) -> Result<T> {
    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::deserialize_from(&mut cursor)
        .map_err(|err| anyhow!("decode {label} failed: {err}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after bincode decode",
            bytes.len().saturating_sub(cursor.position() as usize)
        ));
    }
    let canonical =
        bincode::serialize(&value).map_err(|err| anyhow!("re-encode {label} failed: {err}"))?;
    if canonical.as_slice() != bytes {
        return Err(anyhow!(
            "{label} is not canonical bincode encoding: input_len={}, canonical_len={}",
            bytes.len(),
            canonical.len()
        ));
    }
    Ok(value)
}

pub(crate) fn bincode_deserialize_exact_with_limit<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    label: &str,
    max_bytes: usize,
) -> Result<T> {
    if bytes.len() > max_bytes {
        return Err(anyhow!(
            "{label} bytes exceed bincode decode limit: {} > {}",
            bytes.len(),
            max_bytes
        ));
    }
    let mut cursor = Cursor::new(bytes);
    let value: T = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes as u64)
        .deserialize_from(&mut cursor)
        .map_err(|err| anyhow!("decode {label} failed: {err}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after bincode decode",
            bytes.len().saturating_sub(cursor.position() as usize)
        ));
    }
    let canonical =
        bincode::serialize(&value).map_err(|err| anyhow!("re-encode {label} failed: {err}"))?;
    if canonical.as_slice() != bytes {
        return Err(anyhow!(
            "{label} is not canonical bincode encoding: input_len={}, canonical_len={}",
            bytes.len(),
            canonical.len()
        ));
    }
    Ok(value)
}

pub(crate) const BINCODE_FIXINT_VEC_LEN_BYTES: usize = 8;
pub(crate) const BINCODE_SERDE_BYTES48_BYTES: usize = BINCODE_FIXINT_VEC_LEN_BYTES + 48;
pub(crate) const NATIVE_BLOCK_META_ACTION_BYTES_OFFSET: usize = 32
    + 32
    + 8
    + 32
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + BINCODE_SERDE_BYTES48_BYTES
    + BINCODE_SERDE_BYTES48_BYTES
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + 4
    + 32
    + 8
    + 8
    + 4
    + 32
    + 32
    + BINCODE_SERDE_BYTES48_BYTES
    + 16
    + 4;

pub(crate) fn bincode_deserialize_native_block_meta_exact(
    bytes: &[u8],
    label: &str,
) -> Result<NativeBlockMeta> {
    validate_native_block_meta_bincode_budget(bytes, label)?;
    match bincode_deserialize_exact_with_limit::<NativeBlockMeta>(
        bytes,
        label,
        MAX_NATIVE_BLOCK_META_BYTES,
    ) {
        Ok(meta) => Ok(meta),
        Err(current_error) => {
            match bincode_deserialize_exact_with_limit::<LegacyNativeBlockMetaV1>(
                bytes,
                &format!("legacy {label}"),
                MAX_NATIVE_BLOCK_META_BYTES,
            ) {
                Ok(meta) => Ok(meta.into()),
                Err(legacy_error) => Err(anyhow!(
                    "{label} did not decode as current or legacy native metadata: current={current_error}; legacy={legacy_error}"
                )),
            }
        }
    }
}

pub(crate) fn validate_native_block_meta_bincode_budget(bytes: &[u8], label: &str) -> Result<()> {
    validate_native_block_meta_bincode_budget_with_total_limit(
        bytes,
        label,
        MAX_NATIVE_BLOCK_META_BYTES,
    )
}

pub(crate) fn validate_native_block_meta_bincode_budget_with_total_limit(
    bytes: &[u8],
    label: &str,
    max_total_bytes: usize,
) -> Result<()> {
    if bytes.len() > max_total_bytes {
        return Err(anyhow!(
            "{label} bytes exceed native block metadata limit: {} > {}",
            bytes.len(),
            max_total_bytes
        ));
    }
    let Some(action_count) = read_bincode_fixint_len(bytes, NATIVE_BLOCK_META_ACTION_BYTES_OFFSET)?
    else {
        return Ok(());
    };
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "{label} action byte count exceeds limit before bincode decode: {} > {}",
            action_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }

    let mut cursor = NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + BINCODE_FIXINT_VEC_LEN_BYTES;
    let mut total_action_bytes = 0usize;
    for index in 0..action_count {
        let Some(action_len) = read_bincode_fixint_len(bytes, cursor)? else {
            return Ok(());
        };
        if action_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "{label} action payload {index} exceeds limit before bincode decode: {} > {}",
                action_len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        total_action_bytes = total_action_bytes
            .checked_add(action_len)
            .ok_or_else(|| anyhow!("{label} action byte total overflow before bincode decode"))?;
        if total_action_bytes > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "{label} action bytes exceed aggregate limit before bincode decode: {} > {}",
                total_action_bytes,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
        cursor = cursor
            .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
            .and_then(|next| next.checked_add(action_len))
            .ok_or_else(|| anyhow!("{label} bincode action-byte cursor overflow"))?;
        if cursor > bytes.len() {
            return Ok(());
        }
    }

    let Some(miner_commitment_len) = read_bincode_fixint_len(bytes, cursor)? else {
        return Ok(());
    };
    if miner_commitment_len > 48 {
        return Err(anyhow!(
            "{label} miner commitment exceeds limit before bincode decode: {} > 48",
            miner_commitment_len
        ));
    }
    let Some(miner_cursor) = cursor
        .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
        .and_then(|next| next.checked_add(miner_commitment_len))
    else {
        return Err(anyhow!("{label} bincode miner-field cursor overflow"));
    };
    if miner_cursor > bytes.len() {
        return Ok(());
    }
    let Some(miner_public_key_len) = read_bincode_fixint_len(bytes, miner_cursor)? else {
        return Ok(());
    };
    if miner_public_key_len > ML_DSA_PUBLIC_KEY_LEN {
        return Err(anyhow!(
            "{label} miner public key exceeds limit before bincode decode: {} > {}",
            miner_public_key_len,
            ML_DSA_PUBLIC_KEY_LEN
        ));
    }
    let Some(after_public_key_len) = miner_cursor.checked_add(BINCODE_FIXINT_VEC_LEN_BYTES) else {
        return Err(anyhow!("{label} bincode miner public-key cursor overflow"));
    };
    let Some(signature_cursor) = after_public_key_len.checked_add(miner_public_key_len) else {
        return Err(anyhow!(
            "{label} bincode miner public-key payload cursor overflow"
        ));
    };
    if signature_cursor > bytes.len() {
        return Ok(());
    }
    let Some(miner_signature_len) = read_bincode_fixint_len(bytes, signature_cursor)? else {
        return Ok(());
    };
    if miner_signature_len > ML_DSA_SIGNATURE_LEN {
        return Err(anyhow!(
            "{label} miner signature exceeds limit before bincode decode: {} > {}",
            miner_signature_len,
            ML_DSA_SIGNATURE_LEN
        ));
    }
    Ok(())
}

pub(crate) fn read_bincode_fixint_len(bytes: &[u8], offset: usize) -> Result<Option<usize>> {
    let Some(end) = offset.checked_add(BINCODE_FIXINT_VEC_LEN_BYTES) else {
        return Err(anyhow!("bincode length cursor overflow"));
    };
    if end > bytes.len() {
        return Ok(None);
    }
    let mut raw = [0u8; BINCODE_FIXINT_VEC_LEN_BYTES];
    raw.copy_from_slice(&bytes[offset..end]);
    usize::try_from(u64::from_le_bytes(raw))
        .map(Some)
        .map_err(|_| anyhow!("bincode length does not fit usize"))
}

pub(crate) fn encoded_len_limit(decoded_len_limit: usize) -> usize {
    decoded_len_limit.saturating_mul(4).saturating_add(2) / 3 + 4
}

pub(crate) fn parse_bytes_value(
    value: &Value,
    max_decoded_len: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow!("expected base64 or 0x-prefixed hex string"))?;
    if let Some(hex) = raw.strip_prefix("0x") {
        if hex.len() > max_decoded_len.saturating_mul(2) {
            return Err(anyhow!(
                "{label} hex length {} exceeds decoded limit {}",
                hex.len(),
                max_decoded_len
            ));
        }
        let bytes = hex::decode(hex).context("decode hex bytes")?;
        if bytes.len() > max_decoded_len {
            return Err(anyhow!(
                "{label} decoded length {} exceeds limit {}",
                bytes.len(),
                max_decoded_len
            ));
        }
        return Ok(bytes);
    }
    if raw.len() > encoded_len_limit(max_decoded_len) {
        return Err(anyhow!(
            "{label} base64 length {} exceeds decoded limit {}",
            raw.len(),
            max_decoded_len
        ));
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .context("decode base64 bytes")?;
    if bytes.len() > max_decoded_len {
        return Err(anyhow!(
            "{label} decoded length {} exceeds limit {}",
            bytes.len(),
            max_decoded_len
        ));
    }
    Ok(bytes)
}

pub(crate) fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| {
            let raw = raw.trim();
            raw == "1" || raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

pub(crate) fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn hash32_with_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn hash48_with_parts(parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 48];
    reader.fill(&mut out);
    out
}

pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub(crate) fn hex48(bytes: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub(crate) fn hex64(bytes: &[u8; 64]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub(crate) fn json_response(node: &NativeNode, status: StatusCode, body: Value) -> Response {
    with_cors(node, (status, Json(body)).into_response())
}

pub(crate) fn with_cors(node: &NativeNode, mut response: Response) -> Response {
    let headers = response.headers_mut();
    if let Some(origin) = rpc_cors_origin(node) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, GET, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, authorization"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("origin"));
    }
    response
}

pub(crate) fn rpc_cors_origin(node: &NativeNode) -> Option<HeaderValue> {
    let cors = node.config.rpc_cors.as_deref()?.trim();
    if cors.is_empty() {
        return None;
    }
    if cors == "*" && node.rpc_policy().ok() == Some(RpcMethodPolicy::Unsafe) {
        warn!("ignoring wildcard RPC CORS while unsafe RPC methods are enabled");
        return None;
    }
    HeaderValue::from_str(cors).ok()
}

pub(crate) fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message.into(),
        },
        "id": id,
    })
}

pub(crate) fn native_rpc_methods(policy: RpcMethodPolicy) -> Vec<&'static str> {
    let mut methods = vec![
        "archive_getContract",
        "archive_getProvider",
        "archive_listContracts",
        "archive_listProviders",
        "archive_providerCount",
        "author_pendingExtrinsics",
        "block_getCommitmentProof",
        "chain_getBlock",
        "chain_getBlockHash",
        "chain_getHeader",
        "chain_subscribeFinalizedHeads",
        "chain_subscribeNewHeads",
        "da_getChunk",
        "da_getParams",
        "da_submitCiphertexts",
        "da_submitProofs",
        "da_submitWitnesses",
        "hegemon_blockTimestamps",
        "hegemon_compactJob",
        "hegemon_consensusStatus",
        "hegemon_exportBridgeWitness",
        "hegemon_generateProof",
        "hegemon_isValidAnchor",
        "hegemon_latestBlock",
        "hegemon_minedBlockTimestamps",
        "hegemon_miningStatus",
        "hegemon_nodeConfig",
        "hegemon_peerGraph",
        "hegemon_peerList",
        "hegemon_poolStatus",
        "hegemon_poolWork",
        "hegemon_startMining",
        "hegemon_stopMining",
        "hegemon_storageFootprint",
        "hegemon_submitAction",
        "hegemon_submitCompactSolution",
        "hegemon_submitPoolShare",
        "hegemon_submitTransaction",
        "hegemon_telemetry",
        "hegemon_walletCiphertexts",
        "hegemon_walletCommitments",
        "hegemon_walletNotes",
        "hegemon_walletNullifiers",
        "rpc_methods",
        "state_getRuntimeVersion",
        "state_getStorage",
        "state_getStorageAt",
        "state_getStorageHash",
        "state_getStorageHashAt",
        "state_getStorageSize",
        "state_getStorageSizeAt",
        "system_chain",
        "system_health",
        "system_name",
        "system_peers",
        "system_version",
    ];
    if policy != RpcMethodPolicy::Unsafe {
        let mut safe_methods = Vec::with_capacity(methods.len());
        for method in methods {
            if !is_unsafe_rpc_method(method) {
                safe_methods.push(method);
            }
        }
        methods = safe_methods;
    }
    methods
}

pub(crate) fn system_peers_snapshot(node: &NativeNode) -> Value {
    Value::Array(
        node.network_peer_snapshot()
            .into_iter()
            .map(|peer| {
                json!({
                    "peerId": hex32(&peer.peer_id),
                    "roles": "FULL",
                    "protocolVersion": 10u32,
                    "bestHash": null,
                    "bestNumber": null,
                    "endpoint": peer.addr.to_string(),
                    "connected": true,
                })
            })
            .collect(),
    )
}

pub(crate) fn hegemon_peer_list_snapshot(node: &NativeNode) -> Value {
    Value::Array(
        node.network_peer_snapshot()
            .into_iter()
            .map(|peer| {
                json!({
                    "peer_id": hex32(&peer.peer_id),
                    "addr": peer.addr.to_string(),
                    "connected": true,
                    "protocols": [NATIVE_SYNC_PROTOCOL_ID],
                })
            })
            .collect(),
    )
}

pub(crate) fn hegemon_peer_graph_snapshot(node: &NativeNode) -> Value {
    let local_peer_id = node.network_local_peer_id().map(|peer_id| hex32(&peer_id));
    let peers = node.network_peer_snapshot();
    let peer_rows: Vec<Value> = peers
        .iter()
        .map(|peer| {
            json!({
                "peer_id": hex32(&peer.peer_id),
                "addr": peer.addr.to_string(),
                "connected": true,
            })
        })
        .collect();
    let links: Vec<Value> = peers
        .iter()
        .map(|peer| {
            json!({
                "from": local_peer_id.clone().unwrap_or_default(),
                "to": hex32(&peer.peer_id),
                "addr": peer.addr.to_string(),
            })
        })
        .collect();

    json!({
        "local_peer_id": local_peer_id.unwrap_or_default(),
        "peers": peer_rows,
        "links": links,
        "reports": [],
    })
}

pub(crate) mod serde_array48 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(D::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

pub(crate) async fn shutdown_signal(node: Arc<NativeNode>) {
    let signal = wait_for_native_shutdown_signal().await;
    info!(signal, "native Hegemon node shutdown signal received");
    node.stop_mining();
    if let Err(err) = flush_native_db_durability_barrier(
        &node.db,
        "native shutdown flush",
        NativeStorageDurabilityOperation::ShutdownFlush,
    ) {
        warn!(error = %err, "failed to flush native db during shutdown");
    }
    record_native_shutdown_complete();
}

pub(crate) fn record_native_shutdown_complete() {
    info!("native Hegemon node shutdown complete");
}

#[cfg(unix)]
pub(crate) async fn wait_for_native_shutdown_signal() -> &'static str {
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(signal) => signal,
        Err(err) => {
            warn!(error = %err, "failed to install SIGTERM handler; falling back to Ctrl-C");
            let _ = tokio::signal::ctrl_c().await;
            return "ctrl_c";
        }
    };

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                warn!(error = %err, "failed while waiting for Ctrl-C shutdown signal");
            }
            "ctrl_c"
        }
        _ = sigterm.recv() => "sigterm",
    }
}

#[cfg(not(unix))]
pub(crate) async fn wait_for_native_shutdown_signal() -> &'static str {
    if let Err(err) = tokio::signal::ctrl_c().await {
        warn!(error = %err, "failed while waiting for Ctrl-C shutdown signal");
    }
    "ctrl_c"
}
