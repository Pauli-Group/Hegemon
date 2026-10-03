//! Reproducibly generate the wallet-owned V8 retained lifecycle carriers.

use clap::Parser;
use codec::Encode;
use protocol_shielded_pool::poseidon2_v8_coinbase::{
    Poseidon2V8CoinbaseNoteOpening, POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES,
    POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};
use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_single_key_authorization_key, poseidon2_v8_words_from_canonical_bytes,
};
use wallet::{
    keys::RootSecret,
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    poseidon2_v8_coinbase::{
        build_poseidon2_v8_coinbase_args_from_opening, build_poseidon2_v8_two_coinbase_self_spend,
        decrypt_poseidon2_v8_coinbase_opening,
    },
};

const VALUE: u64 = 499_429_223;
const MANIFEST_SCHEMA: &str = "hegemon-poseidon2-v8-retained-wallet-vectors-v1";
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const CANDIDATE_DIRECTORY_MAX_BYTES: usize = 32 * 1024;
const CANDIDATE_FILE_COUNT: usize = 5;

type GeneratorResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Parser)]
#[command(
    name = "generate_poseidon2_v8_retained_vectors",
    about = "Generate an isolated, no-overwrite candidate wallet-vector directory"
)]
struct Args {
    /// A new directory outside the canonical retained-vector directory.
    #[arg(long, value_name = "NEW_DIRECTORY")]
    output_root: PathBuf,
}

#[derive(Clone, Copy, Debug)]
struct FileSpec {
    name: &'static str,
    exact_bytes: Option<usize>,
    max_bytes: usize,
}

const FILE_SPECS: [FileSpec; CANDIDATE_FILE_COUNT] = [
    FileSpec {
        name: "coinbase_0.scale",
        exact_bytes: Some(POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES),
        max_bytes: POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES,
    },
    FileSpec {
        name: "coinbase_1.scale",
        exact_bytes: Some(POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES),
        max_bytes: POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES,
    },
    FileSpec {
        name: "output_0.raw",
        exact_bytes: Some(POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES),
        max_bytes: POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
    },
    FileSpec {
        name: "output_1.raw",
        exact_bytes: Some(POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES),
        max_bytes: POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
    },
    FileSpec {
        name: "manifest.json",
        exact_bytes: None,
        max_bytes: MANIFEST_MAX_BYTES,
    },
];

#[derive(Clone, Debug)]
struct CandidateFile {
    name: &'static str,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CandidateBundle {
    files: Vec<CandidateFile>,
}

fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn canonical_vector_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("wallet manifest directory has a repository parent")
        .join("protocol/shielded-pool/test-vectors/poseidon2_v8_retained")
}

fn path_entry_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn normalize_absolute_path(path: &Path) -> GeneratorResult<PathBuf> {
    if !path.is_absolute() {
        return Err("path normalization requires an absolute path".into());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("path traversal escapes the filesystem root".into());
                }
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    Ok(normalized)
}

fn reject_canonical_containment(destination: &Path, canonical: &Path) -> GeneratorResult<()> {
    if destination == canonical || destination.starts_with(canonical) {
        return Err(format!(
            "refusing to write in canonical retained-vector directory {}",
            canonical.display()
        )
        .into());
    }
    Ok(())
}

fn resolve_candidate_destination(requested: &Path) -> GeneratorResult<PathBuf> {
    if requested.as_os_str().is_empty() {
        return Err("candidate output root must not be empty".into());
    }
    if requested
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err("candidate output root must not contain parent traversal".into());
    }
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        env::current_dir()?.join(requested)
    };
    let absolute = normalize_absolute_path(&absolute)?;
    let canonical = normalize_absolute_path(&canonical_vector_directory())?;
    reject_canonical_containment(&absolute, &canonical)?;
    let file_name = absolute
        .file_name()
        .ok_or("candidate output root must name a directory")?
        .to_os_string();
    let parent = absolute
        .parent()
        .ok_or("candidate output root must have a parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        format!(
            "candidate output parent {} must already exist: {error}",
            parent.display()
        )
    })?;
    if !parent_metadata.file_type().is_dir() {
        return Err(format!(
            "candidate output parent {} must be a real directory",
            parent.display()
        )
        .into());
    }
    let destination = fs::canonicalize(parent)?.join(file_name);
    let canonical = fs::canonicalize(canonical)?;
    reject_canonical_containment(&destination, &canonical)?;
    Ok(destination)
}

fn require_absent_destination(destination: &Path) -> GeneratorResult<()> {
    if path_entry_exists(destination)? {
        return Err(format!(
            "refusing to overwrite candidate output root {}",
            destination.display()
        )
        .into());
    }
    Ok(())
}

fn spec_for(name: &str) -> GeneratorResult<FileSpec> {
    FILE_SPECS
        .iter()
        .copied()
        .find(|spec| spec.name == name)
        .ok_or_else(|| format!("unexpected candidate file {name}").into())
}

impl CandidateBundle {
    fn file(&self, name: &str) -> GeneratorResult<&CandidateFile> {
        self.files
            .iter()
            .find(|file| file.name == name)
            .ok_or_else(|| format!("candidate bundle is missing {name}").into())
    }

    fn validate(&self) -> GeneratorResult<()> {
        if self.files.len() != CANDIDATE_FILE_COUNT {
            return Err(format!(
                "candidate bundle has {} files, expected {CANDIDATE_FILE_COUNT}",
                self.files.len()
            )
            .into());
        }
        let mut names = BTreeSet::new();
        let mut total_bytes = 0usize;
        for file in &self.files {
            if !names.insert(file.name) {
                return Err(format!("duplicate candidate file {}", file.name).into());
            }
            let spec = spec_for(file.name)?;
            if file.bytes.len() > spec.max_bytes {
                return Err(format!(
                    "candidate file {} has {} bytes, cap is {}",
                    file.name,
                    file.bytes.len(),
                    spec.max_bytes
                )
                .into());
            }
            if let Some(exact_bytes) = spec.exact_bytes {
                if file.bytes.len() != exact_bytes {
                    return Err(format!(
                        "candidate file {} has {} bytes, expected exactly {exact_bytes}",
                        file.name,
                        file.bytes.len()
                    )
                    .into());
                }
            }
            total_bytes = total_bytes
                .checked_add(file.bytes.len())
                .ok_or("candidate bundle byte count overflow")?;
        }
        let expected_names = FILE_SPECS
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        if names != expected_names {
            return Err("candidate bundle file set is not canonical".into());
        }
        if total_bytes > CANDIDATE_DIRECTORY_MAX_BYTES {
            return Err(format!(
                "candidate bundle has {total_bytes} bytes, cap is {CANDIDATE_DIRECTORY_MAX_BYTES}"
            )
            .into());
        }
        self.validate_manifest()
    }

    fn validate_manifest(&self) -> GeneratorResult<()> {
        let manifest: Value = serde_json::from_slice(&self.file("manifest.json")?.bytes)?;
        if manifest.get("schema").and_then(Value::as_str) != Some(MANIFEST_SCHEMA) {
            return Err("candidate manifest schema mismatch".into());
        }
        let files = manifest
            .get("files")
            .and_then(Value::as_object)
            .ok_or("candidate manifest files object is missing")?;
        if files.len() != CANDIDATE_FILE_COUNT - 1 {
            return Err("candidate manifest payload file set is not exact".into());
        }
        for spec in FILE_SPECS
            .iter()
            .filter(|spec| spec.name != "manifest.json")
        {
            let payload = self.file(spec.name)?;
            let record = files
                .get(spec.name)
                .and_then(Value::as_object)
                .ok_or_else(|| format!("candidate manifest is missing {}", spec.name))?;
            if record.get("bytes").and_then(Value::as_u64)
                != u64::try_from(payload.bytes.len()).ok()
                || record.get("sha512").and_then(Value::as_str)
                    != Some(sha512_hex(&payload.bytes).as_str())
            {
                return Err(
                    format!("candidate manifest identity mismatch for {}", spec.name).into(),
                );
            }
        }
        Ok(())
    }
}

fn write_new_file(path: &Path, bytes: &[u8], cap: usize) -> GeneratorResult<()> {
    if bytes.len() > cap {
        return Err(format!(
            "refusing to write {} bytes to {} with cap {cap}",
            bytes.len(),
            path.display()
        )
        .into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_capped_regular_file(path: &Path, cap: usize) -> GeneratorResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(format!("candidate path {} is not a regular file", path.display()).into());
    }
    if metadata.len() > u64::try_from(cap)? {
        return Err(format!("candidate path {} exceeds cap {cap}", path.display()).into());
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    file.take(u64::try_from(cap)? + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(format!("candidate path {} exceeds cap {cap}", path.display()).into());
    }
    Ok(bytes)
}

fn validate_staged_directory(staging: &Path, bundle: &CandidateBundle) -> GeneratorResult<()> {
    bundle.validate()?;
    let metadata = fs::symlink_metadata(staging)?;
    if !metadata.file_type().is_dir() {
        return Err(format!("staging path {} is not a directory", staging.display()).into());
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        if names.len() == CANDIDATE_FILE_COUNT {
            return Err("staging directory exceeds the five-file cap".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_: OsString| "staging directory contains a non-UTF-8 file name")?;
        spec_for(&name)?;
        if !names.insert(name) {
            return Err("staging directory contains a duplicate file name".into());
        }
    }
    let expected_names = FILE_SPECS
        .iter()
        .map(|spec| spec.name.to_owned())
        .collect::<BTreeSet<_>>();
    if names != expected_names {
        return Err("staging directory file set is not canonical".into());
    }
    let mut total_bytes = 0usize;
    for spec in FILE_SPECS {
        let bytes = read_capped_regular_file(&staging.join(spec.name), spec.max_bytes)?;
        if bytes != bundle.file(spec.name)?.bytes {
            return Err(format!("staged candidate file {} changed", spec.name).into());
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or("staged candidate byte count overflow")?;
    }
    if total_bytes > CANDIDATE_DIRECTORY_MAX_BYTES {
        return Err("staging directory exceeds the total byte cap".into());
    }
    Ok(())
}

fn create_staged_directory(parent: &Path, bundle: &CandidateBundle) -> GeneratorResult<PathBuf> {
    bundle.validate()?;
    let mut staging = None;
    for attempt in 0..128u16 {
        let candidate = parent.join(format!(
            ".wallet-retained-vectors-staging-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                staging = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let staging = staging.ok_or("could not allocate an exclusive staging directory")?;
    let result = (|| -> GeneratorResult<()> {
        for file in &bundle.files {
            write_new_file(
                &staging.join(file.name),
                &file.bytes,
                spec_for(file.name)?.max_bytes,
            )?;
        }
        File::open(&staging)?.sync_all()?;
        validate_staged_directory(&staging, bundle)
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    Ok(staging)
}

#[cfg(target_vendor = "apple")]
fn rename_directory_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    unsafe extern "C" {
        fn renamex_np(
            from: *const std::ffi::c_char,
            to: *const std::ffi::c_char,
            flags: u32,
        ) -> std::ffi::c_int;
    }

    const RENAME_EXCL: u32 = 0x0000_0004;
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // SAFETY: both pointers refer to live, NUL-terminated path buffers and the
    // flag is Apple's documented RENAME_EXCL no-replace operation.
    if unsafe { renamex_np(source.as_ptr(), destination.as_ptr(), RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_directory_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    unsafe extern "C" {
        fn renameat2(
            olddirfd: std::ffi::c_int,
            oldpath: *const std::ffi::c_char,
            newdirfd: std::ffi::c_int,
            newpath: *const std::ffi::c_char,
            flags: u32,
        ) -> std::ffi::c_int;
    }

    const AT_FDCWD: std::ffi::c_int = -100;
    const RENAME_NOREPLACE: u32 = 1;
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // SAFETY: both pointers refer to live, NUL-terminated path buffers and the
    // flags request Linux renameat2's atomic no-replace operation.
    if unsafe {
        renameat2(
            AT_FDCWD,
            source.as_ptr(),
            AT_FDCWD,
            destination.as_ptr(),
            RENAME_NOREPLACE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn rename_directory_noreplace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory publication is unsupported on this platform",
    ))
}

fn publish_staged_directory(
    staging: &Path,
    destination: &Path,
    bundle: &CandidateBundle,
) -> GeneratorResult<()> {
    validate_staged_directory(staging, bundle)?;
    require_absent_destination(destination)?;
    rename_directory_noreplace(staging, destination).map_err(|error| {
        format!(
            "refusing to replace candidate output root {}: {error}",
            destination.display()
        )
    })?;
    File::open(
        destination
            .parent()
            .ok_or("published candidate directory has no parent")?,
    )?
    .sync_all()?;
    Ok(())
}

fn publish_candidate_directory(
    destination: &Path,
    bundle: &CandidateBundle,
) -> GeneratorResult<()> {
    require_absent_destination(destination)?;
    let parent = destination
        .parent()
        .ok_or("candidate output root has no parent")?;
    let staging = create_staged_directory(parent, bundle)?;
    let result = publish_staged_directory(&staging, destination, bundle);
    if result.is_err() && path_entry_exists(&staging).unwrap_or(false) {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn opening(
    recipient_key: [u64; 4],
    authorization_key: [u64; 4],
    rho: [u64; 4],
    randomness: [u64; 4],
) -> Poseidon2V8CoinbaseNoteOpening {
    Poseidon2V8CoinbaseNoteOpening {
        value: VALUE,
        asset_id: 0,
        recipient_key,
        authorization_key,
        rho,
        randomness,
    }
}

fn main() -> GeneratorResult<()> {
    let args = Args::parse();
    let directory = resolve_candidate_destination(&args.output_root)?;
    // Reject before doing any wallet construction. The final no-replace rename
    // repeats this check atomically, so a concurrent publisher also loses
    // without replacing any bytes.
    require_absent_destination(&directory)?;

    let keys = RootSecret::from_bytes([0x51; 32]).derive();
    let material = keys.poseidon2_v8_address(9)?;
    let address = material.shielded_address();
    let spend_key = keys.spend.poseidon2_v8_words()?;
    let recipient_key = poseidon2_v8_words_from_canonical_bytes(address.pk_recipient)
        .map_err(|error| format!("recipient field decode: {error:?}"))?;
    let authorization_key = poseidon2_v8_words_from_canonical_bytes(address.pk_auth)
        .map_err(|error| format!("authorization field decode: {error:?}"))?;
    if authorization_key
        != poseidon2_v8_single_key_authorization_key(spend_key)
            .map_err(|error| format!("authorization derivation: {error:?}"))?
    {
        return Err("wallet authorization vector mismatch".into());
    }

    let coinbase_openings = [
        opening(
            recipient_key,
            authorization_key,
            [31, 32, 33, 34],
            [41, 42, 43, 44],
        ),
        opening(
            recipient_key,
            authorization_key,
            [51, 52, 53, 54],
            [61, 62, 63, 64],
        ),
    ];
    let mut coinbase_bytes = [Vec::new(), Vec::new()];
    // One deterministic stream covers every encrypted carrier in lifecycle
    // order: block-1 coinbase, block-2 coinbase, then the block-3 spend.
    let mut retained_rng = StdRng::seed_from_u64(301);
    for index in 0..2 {
        let args = build_poseidon2_v8_coinbase_args_from_opening(
            &address,
            coinbase_openings[index],
            &mut retained_rng,
        )?;
        if decrypt_poseidon2_v8_coinbase_opening(&args, &material)?
            != wallet::poseidon2_v8_coinbase::protocol_opening_to_relation(coinbase_openings[index])
        {
            return Err(format!("coinbase {index} wallet recovery mismatch").into());
        }
        coinbase_bytes[index] = args.encode();
    }

    // The retained output carriers are generated by the complete wallet
    // constructor itself. This prevents the fixture and the production wallet
    // path from silently implementing two different randomness schedules.
    let spend = build_poseidon2_v8_two_coinbase_self_spend(
        &RootSecret::from_bytes([0x51; 32]),
        9,
        [&coinbase_bytes[0], &coinbase_bytes[1]],
        2,
        [9, 9],
        &mut retained_rng,
    )?;
    let output_openings = spend.witness.outputs.map(|output| output.note);
    let output_bytes = spend.inline_ciphertexts.ciphertexts.map(|ciphertext| {
        ciphertext
            .expect("the retained maximum-shape spend has two active outputs")
            .to_vec()
    });
    for index in 0..2 {
        let note = output_openings[index];
        let expected = NotePlaintext {
            value: note.value,
            asset_id: note.asset_id,
            rho: transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_to_bytes(
                note.rho,
            ),
            r: transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_to_bytes(
                note.randomness,
            ),
            memo: MemoPlaintext::default(),
        };
        let recovered = NoteCiphertext::from_da_bytes(&output_bytes[index])?.decrypt(&material)?;
        if recovered != expected {
            return Err(format!("output {index} wallet recovery mismatch").into());
        }
    }

    let names = [
        "coinbase_0.scale",
        "coinbase_1.scale",
        "output_0.raw",
        "output_1.raw",
    ];
    let carriers = [
        &coinbase_bytes[0],
        &coinbase_bytes[1],
        &output_bytes[0],
        &output_bytes[1],
    ];
    let manifest = json!({
        "schema": MANIFEST_SCHEMA,
        "root_secret_hex": hex::encode([0x51; 32]),
        "address_index": 9,
        "spend_key_words": spend_key,
        "recipient_key_words": recipient_key,
        "authorization_key_words": authorization_key,
        "coinbase_opening_words": coinbase_openings.map(|opening| opening.note_hash_words()),
        "output_opening_words": output_openings.map(|note| Poseidon2V8CoinbaseNoteOpening {
            value: note.value,
            asset_id: note.asset_id,
            recipient_key: note.recipient_key,
            authorization_key: note.authorization_key,
            rho: note.rho,
            randomness: note.randomness,
        }.note_hash_words()),
        "spend_material": {
            "parent_height": 2,
            "statement_bytes": spend.statement.to_public_bytes().len(),
            "statement_sha512": sha512_hex(&spend.statement.to_public_bytes()),
            "witness_bytes": spend.witness.to_witness_bytes().len(),
            "witness_sha512": sha512_hex(&spend.witness.to_witness_bytes()),
            "inline_ciphertext_bytes": spend.inline_ciphertexts.to_inline_ciphertext_bytes().len(),
            "inline_ciphertext_sha512": sha512_hex(&spend.inline_ciphertexts.to_inline_ciphertext_bytes()),
        },
        "files": {
            "coinbase_0.scale": {"bytes": coinbase_bytes[0].len(), "sha512": sha512_hex(&coinbase_bytes[0])},
            "coinbase_1.scale": {"bytes": coinbase_bytes[1].len(), "sha512": sha512_hex(&coinbase_bytes[1])},
            "output_0.raw": {"bytes": output_bytes[0].len(), "sha512": sha512_hex(&output_bytes[0])},
            "output_1.raw": {"bytes": output_bytes[1].len(), "sha512": sha512_hex(&output_bytes[1])},
        },
    });
    let mut files = names
        .into_iter()
        .zip(carriers)
        .map(|(name, bytes)| CandidateFile {
            name,
            bytes: bytes.to_vec(),
        })
        .collect::<Vec<_>>();
    files.push(CandidateFile {
        name: "manifest.json",
        bytes: format!("{}\n", serde_json::to_string_pretty(&manifest)?).into_bytes(),
    });
    publish_candidate_directory(&directory, &CandidateBundle { files })?;
    println!("{}", directory.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn synthetic_bundle(marker: u8) -> CandidateBundle {
        let mut files = vec![
            CandidateFile {
                name: "coinbase_0.scale",
                bytes: vec![marker; POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES],
            },
            CandidateFile {
                name: "coinbase_1.scale",
                bytes: vec![marker.wrapping_add(1); POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES],
            },
            CandidateFile {
                name: "output_0.raw",
                bytes: vec![marker.wrapping_add(2); POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES],
            },
            CandidateFile {
                name: "output_1.raw",
                bytes: vec![marker.wrapping_add(3); POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES],
            },
        ];
        let records = files
            .iter()
            .map(|file| {
                (
                    file.name.to_owned(),
                    json!({
                        "bytes": file.bytes.len(),
                        "sha512": sha512_hex(&file.bytes),
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        files.push(CandidateFile {
            name: "manifest.json",
            bytes: format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({
                    "schema": MANIFEST_SCHEMA,
                    "files": records,
                }))
                .unwrap()
            )
            .into_bytes(),
        });
        CandidateBundle { files }
    }

    #[test]
    fn cli_requires_an_explicit_candidate_output_root() {
        assert!(Args::try_parse_from(["generator"]).is_err());
        assert_eq!(
            Args::try_parse_from(["generator", "--output-root", "candidate"])
                .unwrap()
                .output_root,
            PathBuf::from("candidate")
        );
    }

    #[test]
    fn canonical_vector_directory_is_never_a_candidate_destination() {
        let canonical = canonical_vector_directory();
        let probe = canonical.join(format!(
            ".wallet-generator-rejection-probe-{}",
            std::process::id()
        ));
        assert!(!path_entry_exists(&probe).unwrap());
        let error = resolve_candidate_destination(&probe.join("candidate")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refusing to write in canonical retained-vector directory"),
            "{error}"
        );
        assert!(!path_entry_exists(&probe).unwrap());
    }

    #[test]
    fn parent_traversal_rejects_before_creating_a_parent() {
        let temp = tempdir().unwrap();
        let missing = temp.path().join("must-not-be-created");
        let requested = missing.join("..").join("candidate");
        let error = resolve_candidate_destination(&requested).unwrap_err();
        assert!(error.to_string().contains("parent traversal"), "{error}");
        assert!(!path_entry_exists(&missing).unwrap());
    }

    #[test]
    fn missing_parent_is_not_created_implicitly() {
        let temp = tempdir().unwrap();
        let missing = temp.path().join("must-not-be-created");
        let error = resolve_candidate_destination(&missing.join("candidate")).unwrap_err();
        assert!(error.to_string().contains("must already exist"), "{error}");
        assert!(!path_entry_exists(&missing).unwrap());
    }

    #[test]
    fn atomic_publication_refuses_to_replace_an_existing_candidate() {
        let temp = tempdir().unwrap();
        let destination = resolve_candidate_destination(&temp.path().join("candidate")).unwrap();
        let original = synthetic_bundle(11);
        publish_candidate_directory(&destination, &original).unwrap();
        let original_coinbase = fs::read(destination.join("coinbase_0.scale")).unwrap();

        let replacement = synthetic_bundle(91);
        let error = publish_candidate_directory(&destination, &replacement).unwrap_err();
        assert!(
            error.to_string().contains("refusing to overwrite"),
            "{error}"
        );
        assert_eq!(
            fs::read(destination.join("coinbase_0.scale")).unwrap(),
            original_coinbase
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_publishers_leave_one_complete_candidate() {
        let temp = tempdir().unwrap();
        let destination =
            Arc::new(resolve_candidate_destination(&temp.path().join("candidate")).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let first_bundle = synthetic_bundle(31);
        let second_bundle = synthetic_bundle(71);

        let spawn_publisher = |bundle: CandidateBundle| {
            let destination = Arc::clone(&destination);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                publish_candidate_directory(&destination, &bundle)
                    .map_err(|error| error.to_string())
            })
        };
        let first = spawn_publisher(first_bundle.clone());
        let second = spawn_publisher(second_bundle.clone());
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(
            validate_staged_directory(&destination, &first_bundle).is_ok()
                || validate_staged_directory(&destination, &second_bundle).is_ok()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn staged_byte_mutation_rejects_before_publication() {
        let temp = tempdir().unwrap();
        let destination = resolve_candidate_destination(&temp.path().join("candidate")).unwrap();
        let bundle = synthetic_bundle(17);
        let staging = create_staged_directory(temp.path(), &bundle).unwrap();
        let path = staging.join("output_0.raw");
        let mut mutated = fs::read(&path).unwrap();
        mutated[0] ^= 1;
        fs::write(&path, mutated).unwrap();

        let error = publish_staged_directory(&staging, &destination, &bundle).unwrap_err();
        assert!(error.to_string().contains("changed"), "{error}");
        assert!(!path_entry_exists(&destination).unwrap());
        fs::remove_dir_all(staging).unwrap();
    }

    #[test]
    fn oversized_candidate_rejects_before_staging() {
        let temp = tempdir().unwrap();
        let destination = resolve_candidate_destination(&temp.path().join("candidate")).unwrap();
        let mut bundle = synthetic_bundle(23);
        bundle.file("manifest.json").unwrap();
        bundle
            .files
            .iter_mut()
            .find(|file| file.name == "manifest.json")
            .unwrap()
            .bytes = vec![b' '; MANIFEST_MAX_BYTES + 1];

        let error = publish_candidate_directory(&destination, &bundle).unwrap_err();
        assert!(error.to_string().contains("cap"), "{error}");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}
