//! Explicitly selected archive custodian, with a bounded private process protocol.
//! Material30 is recoverable output data, not a holder/issuer/delegate action key.
//! This adapter never treats a provider receipt as a capsule proof.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use transaction_circuit::{
    asset_recovery_capsule_v1 as capsule, asset_recovery_v1 as core, asset_recovery_wire_v1 as wire,
};
use wallet::{
    asset_recovery_build_v1::{
        ArchiveCapsuleProviderV1, ArchiveCapsuleRequestV1, CapsuleTransportV1,
        LocalArchiveProviderV1,
    },
    asset_recovery_v1::{
        operator::{Zeroize, Zeroizing},
        RecoveryNoteContextV1, RecoveryNoteMaterialV1,
    },
    WalletError,
};

const SCHEMA: &str = "hegemon.recovery.archive-provider.v1";
const METHOD: &str = "recovery.archiveProve";
const REQUEST_CAP: usize = 16 * 1024;
const RESPONSE_CAP: usize = 2 * wire::MAX_CAPSULE_BUNDLE_BYTES + 4096;
const DEFAULT_TIMEOUT_SECONDS: u64 = 600;
const MAX_TIMEOUT_SECONDS: u64 = 1800;

fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessArchiveProviderSpec {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}
impl ProcessArchiveProviderSpec {
    pub fn validate(&self) -> Result<(), WalletError> {
        if !Path::new(&self.executable).is_absolute()
            || self.executable.contains('\0')
            || self.executable.len() > 4096
            || self.args.len() > 32
            || self.args.iter().any(|s| s.len() > 4096 || s.contains('\0'))
            || self.args.iter().map(String::len).sum::<usize>() > 16 * 1024
            || !(1..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds)
        {
            return Err(invalid("invalid archive provider executable/args/timeout"));
        }
        #[cfg(not(unix))]
        return Err(invalid(
            "process archive providers require Unix standard streams",
        ));
        #[cfg(unix)]
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    asset_id: u32,
    stable_policy_id: [u64; 7],
    policy_admin_commitment: [u64; 7],
    archive_key_commitment: [u64; 7],
    maximum_transfer: bool,
    maximum_burn: bool,
}
impl Descriptor {
    fn typed(&self) -> core::RecoveryDescriptorV1 {
        core::RecoveryDescriptorV1 {
            asset_id: self.asset_id,
            stable_policy_id: self.stable_policy_id,
            policy_admin_commitment: self.policy_admin_commitment,
            archive_key_commitment: self.archive_key_commitment,
            maximum_powers: core::RecoveryPowersV1 {
                transfer: self.maximum_transfer,
                burn: self.maximum_burn,
            },
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    chain_id: [u8; 32],
    asset_id: u32,
    stable_policy_id: [u64; 7],
    output_commitment: [u64; 7],
}
impl Context {
    fn typed(&self) -> RecoveryNoteContextV1 {
        RecoveryNoteContextV1 {
            chain_id: self.chain_id,
            asset_id: self.asset_id,
            stable_policy_id: self.stable_policy_id,
            output_commitment: self.output_commitment,
        }
    }
}
// Do not add Debug, generic request envelopes, action witnesses, or secret keys.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    schema: String,
    method: String,
    descriptor: Descriptor,
    context: Context,
    material: [u64; 30],
}
impl Drop for WorkerRequest {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}
impl WorkerRequest {
    fn from_trusted(request: &ArchiveCapsuleRequestV1<'_>) -> Result<Self, WalletError> {
        request
            .descriptor
            .validate()
            .map_err(|_| invalid("archive descriptor"))?;
        let words = request.material.material_words(&request.context)?;
        let d = request.descriptor;
        let c = request.context;
        let result = Self {
            schema: SCHEMA.into(),
            method: METHOD.into(),
            descriptor: Descriptor {
                asset_id: d.asset_id,
                stable_policy_id: d.stable_policy_id,
                policy_admin_commitment: d.policy_admin_commitment,
                archive_key_commitment: d.archive_key_commitment,
                maximum_transfer: d.maximum_powers.transfer,
                maximum_burn: d.maximum_powers.burn,
            },
            context: Context {
                chain_id: c.chain_id,
                asset_id: c.asset_id,
                stable_policy_id: c.stable_policy_id,
                output_commitment: c.output_commitment,
            },
            material: *words,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<RecoveryNoteMaterialV1, WalletError> {
        if self.schema != SCHEMA || self.method != METHOD {
            return Err(invalid("archive protocol version/method"));
        }
        let descriptor = self.descriptor.typed();
        descriptor
            .validate()
            .map_err(|_| invalid("archive descriptor"))?;
        let context = self.context.typed();
        if descriptor.asset_id != context.asset_id
            || descriptor.stable_policy_id != context.stable_policy_id
        {
            return Err(invalid("archive descriptor/context mismatch"));
        }
        RecoveryNoteMaterialV1::from_material_words(&self.material, &context)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponse {
    schema: String,
    public_words: Vec<u64>,
    proof_hex: String,
}
fn parse_response(
    request: &ArchiveCapsuleRequestV1<'_>,
    bytes: &[u8],
) -> Result<CapsuleTransportV1, WalletError> {
    if bytes.len() > RESPONSE_CAP {
        return Err(invalid("archive response exceeds finite cap"));
    }
    let response: WorkerResponse =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid archive response protocol"))?;
    if response.schema != SCHEMA
        || response.public_words.len() != capsule::PUBLIC_WORDS
        || response.proof_hex.len() > 2 * wire::MAX_CAPSULE_BUNDLE_BYTES
        || response.proof_hex.is_empty()
    {
        return Err(invalid("archive response version/shape"));
    }
    let words = response
        .public_words
        .try_into()
        .map_err(|_| invalid("archive public width"))?;
    let public =
        wire::decode_capsule_public(&words).map_err(|_| invalid("archive public encoding"))?;
    let proof = hex::decode(&response.proof_hex).map_err(|_| invalid("archive proof encoding"))?;
    if hex::encode(&proof) != response.proof_hex {
        return Err(invalid("archive proof must be canonical lowercase hex"));
    }
    // Authenticate against the ORIGINAL request, not provider-returned context.
    CapsuleTransportV1::from_untrusted(request, public, proof)
}

pub(super) struct ProcessArchiveProviderV1(ProcessArchiveProviderSpec);
impl ProcessArchiveProviderV1 {
    pub fn new(spec: ProcessArchiveProviderSpec) -> Result<Self, WalletError> {
        spec.validate()?;
        Ok(Self(spec))
    }
}
impl ArchiveCapsuleProviderV1 for ProcessArchiveProviderV1 {
    fn create_capsule(
        &mut self,
        request: &ArchiveCapsuleRequestV1<'_>,
    ) -> Result<CapsuleTransportV1, WalletError> {
        let dto = WorkerRequest::from_trusted(request)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&dto).map_err(|_| invalid("archive request encoding"))?,
        );
        if bytes.len() > REQUEST_CAP {
            return Err(invalid("archive request exceeds finite cap"));
        }
        let response = process_exchange(&self.0, &bytes, RESPONSE_CAP)?;
        parse_response(request, &response)
    }
}

// Timeout-enabled Unix socket pairs back private stdin/stdout. This is std-only
// and permits bounded cancellation even if a child leaves a stream inherited by
// a descendant. No new process group: the resource guard retains its PGID.
#[cfg(unix)]
fn process_exchange(
    spec: &ProcessArchiveProviderSpec,
    request: &[u8],
    response_cap: usize,
) -> Result<Vec<u8>, WalletError> {
    use std::{
        net::Shutdown,
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread,
    };
    spec.validate()?;
    if request.len() > REQUEST_CAP {
        return Err(invalid("archive request exceeds finite cap"));
    }
    let (mut input, child_input) =
        UnixStream::pair().map_err(|_| invalid("archive private stdin unavailable"))?;
    let (mut output, child_output) =
        UnixStream::pair().map_err(|_| invalid("archive private stdout unavailable"))?;
    input
        .set_write_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| invalid("archive stdin timeout unavailable"))?;
    output
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|_| invalid("archive stdout timeout unavailable"))?;
    // The provider is selected explicitly by the operator. Do not inherit other
    // wallet/agent credentials, proof tracing, or an executable search path.
    let child = Command::new(&spec.executable)
        .args(&spec.args)
        .env_clear()
        .env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::from(OwnedFd::from(child_input)))
        .stdout(Stdio::from(OwnedFd::from(child_output)))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| invalid("archive provider could not start"))?;
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(child);
    let cancel = Arc::new(AtomicBool::new(false));
    let reader_cancel = Arc::clone(&cancel);
    let (send, receive) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        let result = loop {
            if reader_cancel.load(Ordering::Relaxed) {
                break Err(invalid("archive provider cancelled"));
            }
            match output.read(&mut chunk) {
                Ok(0) => break Ok(bytes),
                Ok(n) => {
                    if bytes.len().saturating_add(n) > response_cap {
                        break Err(invalid("archive response exceeds finite cap"));
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
                Err(_) => break Err(invalid("archive provider stdout failed")),
            }
        };
        let _ = send.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    // After spawn, every exit goes through this cleanup path (including writes,
    // reader errors, exit-status failures, and response deadlines).
    let result = (|| {
        let mut sent = 0;
        while sent < request.len() {
            if Instant::now() >= deadline {
                return Err(invalid("archive provider response timeout"));
            }
            match input.write(&request[sent..]) {
                Ok(0) => return Err(invalid("archive provider stdin closed")),
                Ok(n) => sent += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
                Err(_) => return Err(invalid("archive provider stdin failed")),
            }
        }
        input
            .shutdown(Shutdown::Write)
            .map_err(|_| invalid("archive provider stdin close failed"))?;
        let mut response = None;
        loop {
            if Instant::now() >= deadline {
                return Err(invalid("archive provider response timeout"));
            }
            if response.is_none() {
                match receive.try_recv() {
                    Ok(value) => response = Some(value?),
                    Err(mpsc::TryRecvError::Empty) => (),
                    Err(_) => return Err(invalid("archive provider reader failed")),
                }
            }
            match child.0.try_wait() {
                Ok(Some(status)) if !status.success() => {
                    return Err(invalid("archive provider failed"));
                }
                Ok(Some(_)) if response.is_some() => return Ok(response.take().unwrap()),
                Ok(_) => (),
                Err(_) => return Err(invalid("archive provider status failed")),
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    cancel.store(true, Ordering::Relaxed);
    let _ = input.shutdown(Shutdown::Both);
    drop(child); // kill and reap the directly owned child on ALL paths
    let joined = reader.join(); // read timeout/cancel bounds this, even for inherited FDs
    if joined.is_err() {
        return Err(invalid("archive provider reader failed"));
    }
    result
}
#[cfg(not(unix))]
fn process_exchange(
    _: &ProcessArchiveProviderSpec,
    _: &[u8],
    _: usize,
) -> Result<Vec<u8>, WalletError> {
    Err(invalid(
        "process archive providers require Unix standard streams",
    ))
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let before =
        std::fs::symlink_metadata(path).map_err(|_| invalid("archive key file unavailable"))?;
    if !before.file_type().is_file() {
        return Err(invalid("archive key must be a regular private file"));
    }
    let file = std::fs::File::open(path).map_err(|_| invalid("archive key file unavailable"))?;
    let opened = file
        .metadata()
        .map_err(|_| invalid("archive key metadata unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !opened.is_file()
            || opened.permissions().mode() & 0o7777 != 0o600
            || before.dev() != opened.dev()
            || before.ino() != opened.ino()
        {
            return Err(invalid(
                "archive key must be an unchanged mode0600 regular file",
            ));
        }
    }
    #[cfg(not(unix))]
    return Err(invalid("archive worker key permissions require Unix"));
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("archive key read failed"))?;
    if bytes.len() != 32 {
        return Err(invalid("archive key file must contain exactly32 raw bytes"));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Worker configuration is an operator argument, never part of the holder DTO.
pub(super) fn worker(key_file: &Path) -> Result<(), WalletError> {
    let key = read_key(key_file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take((REQUEST_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("archive request read failed"))?;
    if bytes.len() > REQUEST_CAP {
        return Err(invalid("archive request exceeds finite cap"));
    }
    let dto: WorkerRequest =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid archive request protocol"))?;
    let transport = prove_worker_request(&dto, key)?;
    let response = WorkerResponse {
        schema: SCHEMA.into(),
        public_words: transport
            .public_statement()
            .words()
            .map_err(|_| invalid("archive public encoding"))?
            .to_vec(),
        proof_hex: hex::encode(transport.proof_bytes()),
    };
    let bytes = serde_json::to_vec(&response).map_err(|_| invalid("archive response encoding"))?;
    if bytes.len() > RESPONSE_CAP {
        return Err(invalid("archive response exceeds finite cap"));
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| invalid("archive response write failed"))
}
fn prove_worker_request(
    dto: &WorkerRequest,
    key: Zeroizing<[u8; 32]>,
) -> Result<CapsuleTransportV1, WalletError> {
    let material = dto.validate()?;
    let descriptor = dto.descriptor.typed();
    if core::archive_key_commitment(&key).map_err(|_| invalid("archive key commitment failed"))?
        != descriptor.archive_key_commitment
    {
        return Err(invalid("archive worker key does not match descriptor"));
    }
    let request = ArchiveCapsuleRequestV1 {
        descriptor: &descriptor,
        context: dto.context.typed(),
        material: &material,
    };
    let mut provider = LocalArchiveProviderV1::new(key);
    provider.create_capsule(&request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wallet::asset_recovery_build_v1 as build;

    fn fixture() -> (
        core::RecoveryDescriptorV1,
        RecoveryNoteMaterialV1,
        RecoveryNoteContextV1,
    ) {
        let descriptor = core::RecoveryDescriptorV1 {
            asset_id: 17,
            stable_policy_id: [5; 7],
            policy_admin_commitment: [7; 7],
            archive_key_commitment: core::archive_key_commitment(&[3; 32]).unwrap(),
            maximum_powers: core::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let material = build::new_recovery_output_os(
            [8; 32],
            17,
            descriptor.stable_policy_id,
            10,
            [2; 4],
            [9; 7],
        )
        .unwrap();
        let context = RecoveryNoteContextV1 {
            chain_id: [8; 32],
            asset_id: 17,
            stable_policy_id: descriptor.stable_policy_id,
            output_commitment: transaction_circuit::private_spend::note_commitment(
                material.as_note(),
            )
            .unwrap(),
        };
        (descriptor, material, context)
    }

    #[test]
    fn archive_request_excludes_action_secrets_and_binds_material_context() {
        let (descriptor, material, context) = fixture();
        let request = ArchiveCapsuleRequestV1 {
            descriptor: &descriptor,
            context,
            material: &material,
        };
        let dto = WorkerRequest::from_trusted(&request).unwrap();
        let value = serde_json::to_value(&dto).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["material"][25], material.shared_nf_key[0]);
        fn contains_key(value: &serde_json::Value, name: &str) -> bool {
            match value {
                serde_json::Value::Object(fields) => fields
                    .iter()
                    .any(|(key, value)| key == name || contains_key(value, name)),
                serde_json::Value::Array(values) => {
                    values.iter().any(|value| contains_key(value, name))
                }
                _ => false,
            }
        }
        for field in [
            "archive_key",
            "issuer_secret",
            "delegate_secret",
            "admin_secret",
            "spend_key",
        ] {
            assert!(!contains_key(&value, field));
            let mut extra = value.clone();
            extra[field] = json!(vec![1; 7]);
            assert!(serde_json::from_value::<WorkerRequest>(extra).is_err());
        }
        assert!(dto.validate().is_ok());
        let zero_material = build::new_recovery_output_os(
            context.chain_id,
            descriptor.asset_id,
            descriptor.stable_policy_id,
            0,
            [2; 4],
            [9; 7],
        )
        .unwrap();
        let zero_context = RecoveryNoteContextV1 {
            output_commitment: transaction_circuit::private_spend::note_commitment(
                zero_material.as_note(),
            )
            .unwrap(),
            ..context
        };
        let zero_request = ArchiveCapsuleRequestV1 {
            descriptor: &descriptor,
            context: zero_context,
            material: &zero_material,
        };
        let zero_dto = WorkerRequest::from_trusted(&zero_request).unwrap();
        assert_eq!(zero_dto.material[0], 0);
        assert!(zero_dto.validate().is_ok());
        for key in ["schema", "method"] {
            let mut bad = value.clone();
            bad[key] = json!("different-protocol");
            assert!(serde_json::from_value::<WorkerRequest>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        for (part, field) in [("context", "asset_id"), ("descriptor", "asset_id")] {
            let mut bad = value.clone();
            bad[part][field] = json!(18);
            assert!(serde_json::from_value::<WorkerRequest>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        for slot in [0, 14, 18, 25] {
            let mut bad = WorkerRequest::from_trusted(&request).unwrap();
            bad.material[slot] ^= 1;
            assert!(bad.validate().is_err());
        }
        let mut bad = WorkerRequest::from_trusted(&request).unwrap();
        bad.material[25] = 0xffff_ffff_0000_0001;
        assert!(bad.validate().is_err());
        assert!(prove_worker_request(&dto, Zeroizing::new([4; 32])).is_err());
    }

    #[test]
    fn archive_untrusted_response_requires_binding_and_actual_proof() {
        let (descriptor, material, context) = fixture();
        let request = ArchiveCapsuleRequestV1 {
            descriptor: &descriptor,
            context,
            material: &material,
        };
        let words = material.material_words(&context).unwrap();
        let mut public = capsule::encrypt(
            context.chain_id,
            context.asset_id,
            context.stable_policy_id,
            &[3; 32],
            &words,
        )
        .unwrap();
        let response = |p: &capsule::AssetRecoveryCapsulePublicV1| {
            json!({
                "schema": SCHEMA, "public_words": p.words().unwrap().to_vec(), "proof_hex":"00"
            })
        };
        // A well-shaped real encryption with a fake proof is never accepted.
        let base = response(&public);
        let error = parse_response(&request, &serde_json::to_vec(&base).unwrap())
            .err()
            .unwrap();
        assert!(error.to_string().contains("capsule proof rejected"));
        public.chain_id[0] ^= 1;
        assert!(
            parse_response(&request, &serde_json::to_vec(&response(&public)).unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("response binding")
        );
        public.chain_id = context.chain_id;
        public.note_commitment = if context.output_commitment == [1; 7] {
            [2; 7]
        } else {
            [1; 7]
        };
        assert!(
            parse_response(&request, &serde_json::to_vec(&response(&public)).unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("response binding")
        );
        let mut extra = base.clone();
        extra["archive_key"] = json!("not-permitted");
        assert!(parse_response(&request, &serde_json::to_vec(&extra).unwrap()).is_err());
        let mut wrong = base.clone();
        wrong["schema"] = json!("v2");
        assert!(parse_response(&request, &serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut wrong = base.clone();
        wrong["public_words"][0] = json!(u64::MAX);
        assert!(parse_response(&request, &serde_json::to_vec(&wrong).unwrap()).is_err());
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("proof_hex");
        assert!(parse_response(&request, &serde_json::to_vec(&missing).unwrap()).is_err());
        let mut short = base.clone();
        short["public_words"] = json!(vec![1u64; capsule::PUBLIC_WORDS - 1]);
        assert!(parse_response(&request, &serde_json::to_vec(&short).unwrap()).is_err());
        let mut uppercase = base.clone();
        uppercase["proof_hex"] = json!("AA");
        assert!(
            parse_response(&request, &serde_json::to_vec(&uppercase).unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("canonical lowercase")
        );
        let mut trailing = serde_json::to_vec(&base).unwrap();
        trailing.extend_from_slice(b"{}");
        assert!(parse_response(&request, &trailing).is_err());
        assert!(parse_response(&request, &vec![b' '; RESPONSE_CAP + 1]).is_err());
    }

    #[test]
    fn archive_provider_spec_has_finite_explicit_executable_contract() {
        let make = |executable: &str, timeout: u64| ProcessArchiveProviderSpec {
            executable: executable.into(),
            args: vec![],
            timeout_seconds: timeout,
        };
        assert!(make("walletd", 1).validate().is_err());
        assert!(make("/private/walletd", 0).validate().is_err());
        assert!(make("/private/walletd", MAX_TIMEOUT_SECONDS + 1)
            .validate()
            .is_err());
        assert!(serde_json::from_value::<ProcessArchiveProviderSpec>(json!({
            "executable":"/private/walletd", "shell":true
        }))
        .is_err());
        #[cfg(unix)]
        assert!(make("/private/walletd", DEFAULT_TIMEOUT_SECONDS)
            .validate()
            .is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn archive_key_file_is_exact_private_regular_and_symlink_free() {
        use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "walletd-archive-key-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("key");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        f.write_all(&[3; 32]).unwrap();
        drop(f);
        assert_eq!(*read_key(&path).unwrap(), [3; 32]);
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_key(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [3; 33]).unwrap();
        assert!(read_key(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // This subprocess fixture exercises transport only. Its bytes cannot pass
    // parse_response/from_untrusted and are never represented as a valid proof.
    #[cfg(unix)]
    #[test]
    #[ignore = "invoked only as a subprocess by archive_process_transport_bounds_and_cleanup"]
    fn provider_child_transport_fixture() {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        match input.as_str() {
            "WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:large" => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&vec![b'x'; 3_500_000]).unwrap();
                stdout.flush().unwrap();
                std::process::exit(0);
            }
            "WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:hang" => {
                std::thread::sleep(Duration::from_secs(30));
                std::process::exit(0);
            }
            "WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:fail" => {
                eprintln!("PRIVATE_PROVIDER_DIAGNOSTIC_CANARY");
                println!("PRIVATE_PROVIDER_OUTPUT_CANARY");
                std::process::exit(7);
            }
            _ => panic!("transport fixture is not an operator method"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_process_transport_bounds_and_cleanup() {
        let spec = ProcessArchiveProviderSpec {
            executable: std::env::current_exe().unwrap().to_str().unwrap().into(),
            args: vec![
                "--exact".into(),
                "recovery_archive_process::tests::provider_child_transport_fixture".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            timeout_seconds: 10,
        };
        let output = process_exchange(
            &spec,
            b"WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:large",
            4_000_000,
        )
        .unwrap();
        assert!(output.len() >= 3_500_000);
        assert!(output.ends_with(&[b'x'; 128]));
        assert!(
            process_exchange(&spec, b"WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:large", 1024)
                .err()
                .unwrap()
                .to_string()
                .contains("finite cap")
        );
        let failed = process_exchange(&spec, b"WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:fail", 4096)
            .err()
            .unwrap()
            .to_string();
        assert!(!failed.contains("PRIVATE_PROVIDER"));
        assert!(failed.contains("provider failed"));
        let short = ProcessArchiveProviderSpec {
            timeout_seconds: 1,
            ..spec
        };
        let start = Instant::now();
        assert!(
            process_exchange(&short, b"WALLETD_ARCHIVE_PROCESS_FIXTURE_V1:hang", 4096)
                .err()
                .unwrap()
                .to_string()
                .contains("timeout")
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
