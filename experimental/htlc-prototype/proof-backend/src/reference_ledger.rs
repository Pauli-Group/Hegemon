//! Bounded local host admission, not consensus state or a proof verifier.
//!
//! Cooperating processes hold an OS exclusive lock on the journal itself from
//! open through drop. Only public admission records are persisted. The caller
//! owns/trusts the local path and must supply an externally authenticated chain
//! adapter. Corruption is rejected; crash repair, reorg, hostile filesystem
//! writers, removal of whole valid record suffixes and distributed consensus
//! are deliberately outside this experiment. There is no external trusted head
//! with which to detect complete-record rollback.

use crate::authorization::MlDsaAuthorizer;
use htlc_prototype::{
    hashlock::Sha256Hashlock,
    relation::{
        check_spend, AuthenticatedChain, Branch, ChainError, Context, Digest, LockedNote,
        RelationError, SpendStatement, SpendWitness, ValidatedSpend,
    },
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const HEADER: &[u8; 16] = b"HHTLCJOURNALv001";
const BODY_BYTES: usize = 177;
pub const RECORD_BYTES: usize = BODY_BYTES + 32;
pub const MAX_RECORDS: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("journal is busy: another process holds the admission lock")]
    Busy,
    #[error("journal is damaged or not a canonical public admission stream")]
    Damaged,
    #[error("journal record limit must be between 1 and {MAX_RECORDS}")]
    InvalidLimit,
    #[error("journal record limit exhausted")]
    Full,
    #[error("journal writer is poisoned by an uncertain append; reopen and inspect externally")]
    Poisoned,
    #[error("host relation rejected spend: {0:?}")]
    Relation(RelationError),
    #[error("journal I/O: {0}")]
    Io(#[from] io::Error),
}

pub struct ReferenceLedger {
    file: File,
    records: Vec<ValidatedSpend>,
    spent: HashSet<Digest>,
    last_checksum: Digest,
    record_limit: usize,
    poisoned: bool,
}

impl ReferenceLedger {
    /// Create a new journal or strictly reload an existing one. Lock contention
    /// fails immediately; dropping this object releases the process-level lock.
    /// Existing empty and partial-record journals fail, never auto-initialize.
    pub fn open(path: &Path, record_limit: usize) -> Result<Self, LedgerError> {
        if !(1..=MAX_RECORDS).contains(&record_limit) {
            return Err(LedgerError::InvalidLimit);
        }
        let options = |create_new| {
            let mut options = OpenOptions::new();
            options.read(true).append(true).create_new(create_new);
            options
        };
        let (mut file, created) = match options(true).open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                (options(false).open(path)?, false)
            }
            Err(error) => return Err(error.into()),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LedgerError::Busy),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        if !file.metadata()?.is_file() {
            return Err(LedgerError::Damaged);
        }
        if created {
            if file.metadata()?.len() != 0 {
                return Err(LedgerError::Damaged);
            }
            file.write_all(HEADER)?;
            file.sync_all()?;
        }
        let length = usize::try_from(file.metadata()?.len()).map_err(|_| LedgerError::Damaged)?;
        let max_bytes = HEADER.len() + record_limit * RECORD_BYTES;
        if length < HEADER.len()
            || length > max_bytes
            || (length - HEADER.len()) % RECORD_BYTES != 0
        {
            return Err(LedgerError::Damaged);
        }
        file.seek(SeekFrom::Start(0))?;
        // Read at most the measured bound + one byte: a non-cooperating writer
        // cannot turn read_to_end into an unbounded allocation.
        let mut bytes = Vec::with_capacity(length);
        (&mut file)
            .take((length + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() != length || bytes[..HEADER.len()] != HEADER[..] {
            return Err(LedgerError::Damaged);
        }
        let mut records = Vec::new();
        let mut spent = HashSet::new();
        let mut last_checksum = [0; 32];
        for (index, encoded) in bytes[HEADER.len()..].chunks_exact(RECORD_BYTES).enumerate() {
            let (record, checksum) = decode_record(encoded, index as u64 + 1, &last_checksum)?;
            if !spent.insert(record.nullifier) {
                return Err(LedgerError::Damaged);
            }
            records.push(record);
            last_checksum = checksum;
        }
        // Repeat the directory barrier on existing files as well: a prior
        // failed creation barrier may have left a syntactically valid header.
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        File::open(parent.unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(Self {
            file,
            records,
            spent,
            last_checksum,
            record_limit,
            poisoned: false,
        })
    }

    pub fn records(&self) -> &[ValidatedSpend] {
        &self.records
    }

    /// Check the host relation and append/fsync a public record under the same
    /// lock as the unspent check. Signature, height and SHA host checks are not
    /// ZK proof verification. An I/O error can leave an uncertain append; this
    /// handle then refuses every subsequent admission without attempting repair.
    pub fn admit(
        &mut self,
        circuit: &Sha256Hashlock,
        note: &LockedNote,
        statement: &SpendStatement,
        witness: SpendWitness<'_>,
        chain: &impl AuthenticatedChain,
        authorizer: &MlDsaAuthorizer,
    ) -> Result<ValidatedSpend, LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let expected_length = HEADER.len() + self.records.len() * RECORD_BYTES;
        if self.file.metadata()?.len() != expected_length as u64 {
            self.poisoned = true;
            return Err(LedgerError::Damaged);
        }
        if self.records.len() == self.record_limit {
            return Err(LedgerError::Full);
        }
        let chain = UnspentChain {
            external: chain,
            spent: &self.spent,
        };
        let accepted = check_spend(circuit, note, statement, witness, &chain, authorizer)
            .map_err(LedgerError::Relation)?;
        let encoded = encode_record(
            &accepted,
            self.records.len() as u64 + 1,
            &self.last_checksum,
        );
        if let Err(error) = self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(error.into());
        }
        self.last_checksum.copy_from_slice(&encoded[BODY_BYTES..]);
        self.spent.insert(accepted.nullifier);
        self.records.push(accepted);
        Ok(accepted)
    }
}

struct UnspentChain<'a, C> {
    external: &'a C,
    spent: &'a HashSet<Digest>,
}

impl<C: AuthenticatedChain> AuthenticatedChain for UnspentChain<'_, C> {
    fn validate_locked_note(
        &self,
        commitment: &Digest,
        nullifier: &Digest,
    ) -> Result<Context, ChainError> {
        if self.spent.contains(nullifier) {
            return Err(ChainError::AlreadySpent);
        }
        self.external.validate_locked_note(commitment, nullifier)
    }
}

fn checksum(body: &[u8], previous: &Digest) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"hegemon-experimental-htlc-admission-journal-v1");
    hash.update(previous);
    hash.update(body);
    hash.finalize().into()
}

fn encode_record(record: &ValidatedSpend, sequence: u64, previous: &Digest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&record.note_commitment);
    bytes.extend_from_slice(&record.nullifier);
    bytes.push(match record.branch {
        Branch::Claim => 0,
        Branch::Refund => 1,
    });
    bytes.extend_from_slice(&record.intent_commitment);
    bytes.extend_from_slice(&record.context.network_id);
    bytes.extend_from_slice(&record.context.parent_hash);
    bytes.extend_from_slice(&record.context.parent_height.to_le_bytes());
    let digest = checksum(&bytes, previous);
    bytes.extend_from_slice(&digest);
    bytes
}

fn decode_record(
    bytes: &[u8],
    sequence: u64,
    previous: &Digest,
) -> Result<(ValidatedSpend, Digest), LedgerError> {
    let read_u64 = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let digest = |offset| -> Digest { bytes[offset..offset + 32].try_into().unwrap() };
    let actual_checksum = checksum(&bytes[..BODY_BYTES], previous);
    if read_u64(0) != sequence || digest(BODY_BYTES) != actual_checksum {
        return Err(LedgerError::Damaged);
    }
    let branch = match bytes[72] {
        0 => Branch::Claim,
        1 => Branch::Refund,
        _ => return Err(LedgerError::Damaged),
    };
    Ok((
        ValidatedSpend {
            note_commitment: digest(8),
            nullifier: digest(40),
            branch,
            intent_commitment: digest(73),
            context: Context {
                network_id: digest(105),
                parent_hash: digest(137),
                parent_height: read_u64(169),
            },
        },
        actual_checksum,
    ))
}
