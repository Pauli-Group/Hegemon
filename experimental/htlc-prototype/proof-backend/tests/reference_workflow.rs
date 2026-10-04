use hegemon_isolated_htlc_smallwood::{
    authorization::{authority, sign_authorization, MlDsaAuthorizer, AUTHORIZATION_BYTES},
    reference_ledger::{LedgerError, ReferenceLedger, MAX_RECORDS, RECORD_BYTES},
};
use htlc_prototype::{
    hashlock::Sha256Hashlock,
    relation::{
        authorization_message, AuthenticatedChain, Authorizer, Branch, ChainError, Context, Digest,
        LockedNote, RelationError, SpendIntent, SpendStatement, SpendWitness, POLICY_VERSION,
    },
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
use synthetic_crypto::{
    ml_dsa::MlDsaSecretKey,
    traits::{SigningKey, VerifyKey},
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hegemon-htlc-host-test-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("public.journal")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // Exactly this test's fresh private temp directory; no retained evidence.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// Explicit local test double; no consensus authentication is provided here.
#[derive(Clone, Copy)]
struct LocalChain {
    context: Context,
    commitment: Digest,
    nullifier: Digest,
}
impl AuthenticatedChain for LocalChain {
    fn validate_locked_note(
        &self,
        commitment: &Digest,
        nullifier: &Digest,
    ) -> Result<Context, ChainError> {
        if *commitment != self.commitment || *nullifier != self.nullifier {
            return Err(ChainError::UnknownNote);
        }
        Ok(self.context)
    }
}

struct Fixture {
    circuit: Sha256Hashlock,
    preimage: Digest,
    claim_key: MlDsaSecretKey,
    refund_key: MlDsaSecretKey,
    note: LockedNote,
    statement: SpendStatement,
    chain: LocalChain,
}
impl Fixture {
    fn new() -> Self {
        // Publicly known deterministic TEST keys only. The runnable example
        // generates fresh keys and never persists their seed or opening.
        let claim_key = MlDsaSecretKey::generate_deterministic(b"htlc-host-test-claim");
        let refund_key = MlDsaSecretKey::generate_deterministic(b"htlc-host-test-refund");
        let circuit = Sha256Hashlock::new();
        let preimage = [11; 32];
        let hashlock = circuit.digest(&circuit.evaluate(&preimage)).unwrap();
        let note = LockedNote {
            version: POLICY_VERSION,
            hashlock,
            claim_authority: authority(&claim_key.verify_key()),
            refund_authority: authority(&refund_key.verify_key()),
            timeout_height: 100,
            asset: [6; 32],
            value: 10,
            note_id: [7; 32],
            nullifier_key: [8; 32],
        };
        let statement = SpendStatement {
            note_commitment: note.commitment(),
            nullifier: note.nullifier(),
            intent: SpendIntent {
                network_id: [1; 32],
                recipient_commitment: [2; 32],
                asset: note.asset,
                output_value: 9,
                fee: 1,
                operation_nonce: [3; 32],
            },
        };
        let chain = LocalChain {
            context: Context {
                network_id: statement.intent.network_id,
                parent_hash: [4; 32],
                parent_height: 100,
            },
            commitment: statement.note_commitment,
            nullifier: statement.nullifier,
        };
        Self {
            circuit,
            preimage,
            claim_key,
            refund_key,
            note,
            statement,
            chain,
        }
    }
    fn evidence(&self, branch: Branch) -> Vec<u8> {
        let key = match branch {
            Branch::Claim => &self.claim_key,
            Branch::Refund => &self.refund_key,
        };
        sign_authorization(
            key,
            &authorization_message(&self.statement, branch, self.chain.context),
        )
    }
    fn refund(&self, ledger: &mut ReferenceLedger) -> Result<(), LedgerError> {
        ledger
            .admit(
                &self.circuit,
                &self.note,
                &self.statement,
                SpendWitness::Refund {
                    authorization: &self.evidence(Branch::Refund),
                },
                &self.chain,
                &MlDsaAuthorizer,
            )
            .map(|_| ())
    }
}

#[test]
fn real_claim_reopens_and_rejects_claim_and_refund_replay() {
    let scratch = Scratch::new();
    let f = Fixture::new();
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    let assignment = f.circuit.evaluate(&f.preimage);
    let authorization = f.evidence(Branch::Claim);
    let claim = || SpendWitness::Claim {
        preimage: &f.preimage,
        sha_assignment: &assignment,
        authorization: &authorization,
    };
    ledger
        .admit(
            &f.circuit,
            &f.note,
            &f.statement,
            claim(),
            &f.chain,
            &MlDsaAuthorizer,
        )
        .unwrap();
    let public_record = ledger.records()[0];
    assert_eq!(public_record.branch, Branch::Claim);
    drop(ledger);
    let mut reopened = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    assert_eq!(reopened.records(), &[public_record]);
    assert!(matches!(
        reopened.admit(
            &f.circuit,
            &f.note,
            &f.statement,
            claim(),
            &f.chain,
            &MlDsaAuthorizer
        ),
        Err(LedgerError::Relation(RelationError::Chain(
            ChainError::AlreadySpent
        )))
    ));
    assert!(matches!(
        f.refund(&mut reopened),
        Err(LedgerError::Relation(RelationError::Chain(
            ChainError::AlreadySpent
        )))
    ));
    assert_eq!(
        fs::metadata(scratch.journal()).unwrap().len(),
        16 + RECORD_BYTES as u64
    );
}

#[test]
fn refund_boundary_and_claim_after_timeout_use_external_height() {
    let scratch = Scratch::new();
    let mut f = Fixture::new();
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    f.chain.context.parent_height = 99;
    assert!(matches!(
        f.refund(&mut ledger),
        Err(LedgerError::Relation(RelationError::RefundImmature))
    ));
    assert!(ledger.records().is_empty());
    f.chain.context.parent_height = 100;
    f.refund(&mut ledger).unwrap();
    assert_eq!(ledger.records()[0].branch, Branch::Refund);
    drop(ledger);
    let mut after = ReferenceLedger::open(&scratch.0.join("after.journal"), 10).unwrap();
    f.chain.context.parent_height = 101;
    after
        .admit(
            &f.circuit,
            &f.note,
            &f.statement,
            SpendWitness::Claim {
                preimage: &f.preimage,
                sha_assignment: &f.circuit.evaluate(&f.preimage),
                authorization: &f.evidence(Branch::Claim),
            },
            &f.chain,
            &MlDsaAuthorizer,
        )
        .unwrap();
}

#[test]
fn authorization_binds_every_intent_context_and_branch_field() {
    let f = Fixture::new();
    let message = authorization_message(&f.statement, Branch::Refund, f.chain.context);
    let evidence = f.evidence(Branch::Refund);
    let verify =
        |message: &Digest| MlDsaAuthorizer.verify(&f.note.refund_authority, message, &evidence);
    verify(&message).unwrap();
    for field in 0..7 {
        let mut intent = f.statement.intent;
        match field {
            0 => intent.network_id[0] ^= 1,
            1 => intent.recipient_commitment[0] ^= 1,
            2 => intent.asset[0] ^= 1,
            3 => intent.output_value += 1,
            4 => intent.fee += 1,
            5 => intent.operation_nonce[0] ^= 1,
            _ => {
                intent.output_value -= 1;
                intent.fee += 1;
            }
        }
        let statement = SpendStatement {
            intent,
            ..f.statement
        };
        assert!(verify(&authorization_message(
            &statement,
            Branch::Refund,
            f.chain.context
        ))
        .is_err());
    }
    for field in 0..3 {
        let mut context = f.chain.context;
        match field {
            0 => context.network_id[0] ^= 1,
            1 => context.parent_hash[0] ^= 1,
            _ => context.parent_height += 1,
        }
        assert!(verify(&authorization_message(
            &f.statement,
            Branch::Refund,
            context
        ))
        .is_err());
    }
    assert!(verify(&authorization_message(
        &f.statement,
        Branch::Claim,
        f.chain.context
    ))
    .is_err());
    for field in 0..2 {
        let mut statement = SpendStatement {
            intent: f.statement.intent,
            ..f.statement
        };
        if field == 0 {
            statement.note_commitment[0] ^= 1;
        } else {
            statement.nullifier[0] ^= 1;
        }
        assert!(verify(&authorization_message(
            &statement,
            Branch::Refund,
            f.chain.context
        ))
        .is_err());
    }
}

#[test]
fn malformed_evidence_wrong_keys_and_signatures_reject() {
    let f = Fixture::new();
    let message = authorization_message(&f.statement, Branch::Refund, f.chain.context);
    let evidence = f.evidence(Branch::Refund);
    assert_eq!(evidence.len(), AUTHORIZATION_BYTES);
    let verify = |bytes: &[u8]| MlDsaAuthorizer.verify(&f.note.refund_authority, &message, bytes);
    for length in [0, 1, 1951, 1952, 3309, AUTHORIZATION_BYTES - 1] {
        assert!(verify(&evidence[..length]).is_err());
    }
    let mut appended = evidence.clone();
    appended.push(0);
    assert!(verify(&appended).is_err());
    let mut wrong_key = evidence.clone();
    wrong_key[..1952].copy_from_slice(&f.claim_key.verify_key().to_bytes());
    assert!(verify(&wrong_key).is_err());
    let mut damaged_key = evidence.clone();
    damaged_key[0] ^= 1;
    assert!(verify(&damaged_key).is_err());
    let mut signature = evidence.clone();
    signature[1952..].fill(0);
    assert!(verify(&signature).is_err());
    signature = evidence.clone();
    signature[1952] ^= 1;
    assert!(verify(&signature).is_err());
    let wrong_signer = sign_authorization(&f.claim_key, &message);
    assert!(verify(&wrong_signer).is_err());
    assert!(MlDsaAuthorizer
        .verify(&f.note.claim_authority, &message, &evidence)
        .is_err());
}

#[test]
fn changed_context_intent_and_branch_fail_at_admission_without_writes() {
    let scratch = Scratch::new();
    let mut f = Fixture::new();
    let evidence = f.evidence(Branch::Refund);
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    let witness = || SpendWitness::Refund {
        authorization: &evidence,
    };
    f.statement.intent.recipient_commitment[0] ^= 1;
    assert!(matches!(
        ledger.admit(
            &f.circuit,
            &f.note,
            &f.statement,
            witness(),
            &f.chain,
            &MlDsaAuthorizer
        ),
        Err(LedgerError::Relation(RelationError::Authorization))
    ));
    f.statement.intent.recipient_commitment[0] ^= 1;
    f.chain.context.parent_hash[0] ^= 1;
    assert!(matches!(
        ledger.admit(
            &f.circuit,
            &f.note,
            &f.statement,
            witness(),
            &f.chain,
            &MlDsaAuthorizer
        ),
        Err(LedgerError::Relation(RelationError::Authorization))
    ));
    f.chain.context.parent_hash[0] ^= 1;
    assert!(matches!(
        ledger.admit(
            &f.circuit,
            &f.note,
            &f.statement,
            SpendWitness::Claim {
                preimage: &f.preimage,
                sha_assignment: &f.circuit.evaluate(&f.preimage),
                authorization: &evidence,
            },
            &f.chain,
            &MlDsaAuthorizer
        ),
        Err(LedgerError::Relation(RelationError::Authorization))
    ));
    assert!(ledger.records().is_empty());
    assert_eq!(fs::metadata(scratch.journal()).unwrap().len(), 16);
}

#[test]
fn wrong_preimage_and_unincluded_note_reject_without_admission() {
    let scratch = Scratch::new();
    let mut f = Fixture::new();
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    let wrong = [12; 32];
    assert!(matches!(
        ledger.admit(
            &f.circuit,
            &f.note,
            &f.statement,
            SpendWitness::Claim {
                preimage: &wrong,
                sha_assignment: &f.circuit.evaluate(&wrong),
                authorization: &f.evidence(Branch::Claim),
            },
            &f.chain,
            &MlDsaAuthorizer
        ),
        Err(LedgerError::Relation(RelationError::Hashlock(_)))
    ));
    f.chain.commitment[0] ^= 1;
    assert!(matches!(
        f.refund(&mut ledger),
        Err(LedgerError::Relation(RelationError::Chain(
            ChainError::UnknownNote
        )))
    ));
    assert!(ledger.records().is_empty());
}

#[test]
fn strict_journal_rejects_damage_partial_truncation_duplicate_and_reorder() {
    let scratch = Scratch::new();
    let f = Fixture::new();
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    f.refund(&mut ledger).unwrap();
    drop(ledger);
    let valid = fs::read(scratch.journal()).unwrap();
    for cut in [0, 1, 15, 16, valid.len() - 1] {
        let path = scratch.0.join(format!("cut-{cut}"));
        fs::write(&path, &valid[..cut]).unwrap();
        // A header-only journal is a legitimate empty stream.
        if cut == 16 {
            continue;
        }
        assert!(matches!(
            ReferenceLedger::open(&path, 10),
            Err(LedgerError::Damaged)
        ));
    }
    for offset in [0, 16, 40, 88, valid.len() - 1] {
        let path = scratch.0.join(format!("mutate-{offset}"));
        let mut bytes = valid.clone();
        bytes[offset] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            ReferenceLedger::open(&path, 10),
            Err(LedgerError::Damaged)
        ));
    }
    let mut duplicate = valid.clone();
    let mut second = valid[16..].to_vec();
    second[..8].copy_from_slice(&2u64.to_le_bytes());
    let mut checksum = Sha256::new();
    checksum.update(b"hegemon-experimental-htlc-admission-journal-v1");
    checksum.update(&valid[valid.len() - 32..]);
    checksum.update(&second[..RECORD_BYTES - 32]);
    second[RECORD_BYTES - 32..].copy_from_slice(&checksum.finalize());
    duplicate.extend_from_slice(&second);
    let path = scratch.0.join("duplicate");
    fs::write(&path, &duplicate).unwrap();
    assert!(matches!(
        ReferenceLedger::open(&path, 10),
        Err(LedgerError::Damaged)
    ));
    duplicate[16..16 + RECORD_BYTES].copy_from_slice(&second);
    fs::write(&path, duplicate).unwrap();
    assert!(matches!(
        ReferenceLedger::open(&path, 10),
        Err(LedgerError::Damaged)
    ));
}

#[test]
fn bounded_journal_and_external_size_change_fail_closed() {
    let scratch = Scratch::new();
    assert!(matches!(
        ReferenceLedger::open(&scratch.journal(), 0),
        Err(LedgerError::InvalidLimit)
    ));
    assert!(matches!(
        ReferenceLedger::open(&scratch.journal(), MAX_RECORDS + 1),
        Err(LedgerError::InvalidLimit)
    ));
    let f = Fixture::new();
    let mut ledger = ReferenceLedger::open(&scratch.journal(), 1).unwrap();
    f.refund(&mut ledger).unwrap();
    assert!(matches!(f.refund(&mut ledger), Err(LedgerError::Full)));
    drop(ledger);
    let oversized = scratch.0.join("oversized");
    fs::write(&oversized, vec![0; 16 + 2 * RECORD_BYTES]).unwrap();
    assert!(matches!(
        ReferenceLedger::open(&oversized, 1),
        Err(LedgerError::Damaged)
    ));
    let mut other = ReferenceLedger::open(&scratch.0.join("changed"), 10).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(scratch.0.join("changed"))
        .unwrap()
        .set_len(17)
        .unwrap();
    assert!(matches!(f.refund(&mut other), Err(LedgerError::Damaged)));
    assert!(matches!(f.refund(&mut other), Err(LedgerError::Poisoned)));
}

fn worker(path: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "process_writer_helper", "--nocapture"])
        .env("HTLC_TEST_WORKER_JOURNAL", path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn process_writer_helper() {
    let Some(path) = std::env::var_os("HTLC_TEST_WORKER_JOURNAL") else {
        return;
    };
    let f = Fixture::new();
    let outcome = match ReferenceLedger::open(std::path::Path::new(&path), 10) {
        Err(LedgerError::Busy) => "busy",
        Ok(mut ledger) => match f.refund(&mut ledger) {
            Ok(()) => "admitted",
            Err(LedgerError::Relation(RelationError::Chain(ChainError::AlreadySpent))) => "replay",
            other => panic!("unexpected admission outcome: {other:?}"),
        },
        Err(other) => panic!("unexpected open outcome: {other:?}"),
    };
    println!("HTLC_WORKER_OUTCOME={outcome}");
}

#[test]
fn process_lock_rejects_busy_writer_and_releases_on_drop() {
    let scratch = Scratch::new();
    let ledger = ReferenceLedger::open(&scratch.journal(), 10).unwrap();
    let output = worker(&scratch.journal()).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("HTLC_WORKER_OUTCOME=busy"));
    assert!(ledger.records().is_empty());
    drop(ledger);
    let output = worker(&scratch.journal()).output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("HTLC_WORKER_OUTCOME=admitted"));
    assert_eq!(
        ReferenceLedger::open(&scratch.journal(), 10)
            .unwrap()
            .records()
            .len(),
        1
    );
}

#[test]
fn competing_process_writers_can_admit_only_once() {
    let scratch = Scratch::new();
    drop(ReferenceLedger::open(&scratch.journal(), 10).unwrap());
    let one = worker(&scratch.journal()).spawn().unwrap();
    let two = worker(&scratch.journal()).spawn().unwrap();
    let outputs = [
        one.wait_with_output().unwrap(),
        two.wait_with_output().unwrap(),
    ];
    let mut admitted = 0;
    for output in outputs {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        admitted += usize::from(text.contains("HTLC_WORKER_OUTCOME=admitted"));
        assert!(text.contains("HTLC_WORKER_OUTCOME="));
    }
    assert_eq!(admitted, 1);
    assert_eq!(
        ReferenceLedger::open(&scratch.journal(), 10)
            .unwrap()
            .records()
            .len(),
        1
    );
}
