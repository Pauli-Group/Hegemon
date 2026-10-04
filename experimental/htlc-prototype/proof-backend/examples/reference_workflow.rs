//! Local host demonstration only: no authenticated network oracle, full HTLC
//! proof, production admission, consensus import or activated swap is provided.
use hegemon_isolated_htlc_smallwood::{
    authorization::{authority, sign_authorization, MlDsaAuthorizer},
    reference_ledger::{LedgerError, ReferenceLedger},
};
use htlc_prototype::{
    hashlock::Sha256Hashlock,
    relation::{
        authorization_message, AuthenticatedChain, Branch, ChainError, Context, Digest, LockedNote,
        RelationError, SpendIntent, SpendStatement, SpendWitness, POLICY_VERSION,
    },
};
use std::{
    error::Error,
    path::Path,
    process::{Command, ExitCode},
};
use synthetic_crypto::{ml_dsa::MlDsaSecretKey, traits::SigningKey};

/// Explicit LOCAL test oracle. The provided note and height are trusted by this
/// host demonstration; no consensus evidence authenticates either of them.
struct LocalDemoChain {
    context: Context,
    known: Vec<(Digest, Digest)>,
}
impl AuthenticatedChain for LocalDemoChain {
    fn validate_locked_note(
        &self,
        commitment: &Digest,
        nullifier: &Digest,
    ) -> Result<Context, ChainError> {
        if !self.known.contains(&(*commitment, *nullifier)) {
            return Err(ChainError::UnknownNote);
        }
        Ok(self.context)
    }
}

fn random_digest() -> Result<Digest, Box<dyn Error>> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("OS randomness: {error}"))?;
    Ok(bytes)
}

fn fresh_note(
    claim: &MlDsaSecretKey,
    refund: &MlDsaSecretKey,
    hashlock: Digest,
) -> Result<LockedNote, Box<dyn Error>> {
    Ok(LockedNote {
        version: POLICY_VERSION,
        hashlock,
        claim_authority: authority(&claim.verify_key()),
        refund_authority: authority(&refund.verify_key()),
        timeout_height: 100,
        asset: [6; 32],
        value: 10,
        note_id: random_digest()?,
        nullifier_key: random_digest()?,
    })
}

fn statement(note: &LockedNote) -> SpendStatement {
    SpendStatement {
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
    }
}

fn demo(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.try_exists()? {
        return Err("--demo requires a fresh journal path; retained records are preserved".into());
    }
    // Fresh private material remains in memory only. No secret is printed,
    // serialized or included in child-process arguments or environment.
    let claim_key = MlDsaSecretKey::generate_deterministic(&random_digest()?);
    let refund_key = MlDsaSecretKey::generate_deterministic(&random_digest()?);
    let preimage = random_digest()?;
    let circuit = Sha256Hashlock::new();
    let assignment = circuit.evaluate(&preimage);
    let hashlock = circuit
        .digest(&assignment)
        .map_err(|e| format!("SHA host assignment: {e:?}"))?;
    let claim_note = fresh_note(&claim_key, &refund_key, hashlock)?;
    let refund_note = fresh_note(&claim_key, &refund_key, hashlock)?;
    let claim_statement = statement(&claim_note);
    let refund_statement = statement(&refund_note);
    let mut chain = LocalDemoChain {
        context: Context {
            network_id: [1; 32],
            parent_hash: [4; 32],
            parent_height: 99,
        },
        known: vec![
            (claim_note.commitment(), claim_note.nullifier()),
            (refund_note.commitment(), refund_note.nullifier()),
        ],
    };
    let mut ledger = ReferenceLedger::open(path, 10)?;
    let claim_signature = sign_authorization(
        &claim_key,
        &authorization_message(&claim_statement, Branch::Claim, chain.context),
    );
    let claim_witness = || SpendWitness::Claim {
        preimage: &preimage,
        sha_assignment: &assignment,
        authorization: &claim_signature,
    };
    ledger.admit(
        &circuit,
        &claim_note,
        &claim_statement,
        claim_witness(),
        &chain,
        &MlDsaAuthorizer,
    )?;
    let replay = ledger.admit(
        &circuit,
        &claim_note,
        &claim_statement,
        claim_witness(),
        &chain,
        &MlDsaAuthorizer,
    );
    if !matches!(
        replay,
        Err(LedgerError::Relation(RelationError::Chain(
            ChainError::AlreadySpent
        )))
    ) {
        return Err("claim replay did not reject as spent".into());
    }
    let immature_signature = sign_authorization(
        &refund_key,
        &authorization_message(&refund_statement, Branch::Refund, chain.context),
    );
    let immature = ledger.admit(
        &circuit,
        &refund_note,
        &refund_statement,
        SpendWitness::Refund {
            authorization: &immature_signature,
        },
        &chain,
        &MlDsaAuthorizer,
    );
    if !matches!(
        immature,
        Err(LedgerError::Relation(RelationError::RefundImmature))
    ) {
        return Err("immature refund did not reject".into());
    }
    chain.context.parent_height = 100;
    let mature_signature = sign_authorization(
        &refund_key,
        &authorization_message(&refund_statement, Branch::Refund, chain.context),
    );
    ledger.admit(
        &circuit,
        &refund_note,
        &refund_statement,
        SpendWitness::Refund {
            authorization: &mature_signature,
        },
        &chain,
        &MlDsaAuthorizer,
    )?;
    let competing = Command::new(std::env::current_exe()?)
        .arg("--probe-lock")
        .arg(path)
        .output()?;
    if !competing.status.success()
        || !String::from_utf8_lossy(&competing.stdout).contains("busy_rejected")
    {
        return Err("competing process failed to reject the held journal lock".into());
    }
    let before = ledger.records().to_vec();
    drop(ledger);
    // Public-only separate-process readback: child receives only the path.
    let inspected = Command::new(std::env::current_exe()?)
        .arg("--inspect")
        .arg(path)
        .output()?;
    if !inspected.status.success() {
        return Err("public-only fresh-process readback failed".into());
    }
    let public_receipt: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
    if public_receipt["records"] != 2 {
        return Err("fresh-process journal count differs".into());
    }
    let mut reopened = ReferenceLedger::open(path, 10)?;
    if reopened.records() != before.as_slice() {
        return Err("reopened public records differ".into());
    }
    let opposite_signature = sign_authorization(
        &refund_key,
        &authorization_message(&claim_statement, Branch::Refund, chain.context),
    );
    let opposite = reopened.admit(
        &circuit,
        &claim_note,
        &claim_statement,
        SpendWitness::Refund {
            authorization: &opposite_signature,
        },
        &chain,
        &MlDsaAuthorizer,
    );
    if !matches!(
        opposite,
        Err(LedgerError::Relation(RelationError::Chain(
            ChainError::AlreadySpent
        )))
    ) {
        return Err("opposite-branch replay did not reject after reopen".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "scope": "experimental_host_only_local_trusted_height_and_inclusion",
            "records": reopened.records().len(),
            "claim_accepted": true, "mature_refund_accepted": true,
            "immature_refund_rejected": true, "claim_replay_rejected": true,
            "opposite_branch_replay_rejected_after_reopen": true,
            "competing_process_busy_rejected": true,
            "public_only_fresh_process_readback": true,
            "private_material_persisted": false,
            "full_htlc_zk_or_production_swap": false,
        })
    );
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: reference_workflow --demo FRESH_JOURNAL | --inspect JOURNAL | --probe-lock JOURNAL".into());
    }
    let path = Path::new(&args[1]);
    if args[0] == "--demo" {
        demo(path)
    } else if args[0] == "--inspect" {
        if !path.try_exists()? {
            return Err("journal does not exist".into());
        }
        let ledger = ReferenceLedger::open(path, 10)?;
        println!(
            "{}",
            serde_json::json!({ "scope": "public_local_journal_only", "records": ledger.records().len() })
        );
        Ok(())
    } else if args[0] == "--probe-lock" {
        if !path.try_exists()? {
            return Err("journal does not exist".into());
        }
        match ReferenceLedger::open(path, 10) {
            Err(LedgerError::Busy) => {
                println!("busy_rejected");
                Ok(())
            }
            _ => Err("expected another process to hold the journal lock".into()),
        }
    } else {
        Err("unknown workflow operation".into())
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("experimental host workflow: {error}");
            ExitCode::FAILURE
        }
    }
}
