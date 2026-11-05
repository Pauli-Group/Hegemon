//! Native account persistence. These helpers do not activate a network or
//! grant proof authority. A source-verified block planner must bind both account
//! and note roots before installing a journal in the shared canonical transaction.
use anyhow::{anyhow, ensure, Context, Result};
use codec::{Decode, Encode};
use protocol_reward_accounts::{
    AccountChainContext, AccountPolicyId48, RewardAccount, RewardAccountCheckpoint,
    RewardAccountJournal, RewardAccountLedger, RewardAccountsGenesis, RewardAccountsRoot48,
    RewardJournalDirection,
};
use sled::transaction::{
    ConflictableTransactionError, ConflictableTransactionResult, TransactionalTree,
};

const GENESIS_KEY: &[u8] = b"reward-accounts/v1/genesis";
const TIP_KEY: &[u8] = b"reward-accounts/v1/canonical-tip";
const ROW_PREFIX: &[u8] = b"reward-accounts/v1/account/";
const JOURNAL_PREFIX: &[u8] = b"reward-accounts/v1/block/";
const MAX_METADATA_BYTES: usize = 512 * 1024;
const MAX_ROW_BYTES: usize = 128;
const MAX_JOURNAL_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct RewardAccountAnchor {
    pub(crate) height: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) accounts_root: RewardAccountsRoot48,
    pub(crate) note_root: [u64; 7],
}
impl RewardAccountAnchor {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.block_hash != [0; 32] && self.accounts_root != RewardAccountsRoot48::ZERO,
            "zero account checkpoint identity"
        );
        super::poseidon2_v8_state::Poseidon2V8NoteRoot::new(self.note_root)
            .map_err(|e| anyhow!("invalid shared note root: {e}"))?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct DiskTip {
    anchor: RewardAccountAnchor,
    checkpoint: RewardAccountCheckpoint,
}
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct RewardAccountBlockJournal {
    before: RewardAccountAnchor,
    after: RewardAccountAnchor,
    journal: RewardAccountJournal,
}
impl RewardAccountBlockJournal {
    /// Assembly only. The caller must supply roots from the source-verified
    /// canonical block transition, not roots advertised by a peer.
    pub(crate) fn new(
        before: RewardAccountAnchor,
        after: RewardAccountAnchor,
        journal: RewardAccountJournal,
    ) -> Result<Self> {
        let record = Self {
            before,
            after,
            journal,
        };
        record.validate()?;
        Ok(record)
    }
    fn validate(&self) -> Result<()> {
        self.before.validate()?;
        self.after.validate()?;
        self.journal.validate_shape()?;
        ensure!(
            self.before.height.checked_add(1) == Some(self.after.height)
                && self.before.block_hash != self.after.block_hash,
            "nonsequential account journal anchors"
        );
        ensure!(
            self.before.height == self.journal.before().height()
                && self.after.height == self.journal.after().height()
                && self.before.accounts_root == self.journal.before_root()
                && self.after.accounts_root == self.journal.after_root(),
            "account journal differs from canonical anchors"
        );
        ensure!(
            self.encode().len() <= MAX_JOURNAL_BYTES,
            "account journal exceeds byte bound"
        );
        ensure!(
            self.before_tip().encode().len() <= MAX_METADATA_BYTES
                && self.after_tip().encode().len() <= MAX_METADATA_BYTES,
            "account metadata exceeds byte bound"
        );
        Ok(())
    }
    fn before_tip(&self) -> DiskTip {
        DiskTip {
            anchor: self.before,
            checkpoint: self.journal.before().clone(),
        }
    }
    fn after_tip(&self) -> DiskTip {
        DiskTip {
            anchor: self.after,
            checkpoint: self.journal.after().clone(),
        }
    }
}

fn exact<T: Decode + Encode>(bytes: &[u8], cap: usize) -> Result<T> {
    ensure!(bytes.len() <= cap, "account state row exceeds byte bound");
    let mut cursor = bytes;
    let value = T::decode(&mut cursor).map_err(|_| anyhow!("invalid account state encoding"))?;
    ensure!(
        cursor.is_empty() && value.encode() == bytes,
        "noncanonical account state encoding"
    );
    Ok(value)
}
fn row_key(id: AccountPolicyId48) -> Vec<u8> {
    let mut key = ROW_PREFIX.to_vec();
    key.extend(id.as_bytes());
    key
}
fn journal_key(hash: [u8; 32]) -> Vec<u8> {
    let mut key = JOURNAL_PREFIX.to_vec();
    key.extend(hash);
    key
}
fn abort(message: &str) -> ConflictableTransactionError<String> {
    ConflictableTransactionError::Abort(message.to_owned())
}

pub(crate) struct RewardAccountStateStore {
    tree: sled::Tree,
}
impl RewardAccountStateStore {
    /// Account rows use a separate namespace in the existing shared pool tree,
    /// so every canonical transaction can publish/undo both without a second DB.
    pub(crate) fn open(
        db: &sled::Db,
        genesis: RewardAccountsGenesis,
        context: AccountChainContext,
        canonical: RewardAccountAnchor,
    ) -> Result<(Self, RewardAccountLedger)> {
        canonical.validate()?;
        context.validate(&genesis)?;
        let tree = db.open_tree(super::poseidon2_v8_state::POSEIDON2_V8_STATE_TREE_NAME)?;
        let genesis_bytes = genesis.encode();
        if tree.get(TIP_KEY)?.is_none() {
            let initial = RewardAccountLedger::new(genesis.clone(), context.clone())?;
            ensure!(
                canonical.height == 0
                    && canonical.block_hash == context.genesis_hash
                    && canonical.accounts_root == initial.state_root(),
                "missing account state at non-genesis canonical tip"
            );
            ensure!(
                tree.get(GENESIS_KEY)?.is_none()
                    && tree.scan_prefix(ROW_PREFIX).next().is_none()
                    && tree.scan_prefix(JOURNAL_PREFIX).next().is_none(),
                "orphan account rows without canonical metadata"
            );
            let tip = DiskTip {
                anchor: canonical,
                checkpoint: initial.checkpoint(),
            }
            .encode();
            let rows: Vec<_> = initial
                .checkpoint_rows()
                .map(|(id, row)| (row_key(id), row.encode()))
                .collect();
            tree.transaction::<_, _, String>(|tx| {
                if tx.get(TIP_KEY)?.is_some() || tx.get(GENESIS_KEY)?.is_some() {
                    return Err(abort("account genesis changed during initialization"));
                }
                for (key, value) in &rows {
                    if tx.get(key)?.is_some() {
                        return Err(abort("account genesis would overwrite a row"));
                    }
                    tx.insert(key.as_slice(), value.as_slice())?;
                }
                tx.insert(GENESIS_KEY, genesis_bytes.as_slice())?;
                tx.insert(TIP_KEY, tip.as_slice())?;
                Ok(())
            })
            .map_err(|e| anyhow!("atomic account genesis initialization: {e}"))?;
        }
        ensure!(
            tree.get(GENESIS_KEY)?.as_deref() == Some(genesis_bytes.as_slice()),
            "stored account genesis differs from source network"
        );
        let tip: DiskTip = exact(
            &tree
                .get(TIP_KEY)?
                .ok_or_else(|| anyhow!("missing account tip"))?,
            MAX_METADATA_BYTES,
        )?;
        ensure!(
            tip.anchor == canonical
                && tip.checkpoint.height() == canonical.height
                && tip.checkpoint.context() == &context,
            "account checkpoint differs from authenticated canonical tip"
        );
        let mut row_error = None;
        let rows = tree.scan_prefix(ROW_PREFIX).map_while(|row| {
            let decoded = (|| -> Result<_> {
                let (key, value) = row?;
                let raw: [u8; 48] = key
                    .get(ROW_PREFIX.len()..)
                    .ok_or_else(|| anyhow!("invalid account key prefix"))?
                    .try_into()
                    .context("invalid account key width")?;
                Ok((
                    AccountPolicyId48::new(raw),
                    exact::<RewardAccount>(&value, MAX_ROW_BYTES)?,
                ))
            })();
            match decoded {
                Ok(row) => Some(row),
                Err(e) => {
                    row_error = Some(e);
                    None
                }
            }
        });
        let recovered = RewardAccountLedger::restore_checkpoint(
            genesis,
            tip.checkpoint,
            rows,
            canonical.accounts_root,
        );
        if let Some(error) = row_error {
            return Err(error);
        }
        let recovered = recovered?;
        Ok((Self { tree }, recovered))
    }
    pub(crate) fn tree(&self) -> &sled::Tree {
        &self.tree
    }
    pub(crate) fn load_journal(&self, hash: [u8; 32]) -> Result<RewardAccountBlockJournal> {
        let bytes = self
            .tree
            .get(journal_key(hash))?
            .ok_or_else(|| anyhow!("missing account block journal"))?;
        let record: RewardAccountBlockJournal = exact(&bytes, MAX_JOURNAL_BYTES)?;
        ensure!(
            record.after.block_hash == hash,
            "account journal block identity mismatch"
        );
        RewardAccountBlockJournal::new(record.before, record.after, record.journal)
    }
    /// Call in the SAME transaction as note/nullifier state and the native
    /// canonical pointers. No independent commit method is provided here.
    pub(crate) fn apply_in_transaction(
        tree: &TransactionalTree,
        record: &RewardAccountBlockJournal,
        direction: RewardJournalDirection,
    ) -> ConflictableTransactionResult<(), String> {
        record.validate().map_err(|e| abort(&e.to_string()))?;
        let forward = direction == RewardJournalDirection::Forward;
        let (before, after) = if forward {
            (record.before_tip(), record.after_tip())
        } else {
            (record.after_tip(), record.before_tip())
        };
        let before_bytes = before.encode();
        let after_bytes = after.encode();
        if tree.get(TIP_KEY)?.as_deref() != Some(before_bytes.as_slice()) {
            return Err(abort("stale account canonical tip"));
        }
        let key = journal_key(record.after.block_hash);
        let encoded = record.encode();
        match tree.get(&key)? {
            Some(stored) if stored.as_ref() == encoded.as_slice() => {}
            Some(_) => return Err(abort("immutable account journal collision")),
            None if forward => {
                tree.insert(key, encoded)?;
            }
            None => return Err(abort("cannot undo an unrecorded account journal")),
        }
        for row in record.journal.rows() {
            let (old, new) = if forward {
                (&row.before, &row.after)
            } else {
                (&row.after, &row.before)
            };
            let key = row_key(row.account);
            let expected = old.as_ref().map(Encode::encode);
            if tree.get(&key)?.as_deref() != expected.as_deref() {
                return Err(abort("account journal expected row mismatch"));
            }
            match new {
                Some(value) => {
                    tree.insert(key, value.encode())?;
                }
                None => {
                    tree.remove(key)?;
                }
            }
        }
        tree.insert(TIP_KEY, after_bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::poseidon2_v8_state::*;
    use super::*;
    use crypto::{hash384::RulesHash48, ml_dsa::MlDsaSecretKey, traits::SigningKey};
    use protocol_reward_accounts::*;
    use sled::transaction::TransactionError;
    // These storage tests contain public reward-only blocks. Every unexpected
    // private proof is rejected; this verifier authorizes no fixture proofs.
    struct NoPrivateProofs;
    impl RewardAccountProofVerifier for NoPrivateProofs {
        fn verify_claim(&self, _: &AccountClaim, _: &[u8]) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_donation(
            &self,
            _: &TreasuryDonation,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_private_fee(
            &self,
            _: &AccountChainContext,
            _: u64,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
    }
    impl Poseidon2V8ExactLeafVerifier for NoPrivateProofs {
        fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
            Poseidon2V8NativeLeafProfile::Smz9
        }
        fn verify_exact_v8_leaf(
            &mut self,
            _: Poseidon2V8BlockContext,
            _: usize,
            _: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            Err("no proof admitted in reward-only storage test".into())
        }
    }
    fn fixture() -> (
        RewardAccountsGenesis,
        AccountChainContext,
        RewardAccountLedger,
        RewardAccountAnchor,
    ) {
        let key = MlDsaSecretKey::generate_deterministic(b"account storage test");
        let genesis = RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [8; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: AccountPolicy::single(&key.verify_key()),
            allocations: BoundedVec::default(),
        };
        let context = AccountChainContext {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            genesis_config_hash: RulesHash48::new(genesis.commitment().unwrap()),
        };
        let ledger = RewardAccountLedger::new(genesis.clone(), context.clone()).unwrap();
        let note_root =
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()
                [32];
        let anchor = RewardAccountAnchor {
            height: 0,
            block_hash: context.genesis_hash,
            accounts_root: ledger.state_root(),
            note_root,
        };
        (genesis, context, ledger, anchor)
    }
    fn note_store(db: &sled::Db, a: RewardAccountAnchor) -> Poseidon2V8StateStore {
        Poseidon2V8StateStore::open(
            db,
            Poseidon2V8Checkpoint::new(0, a.block_hash, Poseidon2V8Root::new([0; 7]).unwrap()),
            Poseidon2V8NoteRoot::new(a.note_root).unwrap(),
        )
        .unwrap()
    }
    fn next(
        ledger: &RewardAccountLedger,
        parent: RewardAccountAnchor,
        tag: u8,
        miner: u8,
    ) -> (RewardAccountLedger, RewardAccountBlockJournal) {
        let (next, journal) = ledger
            .apply_block_journaled(
                parent.height + 1,
                AccountPolicyId48::new([miner; 48]),
                &[],
                &NoPrivateProofs,
                None,
            )
            .unwrap();
        let anchor = RewardAccountAnchor {
            height: next.height(),
            block_hash: [tag; 32],
            accounts_root: next.state_root(),
            note_root: parent.note_root,
        };
        let record = RewardAccountBlockJournal::new(parent, anchor, journal).unwrap();
        (next, record)
    }
    fn note_block(record: &RewardAccountBlockJournal) -> Poseidon2V8UnverifiedBlock<'static> {
        Poseidon2V8UnverifiedBlock::new(
            Poseidon2V8BlockContext::new(
                record.before.height,
                record.before.block_hash,
                record.after.height,
                record.after.block_hash,
            )
            .unwrap(),
            &[],
        )
        .unwrap()
    }
    fn commit(
        notes: &Poseidon2V8StateStore,
        detach: &[RewardAccountBlockJournal],
        attach: &[RewardAccountBlockJournal],
    ) {
        let blocks: Vec<_> = attach.iter().map(note_block).collect();
        let hashes: Vec<_> = detach.iter().map(|r| r.after.block_hash).collect();
        let plan = notes
            .plan_verified_reorganization(&hashes, &blocks, &mut NoPrivateProofs)
            .unwrap();
        let result: Result<(), TransactionError<String>> = notes.tree().transaction(|tree| {
            Poseidon2V8StateStore::apply_canonical_plan_in_transaction(tree, &plan)?;
            for record in detach {
                RewardAccountStateStore::apply_in_transaction(
                    tree,
                    record,
                    RewardJournalDirection::Reverse,
                )?;
            }
            for record in attach {
                RewardAccountStateStore::apply_in_transaction(
                    tree,
                    record,
                    RewardJournalDirection::Forward,
                )?;
            }
            Ok(())
        });
        result.unwrap();
        notes.tree().flush().unwrap();
    }
    #[test]
    fn reward_accounts_native_atomic_abort_and_disk_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let (g, context, initial, anchor) = fixture();
        let notes = note_store(&db, anchor);
        let (store, recovered) =
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), anchor).unwrap();
        assert_eq!(recovered, initial);
        let (next, record) = next(&initial, anchor, 3, 9);
        let plan = notes
            .plan_verified_reorganization(&[], &[note_block(&record)], &mut NoPrivateProofs)
            .unwrap();
        let result: Result<(), TransactionError<String>> = notes.tree().transaction(|tree| {
            Poseidon2V8StateStore::apply_canonical_plan_in_transaction(tree, &plan)?;
            RewardAccountStateStore::apply_in_transaction(
                tree,
                &record,
                RewardJournalDirection::Forward,
            )?;
            Err(abort("forced failure after both note/account writes"))
        });
        assert!(result.is_err());
        assert_eq!(notes.tip().unwrap().height(), 0);
        assert_eq!(
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), anchor)
                .unwrap()
                .1,
            initial
        );
        assert!(store
            .tree()
            .get(journal_key(record.after.block_hash))
            .unwrap()
            .is_none());
        commit(&notes, &[], std::slice::from_ref(&record));
        assert_eq!(notes.tip().unwrap().block_hash(), record.after.block_hash);
        assert_eq!(store.load_journal(record.after.block_hash).unwrap(), record);
        drop(notes);
        drop(store);
        db.flush().unwrap();
        drop(db);
        let db = sled::open(dir.path()).unwrap();
        let (store, recovered) =
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), record.after).unwrap();
        assert_eq!(recovered, next);
        let notes = note_store(&db, anchor);
        assert_eq!(notes.tip().unwrap().height(), 1);
        assert_eq!(
            notes.note_tip().unwrap().root().limbs(),
            record.after.note_root
        );
        let result: Result<(), TransactionError<String>> = store.tree().transaction(|tree| {
            RewardAccountStateStore::apply_in_transaction(
                tree,
                &record,
                RewardJournalDirection::Forward,
            )
        });
        assert!(result.is_err());
        assert_eq!(notes.tip().unwrap().height(), 1);
        assert!(RewardAccountStateStore::open(&db, g, context, anchor).is_err());
    }
    #[test]
    fn reward_accounts_native_epoch_boundary_suffix_rollback_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();
        let (g, context, initial, anchor) = fixture();
        let notes = note_store(&db, anchor);
        let (store, _) =
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), anchor).unwrap();
        let mut state = initial.clone();
        let mut parent = anchor;
        let mut records = Vec::new();
        let mut at_two = initial;
        for h in 1..=6 {
            let (after, record) = next(&state, parent, 10 + h, 9);
            commit(&notes, &[], std::slice::from_ref(&record));
            parent = record.after;
            state = after;
            records.push(record);
            if h == 2 {
                at_two = state.clone();
            }
        }
        assert!(state.available_total() > 0);
        let detached: Vec<_> = records[2..].iter().rev().cloned().collect();
        let mut state = at_two;
        let mut parent = records[1].after;
        let mut replacement = Vec::new();
        for h in 3..=7 {
            let (after, record) = next(&state, parent, 30 + h, 7);
            parent = record.after;
            state = after;
            replacement.push(record);
        }
        commit(&notes, &detached, &replacement);
        let (_, recovered) =
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), parent).unwrap();
        assert_eq!(recovered, state);
        assert_eq!(notes.tip().unwrap().height(), 7);
        assert_eq!(notes.note_tip().unwrap().leaf_count(), 0);
        for r in &detached {
            assert_eq!(store.load_journal(r.after.block_hash).unwrap(), *r);
        }
        let detach_new: Vec<_> = replacement.into_iter().rev().collect();
        commit(&notes, &detach_new, &records[2..]);
        let expected = records.last().unwrap().after;
        let (_, recovered) = RewardAccountStateStore::open(&db, g, context, expected).unwrap();
        assert_eq!(recovered.state_root(), expected.accounts_root);
        assert_eq!(notes.tip().unwrap().height(), 6);
    }
    #[test]
    fn reward_accounts_native_tampered_rows_fail_root_recovery() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let (g, context, initial, anchor) = fixture();
        let notes = note_store(&db, anchor);
        let (store, _) =
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), anchor).unwrap();
        let (_, record) = next(&initial, anchor, 3, 9);
        commit(&notes, &[], std::slice::from_ref(&record));
        let key = row_key(AccountPolicyId48::new([9; 48]));
        let original = store.tree().get(&key).unwrap().unwrap();
        let mut changed = original.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        store.tree().insert(&key, changed).unwrap();
        assert!(
            RewardAccountStateStore::open(&db, g.clone(), context.clone(), record.after).is_err()
        );
        store.tree().insert(&key, original).unwrap();
        assert!(RewardAccountStateStore::open(&db, g, context, record.after).is_ok());
    }
}
