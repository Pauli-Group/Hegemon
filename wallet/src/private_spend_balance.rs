//! Read-only, exact native monetary inventory. No persisted wallet schema changes.
use super::*;
use synthetic_crypto::private_note_payload::NoteState;

type Digest = [u64; 7];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BalanceAmount {
    pub atoms: u128,
    pub notes: u64,
}
impl BalanceAmount {
    fn add(&mut self, value: u64) -> Result<(), WalletError> {
        self.atoms = self
            .atoms
            .checked_add(u128::from(value))
            .ok_or(WalletError::InvalidState("wallet balance atom overflow"))?;
        self.notes = self.notes.checked_add(1).ok_or(WalletError::InvalidState(
            "wallet balance note count overflow",
        ))?;
        Ok(())
    }
}

/// Snapshot of the already-synced encrypted wallet, not a network balance query.
/// Available ordinary HGN excludes every live cross-route input reservation.
/// Conditional notes remain separate even when the wallet has their openings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivateSpendBalance {
    pub synced_height: u64,
    pub ordinary_available: BalanceAmount,
    pub ordinary_reserved: BalanceAmount,
    pub immature_coinbase: BalanceAmount,
    /// First eligible inclusion height (created height + 120), not release height.
    pub next_maturity_height: Option<u64>,
    /// Additional tip blocks before the next inclusion height can spend it.
    pub blocks_until_next_maturity: Option<u64>,
    pub htlc: BalanceAmount,
    pub policy: BalanceAmount,
    pub treasury_value: BalanceAmount,
    /// Accumulator bookkeeping notes never contribute monetary value.
    pub accumulator_notes: u64,
    /// Non-HGN inventory in each asset's own base units, never summed as HGN.
    pub non_native: BTreeMap<u64, BalanceAmount>,
    /// Watch-only snapshots fail closed with WalletError::WatchOnly because
    /// incoming viewing alone cannot establish complete private spend status.
    pub watch_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ordinary,
    Htlc,
    Policy,
    TreasuryValue,
    Accumulator,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InventoryNote {
    position: u64,
    commitment: Digest,
    nullifier: Digest,
    value: u64,
    asset: u64,
    spent: bool,
    kind: Kind,
}

fn add_occurrence(
    rows: &mut BTreeMap<u64, InventoryNote>,
    row: InventoryNote,
) -> Result<(), WalletError> {
    if let Some(old) = rows.insert(row.position, row) {
        if old != row {
            return Err(WalletError::InvalidState(
                "conflicting wallet balance note occurrence",
            ));
        }
    }
    Ok(())
}
fn count_note(
    balance: &mut PrivateSpendBalance,
    note: &InventoryNote,
    reserved: &HashSet<Digest>,
) -> Result<(), WalletError> {
    if note.spent {
        return Ok(());
    }
    if note.kind == Kind::Accumulator {
        balance.accumulator_notes =
            balance
                .accumulator_notes
                .checked_add(1)
                .ok_or(WalletError::InvalidState(
                    "wallet balance note count overflow",
                ))?;
        return Ok(());
    }
    if note.asset != NATIVE_ASSET_ID {
        return balance
            .non_native
            .entry(note.asset)
            .or_default()
            .add(note.value);
    }
    match note.kind {
        Kind::Ordinary if reserved.contains(&note.nullifier) => {
            balance.ordinary_reserved.add(note.value)
        }
        Kind::Ordinary => balance.ordinary_available.add(note.value),
        Kind::Htlc => balance.htlc.add(note.value),
        Kind::Policy => balance.policy.add(note.value),
        Kind::TreasuryValue => balance.treasury_value.add(note.value),
        Kind::Accumulator => unreachable!(),
    }
}

impl WalletStore {
    pub fn private_spend_balance(&self) -> Result<PrivateSpendBalance, WalletError> {
        self.with_state(|state| {
            if state.mode != WalletMode::Full || state.derived.is_none() {
                return Err(WalletError::WatchOnly);
            }
            let tip = state.poseidon2_v8.tip()?;
            let next_inclusion = tip
                .height
                .checked_add(1)
                .ok_or(WalletError::InvalidState("wallet balance height overflow"))?;
            let mut balance = PrivateSpendBalance {
                synced_height: tip.height,
                ..Default::default()
            };
            // This is the selector's complete live reservation union: ordinary,
            // private spend, HTLC, asset spend/recovery, and treasury multisig.
            let reserved = state.reserved_poseidon2_v8_nullifiers();
            let mut rows = BTreeMap::new();
            for (position, commitment, nullifier, value, asset, spent) in
                state.poseidon2_v8.balance_notes()?
            {
                add_occurrence(
                    &mut rows,
                    InventoryNote {
                        position,
                        commitment,
                        nullifier,
                        value,
                        asset,
                        spent,
                        kind: Kind::Ordinary,
                    },
                )?;
            }
            for note in &state.private_spend_notes {
                let payload = note.opening()?;
                let kind = match &payload.state {
                    NoteState::Ordinary { .. } => Kind::Ordinary,
                    NoteState::Htlc(_) => Kind::Htlc,
                    NoteState::Policy(_) => Kind::Policy,
                    NoteState::TreasuryValue(_) => Kind::TreasuryValue,
                    NoteState::TreasuryAccumulator(_) => Kind::Accumulator,
                };
                add_occurrence(
                    &mut rows,
                    InventoryNote {
                        position: note.position,
                        commitment: note.commitment,
                        nullifier: note.nullifier,
                        value: payload.note.value,
                        asset: payload.note.asset_id,
                        spent: note.spent,
                        kind,
                    },
                )?;
            }
            for note in rows.values() {
                count_note(&mut balance, note, &reserved)?;
            }
            for (value, asset, maturity) in state.poseidon2_v8.immature_owned_rewards()? {
                if maturity <= next_inclusion {
                    return Err(WalletError::InvalidState(
                        "overdue wallet reward maturity queue",
                    ));
                }
                if asset != NATIVE_ASSET_ID {
                    balance.non_native.entry(asset).or_default().add(value)?;
                    continue;
                }
                balance.immature_coinbase.add(value)?;
                balance.next_maturity_height = Some(
                    balance
                        .next_maturity_height
                        .map_or(maturity, |h| h.min(maturity)),
                );
            }
            balance.blocks_until_next_maturity = balance
                .next_maturity_height
                .map(|height| height - next_inclusion);
            Ok(balance)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn note(position: u64, value: u64, kind: Kind) -> InventoryNote {
        InventoryNote {
            position,
            commitment: [position + 1; 7],
            nullifier: [position + 2; 7],
            value,
            asset: NATIVE_ASSET_ID,
            spent: false,
            kind,
        }
    }
    #[test]
    fn private_spend_balance_exact_categories_exclude_spent_conditional_and_accumulator() {
        let mut balance = PrivateSpendBalance::default();
        let reserved: HashSet<_> = [[3; 7]].into_iter().collect();
        let mut spent = note(2, u64::MAX, Kind::Ordinary);
        spent.spent = true;
        let mut foreign = note(7, 19, Kind::Policy);
        foreign.asset = 7;
        let mut foreign2 = note(8, 23, Kind::Ordinary);
        foreign2.asset = 8;
        for row in [
            note(0, u64::MAX, Kind::Ordinary),
            note(1, 11, Kind::Ordinary),
            spent,
            note(3, 13, Kind::Htlc),
            note(4, 17, Kind::Policy),
            note(5, 29, Kind::TreasuryValue),
            note(6, 101, Kind::Accumulator),
            foreign,
            foreign2,
            note(9, u64::MAX, Kind::Ordinary),
        ] {
            count_note(&mut balance, &row, &reserved).unwrap();
        }
        assert_eq!(
            balance.ordinary_available,
            BalanceAmount {
                atoms: 2 * u128::from(u64::MAX),
                notes: 2
            }
        );
        assert_eq!(
            balance.ordinary_reserved,
            BalanceAmount {
                atoms: 11,
                notes: 1
            }
        );
        assert_eq!(balance.htlc.atoms, 13);
        assert_eq!(balance.policy.atoms, 17);
        assert_eq!(balance.treasury_value.atoms, 29);
        assert_eq!(balance.accumulator_notes, 1);
        assert_eq!(balance.non_native[&7].atoms, 19);
        assert_eq!(balance.non_native[&8].atoms, 23);
    }
    #[test]
    fn private_spend_balance_deduplicates_equal_representation_and_rejects_conflicts() {
        let mut rows = BTreeMap::new();
        let row = note(0, 41, Kind::Ordinary);
        add_occurrence(&mut rows, row).unwrap();
        add_occurrence(&mut rows, row).unwrap();
        assert_eq!(rows.len(), 1);
        let mut other = row;
        other.spent = true;
        assert!(add_occurrence(&mut rows, other).is_err());
    }
    #[test]
    fn private_spend_balance_watch_only_is_not_reported_as_zero_available() {
        let directory = tempfile::tempdir().unwrap();
        let root = RootSecret::from_bytes([81; 32]);
        let store = WalletStore::import_viewing_key(
            directory.path().join("view.wallet"),
            "test",
            IncomingViewingKey::from_keys(&root.derive()),
        )
        .unwrap();
        assert!(matches!(
            store.private_spend_balance(),
            Err(WalletError::WatchOnly)
        ));
    }
}
