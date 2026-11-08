//! Finite conformance for the additive candidate model. This does not establish
//! universal Rust refinement, note-cryptography soundness, or release authority.
use super::*;
use rand::{rngs::StdRng, SeedableRng};
use wallet::keys::RootSecret;

#[derive(Deserialize)]
struct Vectors {
    schema_version: u32,
    entitlement_cases: Vec<EntitlementCase>,
    accounting_cases: Vec<AccountingCase>,
    replay_cases: Vec<ReplayCase>,
}
#[derive(Deserialize)]
struct EntitlementCase {
    name: String,
    activation: Option<u64>,
    height: u64,
    expected: Option<Entitlement>,
}
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Entitlement {
    batch_start: u64,
    payout_height: Option<u64>,
    accrued_this_block: u64,
    pending_after: u64,
    payout: u64,
}
#[derive(Deserialize)]
struct AccountingCase {
    name: String,
    activation: u64,
    parent_supply: String,
    height: u64,
    fee_total: Option<u64>,
    coinbase_count: usize,
    primary: Option<u64>,
    secondary: Option<u64>,
    canonical_and_admitted: bool,
    placement_valid: bool,
    recipient_valid: bool,
    expected_issued: Option<u64>,
    expected_supply: Option<String>,
}
#[derive(Deserialize)]
struct ReplayCase {
    name: String,
    parent_supply: String,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    issued_override: Option<u64>,
    expected_supply: Option<String>,
}

fn fixture(primary: u64, secondary: u64, treasury_only: bool) -> (PendingAction, ShieldedAddress) {
    let treasury = RootSecret::from_bytes([0xb1; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    let miner = RootSecret::from_bytes([0xb2; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
        if treasury_only { &treasury } else { &miner },
        primary,
        &treasury,
        secondary,
        &mut StdRng::seed_from_u64(917),
    )
    .unwrap();
    let metadata = core::iter::once(&args.miner_note)
        .chain(args.funding_note.iter())
        .map(|note| {
            coinbase_ciphertext_metadata(&note.encrypted_note)
                .1
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_REWARDS,
        anchor: [0; 48],
        nullifiers: vec![],
        commitments: vec![],
        ciphertext_hashes: metadata.iter().map(|(hash, _)| *hash).collect(),
        ciphertext_sizes: metadata.iter().map(|(_, size)| *size).collect(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    (action, treasury)
}

#[test]
fn lean_generated_treasury_batch_supply_vectors_match_production() {
    // CI sets this variable; an ordinary targeted invocation also uses the
    // committed exact Lean-generated corpus, so this gate cannot silently skip.
    let raw = match std::env::var("HEGEMON_LEAN_TREASURY_BATCH_SUPPLY_VECTORS") {
        Ok(path) => std::fs::read_to_string(path).expect("read Lean treasury vectors"),
        Err(_) => {
            include_str!("../../../formal/core/treasury_batch_supply_vectors.json").to_owned()
        }
    };
    let vectors: Vectors = serde_json::from_str(&raw).expect("parse Lean treasury vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(vectors.entitlement_cases.len() >= 16);
    assert!(vectors.accounting_cases.len() >= 18);
    assert!(vectors.replay_cases.len() >= 7);
    let mut names = BTreeSet::new();
    for case in vectors.entitlement_cases {
        assert!(names.insert(case.name.clone()));
        let policy = case
            .activation
            .and_then(consensus::treasury::TreasuryRewardPolicy::at)
            .unwrap_or_default();
        let actual = policy.entitlement(case.height).map(|e| Entitlement {
            batch_start: e.batch_start,
            payout_height: e.payout_height,
            accrued_this_block: e.accrued_this_block,
            pending_after: e.pending_after,
            payout: e.payout,
        });
        assert_eq!(actual, case.expected, "{} entitlement", case.name);
    }
    for case in vectors.accounting_cases {
        assert!(names.insert(case.name.clone()));
        let policy = consensus::treasury::TreasuryRewardPolicy::at(case.activation).unwrap();
        let due = policy.entitlement(case.height).unwrap().payout;
        let (mut reward, mut recipient) = fixture(
            case.primary.unwrap_or(1),
            case.secondary.unwrap_or(0),
            due > 0 && case.secondary.is_none(),
        );
        if !case.canonical_and_admitted {
            // Exact decoding fails before the amount projection can authorize it.
            reward.public_args.push(0);
        }
        if !case.recipient_valid {
            recipient.pk_auth_extension[0] ^= 1;
        }
        let mut actions = Vec::new();
        // Fee accounting reads only the canonical transfer fee fields here;
        // proof/payload soundness is explicitly outside this finite model.
        for fee in case
            .fee_total
            .map(|f| vec![f])
            .unwrap_or_else(|| vec![u64::MAX, 1])
        {
            let mut transfer = reward.clone();
            transfer.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
            transfer.fee = fee;
            transfer.tx_hash = pending_action_hash(&transfer);
            actions.push(transfer);
        }
        actions.extend(std::iter::repeat_n(reward, case.coinbase_count));
        if !case.placement_valid {
            actions.rotate_right(1);
        }
        let accounting = validate_coinbase_funding_accounting_with_policy(
            &actions,
            case.height,
            Some(&recipient),
            policy,
        );
        assert_eq!(
            accounting.is_ok(),
            case.expected_issued.is_some(),
            "{} accounting: {accounting:?}",
            case.name
        );
        if let Some(issued) = case.expected_issued {
            let projection =
                native_supply_composition_projection_with_policy(&actions, case.height, policy)
                    .unwrap();
            assert_eq!(
                projection.supply_delta,
                u128::from(issued),
                "{} issued",
                case.name
            );
            let actual_supply = advance_native_supply_digest_with_policy(
                case.parent_supply.parse().unwrap(),
                &actions,
                case.height,
                policy,
            )
            .ok();
            assert_eq!(
                actual_supply,
                case.expected_supply.map(|s| s.parse::<u128>().unwrap()),
                "{} supply",
                case.name
            );
        }
    }
    for case in vectors.replay_cases {
        assert!(names.insert(case.name.clone()));
        let expected = case.expected_supply.map(|s| s.parse::<u128>().unwrap());
        let input = NativeBlockReplayRefinementInput {
            leaf_start: 0,
            parent_supply: case.parent_supply.parse().unwrap(),
            height: case.height,
            fee_total: case.fee_total,
            has_coinbase: case.has_coinbase,
            issued_coinbase_amount: case.issued_override,
            claimed_supply: expected.unwrap_or(0),
            tx_count_matches: true,
            state_root_matches: true,
            kernel_root_matches: true,
            nullifier_root_matches: true,
            extrinsics_root_matches: true,
            message_root_matches: true,
            message_count_matches: true,
            header_mmr_root_matches: true,
            header_mmr_len_matches: true,
        };
        let mut nullifiers = NullifierState::new(BTreeSet::new(), BTreeSet::new());
        let mut bridge = InboundReplayState::new(BTreeSet::new(), BTreeSet::new());
        let (_, actual) = evaluate_native_block_replay_refinement_with_trace(
            input,
            std::iter::empty::<NativeActionStreamStep<'_>>(),
            &mut nullifiers,
            &mut bridge,
        );
        match expected {
            Some(supply) => assert_eq!(
                actual.unwrap().expected_supply,
                supply,
                "{} replay",
                case.name
            ),
            None => assert!(
                matches!(
                    actual,
                    Err(NativeBlockReplayRefinementRejection::SupplyDeltaInvalid)
                ),
                "{} replay",
                case.name
            ),
        }
    }
}
