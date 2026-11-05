use codec::{Compact, Decode, Encode};
use crypto::{ml_dsa::MlDsaSecretKey, traits::SigningKey};
use proptest::prelude::*;
use protocol_reward_accounts::*;

fn network() -> AddressNetwork {
    AddressNetwork {
        class: NetworkClass::Testnet,
        discriminator: [9; 32],
    }
}
fn policy() -> AccountPolicy {
    AccountPolicy::single(
        &MlDsaSecretKey::generate_deterministic(b"disposable reward fixture").verify_key(),
    )
}
fn genesis() -> RewardAccountsGenesis {
    RewardAccountsGenesis {
        network: network(),
        reward_epoch_blocks: 1440,
        treasury_policy: policy(),
        allocations: BoundedVec::default(),
    }
}

#[test]
fn reward_accounts_epoch_boundaries_and_overflow() {
    let e = RewardEpochSchedule::new(1440).unwrap();
    for (h, n, r) in [
        (1, 0, 2881),
        (1440, 0, 2881),
        (1441, 1, 4321),
        (2880, 1, 4321),
        (2881, 2, 5761),
    ] {
        assert_eq!(e.epoch_at(h).unwrap(), n);
        assert_eq!(e.reward_release_height(h).unwrap(), r);
    }
    assert!(e.epoch_at(0).is_err());
    assert!(RewardEpochSchedule::new(0).is_err());
    assert!(e.release_height(u64::MAX).is_err());
    assert!(RewardEpochSchedule::new(u64::MAX)
        .unwrap()
        .reward_release_height(1)
        .is_err());
}

#[test]
fn reward_accounts_genesis_budget_and_exact_curve() {
    for g in [0, 1000 * COIN, MAX_SUPPLY - 1, MAX_SUPPLY] {
        let s = IssuanceSchedule::new(g).unwrap();
        assert_eq!(
            (0..64).map(|k| s.era_budget(k)).sum::<u64>(),
            MAX_SUPPLY - g
        );
        assert_eq!(s.issued_through(u64::MAX), MAX_SUPPLY - g);
        assert_eq!(s.subsidy(0), 0);
        assert_eq!(s.subsidy(u64::MAX), 0);
        for h in [
            1,
            2,
            ISSUANCE_ERA_BLOCKS,
            ISSUANCE_ERA_BLOCKS + 1,
            64 * ISSUANCE_ERA_BLOCKS,
        ] {
            assert_eq!(s.subsidy(h), s.issued_through(h) - s.issued_through(h - 1));
        }
    }
    let empty = IssuanceSchedule::new(0).unwrap();
    assert_eq!(empty.subsidy(1), 5 * COIN);
    assert_eq!(empty.subsidy(ISSUANCE_ERA_BLOCKS + 1), 5 * COIN / 2);
    assert!(IssuanceSchedule::new(MAX_SUPPLY + 1).is_err());
    assert_eq!(reward_split(11, 7).unwrap(), (16, 2));
    assert!(reward_split(0, u64::MAX).is_ok());
    assert!(reward_split(10, u64::MAX).is_err());
}

#[test]
fn reward_accounts_genesis_canonical_and_bound() {
    let mut g = genesis();
    let base = g.commitment().unwrap();
    g.allocations = BoundedVec::new(vec![GenesisAllocation {
        account: g.treasury_account().unwrap(),
        amount: MAX_SUPPLY,
    }])
    .unwrap();
    assert_eq!(g.validate().unwrap(), MAX_SUPPLY);
    assert_eq!(g.issuance().unwrap().mining_budget(), 0);
    assert_ne!(g.commitment().unwrap(), base);
    assert_eq!(RewardAccountsGenesis::decode_exact(&g.encode()).unwrap(), g);
    assert_eq!(
        serde_json::from_str::<RewardAccountsGenesis>(&serde_json::to_string(&g).unwrap()).unwrap(),
        g
    );
    let mut trailing = g.encode();
    trailing.push(0);
    assert!(RewardAccountsGenesis::decode_exact(&trailing).is_err());
    g.allocations =
        BoundedVec::new(vec![g.allocations[0].clone(), g.allocations[0].clone()]).unwrap();
    assert!(g.validate().is_err());
    g.allocations = BoundedVec::new(vec![GenesisAllocation {
        account: AccountPolicyId48::new([2; 48]),
        amount: 0,
    }])
    .unwrap();
    assert!(g.validate().is_err());
    let declared = Compact((MAX_GENESIS_ALLOCATIONS + 1) as u32).encode();
    assert!(
        BoundedVec::<GenesisAllocation, MAX_GENESIS_ALLOCATIONS>::decode(&mut declared.as_slice())
            .is_err()
    );
    assert!(serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,3]").is_err());
}

#[test]
fn reward_accounts_address_rejects_relabel_and_wrong_network() {
    let a = PublicAccountAddress {
        network: network(),
        policy: policy().identifier().unwrap(),
    };
    let s = a.encode().unwrap();
    assert!(s.starts_with("heg_test1"));
    assert_eq!(PublicAccountAddress::decode(&s, network()).unwrap(), a);
    assert_eq!(
        PublicAccountAddress::decode(&s.to_uppercase(), network()).unwrap(),
        a
    );
    assert!(PublicAccountAddress::decode(&format!("H{}", &s[1..]), network()).is_err());
    let main = AddressNetwork {
        class: NetworkClass::Mainnet,
        ..network()
    };
    assert!(PublicAccountAddress::decode(&s, main).is_err());
    assert!(PublicAccountAddress::decode(
        &s,
        AddressNetwork {
            discriminator: [8; 32],
            ..network()
        }
    )
    .is_err());
    let (.., data, _) = bech32::decode(&s).unwrap();
    let relabeled = bech32::encode("heg", data.clone(), bech32::Variant::Bech32m).unwrap();
    assert!(PublicAccountAddress::decode(&relabeled, main).is_err());
    let old_checksum = bech32::encode("heg_test", data.clone(), bech32::Variant::Bech32).unwrap();
    assert!(PublicAccountAddress::decode(&old_checksum, network()).is_err());
    let wrong_kind = bech32::encode("heg_shield_test", data, bech32::Variant::Bech32m).unwrap();
    assert!(decode_address_body(&wrong_kind, AddressKind::Shielded, network()).is_err());
    assert!(
        PublicAccountAddress::decode(&"x".repeat(MAX_ACCOUNT_ADDRESS_CHARS + 1), network())
            .is_err()
    );
    assert!(AddressNetwork {
        discriminator: [0; 32],
        ..network()
    }
    .validate()
    .is_err());
}

#[test]
fn reward_accounts_real_five_of_seven_authorization() {
    let keys: Vec<_> = (0u8..7)
        .map(|i| MlDsaSecretKey::generate_deterministic(&[i; 32]))
        .collect();
    let policy = AccountPolicy::threshold(
        5,
        keys.iter()
            .map(|k| account_key_hash(&k.verify_key()))
            .collect(),
    )
    .unwrap();
    let mut approvals: Vec<_> = keys
        .iter()
        .take(5)
        .map(|key| {
            let i = policy
                .signer_hashes()
                .iter()
                .position(|h| *h == account_key_hash(&key.verify_key()))
                .unwrap() as u8;
            AccountApproval::sign(i, key, &[7; 48])
        })
        .collect();
    approvals.sort_by_key(|a| a.signer_index);
    policy.verify(&[7; 48], &approvals).unwrap();
    assert!(policy.verify(&[7; 48], &approvals[..4]).is_err());
    assert!(policy.verify(&[8; 48], &approvals).is_err());
    let mut duplicate = approvals.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(policy.verify(&[7; 48], &duplicate).is_err());
    let wrong = MlDsaSecretKey::generate_deterministic(b"wrong signer");
    let mut wrong_keys = approvals.clone();
    wrong_keys[0] = AccountApproval::sign(approvals[0].signer_index, &wrong, &[7; 48]);
    assert!(policy.verify(&[7; 48], &wrong_keys).is_err());
    assert!(AccountPolicy::threshold(0, policy.signer_hashes().to_vec()).is_err());
    assert!(AccountPolicy::threshold(8, policy.signer_hashes().to_vec()).is_err());
    assert!(AccountPolicy::threshold(1, vec![policy.signer_hashes()[0]; 2]).is_err());
}

proptest! {
    #[test]
    fn reward_accounts_supply_prefix_and_epoch_age(g in 0..=MAX_SUPPLY, h in 1u64..100_000_000) {
        let s=IssuanceSchedule::new(g).unwrap();
        prop_assert_eq!(s.issued_through(h)-s.issued_through(h-1),s.subsidy(h));
        prop_assert!(g+s.issued_through(h)<=MAX_SUPPLY);
        let release=RewardEpochSchedule::new(1440).unwrap().reward_release_height(h).unwrap();
        prop_assert!((1441..=2880).contains(&(release-h)));
    }
}
