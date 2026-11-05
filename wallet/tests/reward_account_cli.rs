use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn run(args: &[&str]) -> Value {
    let output = Command::cargo_bin("reward-account")
        .unwrap()
        .args(args)
        .assert()
        .success();
    serde_json::from_slice(&output.get_output().stdout).unwrap()
}

#[test]
fn reward_accounts_cli_funded_genesis_and_network_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");
    let path = path.to_str().unwrap();
    run(&[
        "development-genesis",
        "--out",
        path,
        "--reward-epoch-blocks",
        "2",
    ]);
    let summary = run(&["genesis-check", "--genesis", path]);
    let g = summary["genesis_allocated_atoms"].as_u64().unwrap();
    let b = summary["remaining_mining_atoms"].as_u64().unwrap();
    assert_eq!(g, 2000 * 100_000_000);
    assert_eq!(g + b, 21_000_000 * 100_000_000);
    assert_eq!(summary["epoch_zero_first_claim_height"], 5);
    assert_eq!(summary["treasury_quorum"]["required"], 5);
    assert_eq!(summary["treasury_quorum"]["members"], 7);
    assert_eq!(summary["runtime_activation"], false);
    let address = summary["treasury_address"].as_str().unwrap();
    assert!(address.starts_with("heg_test1"));
    assert_eq!(
        run(&["address-check", "--genesis", path, "--address", address])["kind"],
        "public-account"
    );
    let mut other: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let first = other["network"]["discriminator"][0].as_u64().unwrap();
    other["network"]["discriminator"][0] = Value::from(first ^ 1);
    let alternate = dir.path().join("other-network.json");
    fs::write(&alternate, serde_json::to_vec(&other).unwrap()).unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args([
            "address-check",
            "--genesis",
            alternate.to_str().unwrap(),
            "--address",
            address,
        ])
        .assert()
        .failure();
}

#[test]
fn reward_accounts_cli_never_overwrites_existing_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");
    fs::write(&path, b"existing operator file").unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args(["development-genesis", "--out", path.to_str().unwrap()])
        .assert()
        .failure();
    assert_eq!(fs::read(path).unwrap(), b"existing operator file");
}

#[test]
fn reward_accounts_offline_review_sign_combine_and_replay_bindings() {
    use codec::Encode;
    use protocol_reward_accounts::*;
    use synthetic_crypto::{
        hash384::{ProofCommitment48, RulesHash48},
        ml_dsa::MlDsaSecretKey,
        traits::SigningKey,
    };
    use wallet::{NetworkShieldedAddress, RootSecret};
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("account.key");
    let secret = secret.to_str().unwrap();
    let policy: AccountPolicy =
        serde_json::from_value(run(&["keygen", "--secret-out", secret])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let key = MlDsaSecretKey::from_bytes(&fs::read(secret).unwrap()).unwrap();
    let policy_path = dir.path().join("policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let g = RewardAccountsGenesis {
        network: AddressNetwork {
            class: NetworkClass::Testnet,
            discriminator: [9; 32],
        },
        reward_epoch_blocks: 2,
        treasury_policy: policy.clone(),
        allocations: BoundedVec::new(vec![GenesisAllocation {
            account: policy.identifier().unwrap(),
            amount: 100 * COIN,
        }])
        .unwrap(),
    };
    let genesis_path = dir.path().join("genesis.json");
    fs::write(&genesis_path, serde_json::to_vec(&g).unwrap()).unwrap();
    let context = AccountChainContext {
        chain_id: [1; 32],
        genesis_hash: [2; 32],
        genesis_config_hash: RulesHash48::new(g.commitment().unwrap()),
    };
    let address = NetworkShieldedAddress::from_recipient(
        g.network,
        RootSecret::from_bytes([55; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address(),
    )
    .unwrap();
    let mut claim = AccountClaim {
        context: context.clone(),
        account: policy.identifier().unwrap(),
        policy_generation: 0,
        sequence: 0,
        amount: 10 * COIN,
        fee: 1000,
        recipient: BoundedVec::new(address.to_bytes().unwrap()).unwrap(),
        payout_binding: ProofCommitment48::new([3; 48]),
    };
    let intent_path = dir.path().join("intent.scale");
    fs::write(&intent_path, claim.encode()).unwrap();
    let chain = hex::encode(context.chain_id);
    let genesis = hex::encode(context.genesis_hash);
    let base = [
        "--genesis",
        genesis_path.to_str().unwrap(),
        "--policy",
        policy_path.to_str().unwrap(),
        "--intent",
        intent_path.to_str().unwrap(),
        "--kind",
        "claim",
        "--expected-chain-id",
        &chain,
        "--expected-genesis-hash",
        &genesis,
    ];
    let review = run(&[&["intent-review"][..], &base].concat());
    assert_eq!(review["details"]["recipient"], address.encode().unwrap());
    assert_eq!(review["details"]["amount_atoms"], 10 * COIN);
    assert_eq!(review["canonical_inclusion_checked"], false);
    let approval_path = dir.path().join("approval.json");
    let approval_path = approval_path.to_str().unwrap();
    run(&[
        &["intent-sign"][..],
        &base,
        &[
            "--secret-key",
            secret,
            "--signer-index",
            "0",
            "--out",
            approval_path,
        ],
    ]
    .concat());
    let approval: AccountApproval =
        serde_json::from_slice(&fs::read(approval_path).unwrap()).unwrap();
    policy
        .verify(
            &claim.authorization_digest(),
            std::slice::from_ref(&approval),
        )
        .unwrap();
    let combined = dir.path().join("combined.json");
    let combined = combined.to_str().unwrap();
    run(&[
        &["intent-combine"][..],
        &base,
        &["--approval", approval_path, "--out", combined],
    ]
    .concat());
    let approvals: Vec<AccountApproval> =
        serde_json::from_slice(&fs::read(combined).unwrap()).unwrap();
    assert_eq!(approvals, vec![approval]);
    let rejected = dir.path().join("rejected.json");
    let rejected = rejected.to_str().unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args(
            [
                &["intent-combine"][..],
                &base,
                &[
                    "--approval",
                    approval_path,
                    "--approval",
                    approval_path,
                    "--out",
                    rejected,
                ],
            ]
            .concat(),
        )
        .assert()
        .failure();
    assert!(!std::path::Path::new(rejected).exists());
    claim.fee += 1;
    fs::write(&intent_path, claim.encode()).unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args(
            [
                &["intent-combine"][..],
                &base,
                &["--approval", approval_path, "--out", rejected],
            ]
            .concat(),
        )
        .assert()
        .failure();
    let mut wrong = base;
    wrong[9] = "0000000000000000000000000000000000000000000000000000000000000001";
    Command::cargo_bin("reward-account")
        .unwrap()
        .args(
            [
                &["intent-sign"][..],
                &wrong,
                &[
                    "--secret-key",
                    secret,
                    "--signer-index",
                    "0",
                    "--out",
                    rejected,
                ],
            ]
            .concat(),
        )
        .assert()
        .failure();
    assert!(!std::path::Path::new(rejected).exists());
    // The treasury's fixed identity differs from the committee's ordinary
    // policy-hash account, but uses the configured committee for generation 0.
    let mut treasury_claim = claim.clone();
    treasury_claim.account = protocol_treasury_account_id();
    fs::write(&intent_path, treasury_claim.encode()).unwrap();
    let review = run(&[&["intent-review"][..], &base].concat());
    assert_eq!(
        review["account"],
        PublicAccountAddress {
            network: g.network,
            policy: protocol_treasury_account_id(),
        }
        .encode()
        .unwrap()
    );
    let treasury_out = dir.path().join("treasury-approval.json");
    run(&[
        &["intent-sign"][..],
        &base,
        &[
            "--secret-key",
            secret,
            "--signer-index",
            "0",
            "--out",
            treasury_out.to_str().unwrap(),
        ],
    ]
    .concat());
    let treasury_approval: AccountApproval =
        serde_json::from_slice(&fs::read(treasury_out).unwrap()).unwrap();
    policy
        .verify(&treasury_claim.authorization_digest(), &[treasury_approval])
        .unwrap();
    // The fork uses a distinct signing domain and retains the configured N/M.
    let next = AccountPolicy::single(
        &MlDsaSecretKey::generate_deterministic(b"new offline fork test").verify_key(),
    );
    let fork = TreasuryForkIntent {
        context,
        current_generation: 0,
        activation_height: 5,
        successor_rules: RulesHash48::new([4; 48]),
        successor_policy: next,
    };
    fs::write(&intent_path, fork.encode()).unwrap();
    let mut fork_base = base;
    fork_base[7] = "treasury-fork";
    let fork_out = dir.path().join("fork-approval.json");
    let fork_out = fork_out.to_str().unwrap();
    run(&[
        &["intent-sign"][..],
        &fork_base,
        &[
            "--secret-key",
            secret,
            "--signer-index",
            "0",
            "--out",
            fork_out,
        ],
    ]
    .concat());
    let approval: AccountApproval = serde_json::from_slice(&fs::read(fork_out).unwrap()).unwrap();
    policy
        .verify(&fork.authorization_digest(), &[approval])
        .unwrap();
    assert_eq!(
        key.verify_key(),
        MlDsaSecretKey::from_bytes(&fs::read(secret).unwrap())
            .unwrap()
            .verify_key()
    );
}
