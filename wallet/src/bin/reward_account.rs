//! Offline public-account/genesis tooling. No daemon admission or proof bypass.
use anyhow::{ensure, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use codec::{Decode, Encode};
use protocol_reward_accounts::*;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use synthetic_crypto::{ml_dsa::MlDsaSecretKey, traits::SigningKey};
use wallet::NetworkShieldedAddress;
use zeroize::Zeroizing;

#[derive(Clone, Copy, ValueEnum)]
enum IntentKind {
    Claim,
    TreasuryFork,
}

#[derive(Args)]
struct IntentArgs {
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    /// Exact canonical SCALE AccountClaim or TreasuryForkIntent bytes.
    #[arg(long)]
    intent: PathBuf,
    #[arg(long, value_enum)]
    kind: IntentKind,
    /// Independently checked chain identity; never inferred from the intent.
    #[arg(long)]
    expected_chain_id: String,
    #[arg(long)]
    expected_genesis_hash: String,
}

#[derive(Parser)]
#[command(
    name = "reward-account",
    about = "Inspect reset reward-account genesis and network-aware addresses"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Generate a new account key; writes a private file, prints public policy.
    Keygen {
        #[arg(long)]
        secret_out: PathBuf,
    },
    /// Display exact signed network, amount, fee, recipient and intent hash.
    IntentReview {
        #[command(flatten)]
        args: IntentArgs,
    },
    /// Sign a reviewed typed intent without exposing key bytes to a node.
    IntentSign {
        #[command(flatten)]
        args: IntentArgs,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        signer_index: u8,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a complete quorum and emit approvals in canonical signer order.
    IntentCombine {
        #[command(flatten)]
        args: IntentArgs,
        #[arg(long, required = true)]
        approval: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Validate an allocation budget and show its network and reward schedule.
    GenesisCheck {
        #[arg(long)]
        genesis: PathBuf,
    },
    /// Create a disposable test network with KNOWN, INSECURE fixture keys.
    DevelopmentGenesis {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 2)]
        reward_epoch_blocks: u64,
        #[arg(long,default_value_t=1_000*COIN)]
        account_atoms: u64,
    },
    /// Encode a policy into an account address for the selected genesis.
    AddressFromPolicy {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Inspect an account or shielded address, rejecting other networks.
    AddressCheck {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        address: String,
    },
}
fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create new file (existing files are never overwritten)")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn bounded_read(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let file = File::open(path).context("open input file")?;
    ensure!(file.metadata()?.is_file(), "input must be a regular file");
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= cap, "input exceeds byte limit");
    Ok(bytes)
}
fn read_signing_key(path: &Path) -> Result<MlDsaSecretKey> {
    let file = File::open(path).context("open signing key")?;
    ensure!(
        file.metadata()?.is_file(),
        "signing key must be a regular file"
    );
    let cap = synthetic_crypto::ml_dsa::ML_DSA_SECRET_KEY_LEN as u64;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(cap + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == cap, "invalid signing key length");
    Ok(MlDsaSecretKey::from_bytes(&bytes)?)
}
fn exact_scale<T: Decode + Encode>(path: &Path) -> Result<T> {
    let bytes = bounded_read(path, 64 * 1024)?;
    let mut cursor = bytes.as_slice();
    let value = T::decode(&mut cursor).map_err(|_| anyhow::anyhow!("invalid intent encoding"))?;
    ensure!(
        cursor.is_empty() && value.encode() == bytes,
        "noncanonical intent encoding"
    );
    Ok(value)
}
fn reviewed(args: &IntentArgs) -> Result<(AccountPolicy, [u8; 48], serde_json::Value)> {
    let g = checked_genesis(&args.genesis)?;
    let policy: AccountPolicy = read_json(&args.policy)?;
    let account = policy.identifier()?;
    let chain: [u8; 32] = hex::decode(&args.expected_chain_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected chain id must contain 32 bytes"))?;
    let genesis: [u8; 32] = hex::decode(&args.expected_genesis_hash)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected genesis hash must contain 32 bytes"))?;
    let (context, digest, details) = match args.kind {
        IntentKind::Claim => {
            let claim: AccountClaim = exact_scale(&args.intent)?;
            ensure!(
                claim.account == account,
                "claim account differs from authorization policy"
            );
            ensure!(
                claim.amount > 0
                    && claim
                        .amount
                        .checked_add(claim.fee)
                        .is_some_and(|n| n <= MAX_SUPPLY),
                "invalid claim amount or fee"
            );
            ensure!(
                claim.payout_binding != synthetic_crypto::hash384::ProofCommitment48::ZERO,
                "claim has no payout binding"
            );
            let recipient = NetworkShieldedAddress::from_bytes(&claim.recipient, g.network)?;
            let digest = claim.authorization_digest();
            let details = json!({"kind":"claim","amount_atoms":claim.amount,"fee_atoms":claim.fee,
                "sequence":claim.sequence,"policy_generation":claim.policy_generation,
                "recipient":recipient.encode()?,"payout_binding":hex::encode(claim.payout_binding.as_bytes())});
            (claim.context, digest, details)
        }
        IntentKind::TreasuryFork => {
            let fork: TreasuryForkIntent = exact_scale(&args.intent)?;
            fork.successor_policy.validate()?;
            ensure!(
                fork.activation_height > 0
                    && fork.successor_rules != synthetic_crypto::hash384::RulesHash48::ZERO,
                "invalid fork height or rules"
            );
            ensure!(
                fork.successor_policy.required() == policy.required()
                    && fork.successor_policy.signer_hashes().len() == policy.signer_hashes().len(),
                "treasury fork must retain N and M"
            );
            let successor = fork.successor_policy.identifier()?;
            ensure!(
                successor != account,
                "treasury fork must replace the policy"
            );
            let digest = fork.authorization_digest();
            let details = json!({"kind":"treasury-fork","activation_height":fork.activation_height,
                "current_generation":fork.current_generation,"successor_rules":hex::encode(fork.successor_rules.as_bytes()),
                "successor_address":PublicAccountAddress{network:g.network,policy:successor}.encode()?,"successor_policy":fork.successor_policy});
            (fork.context, digest, details)
        }
    };
    context.validate(&g)?;
    ensure!(
        context.chain_id == chain && context.genesis_hash == genesis,
        "intent differs from independently expected chain/genesis"
    );
    let review = json!({"account":PublicAccountAddress{network:g.network,policy:account}.encode()?,
        "chain_id":hex::encode(chain),"genesis_hash":hex::encode(genesis),"network":g.network,
        "intent_digest":hex::encode(digest),"policy":policy,"details":details,
        "canonical_inclusion_checked":false});
    Ok((policy, digest, review))
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    const CAP: u64 = 32 * 1024 * 1024;
    let file = File::open(path).context("open public configuration")?;
    ensure!(
        file.metadata()?.is_file(),
        "configuration must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(CAP + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= CAP,
        "public configuration exceeds byte limit"
    );
    Ok(serde_json::from_slice(&bytes).context("decode public configuration")?)
}
fn checked_genesis(path: &Path) -> Result<RewardAccountsGenesis> {
    let g: RewardAccountsGenesis = read_json(path)?;
    g.validate()?;
    Ok(g)
}
fn fixture_key(i: u8) -> MlDsaSecretKey {
    let mut seed = b"hegemon.reward-accounts.DISPOSABLE.FIXTURE.v1/".to_vec();
    seed.push(i);
    MlDsaSecretKey::generate_deterministic(&seed)
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { secret_out } => {
            let mut seed = Zeroizing::new([0u8; 64]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
            let key = MlDsaSecretKey::generate_deterministic(seed.as_ref());
            let secret = Zeroizing::new(key.to_bytes());
            create_private_file(&secret_out, &secret)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&AccountPolicy::single(&key.verify_key()))?
            );
        }
        Command::IntentReview { args } => {
            let (_, _, review) = reviewed(&args)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Command::IntentSign {
            args,
            secret_key,
            signer_index,
            out,
        } => {
            let (policy, digest, review) = reviewed(&args)?;
            let key = read_signing_key(&secret_key)?;
            ensure!(
                policy.signer_hashes().get(signer_index as usize)
                    == Some(&account_key_hash(&key.verify_key())),
                "key does not own selected signer slot"
            );
            let approval = AccountApproval::sign(signer_index, &key, &digest);
            create_private_file(&out, &serde_json::to_vec_pretty(&approval)?)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Command::IntentCombine {
            args,
            approval,
            out,
        } => {
            let (policy, digest, review) = reviewed(&args)?;
            ensure!(approval.len() <= MAX_ACCOUNT_SIGNERS, "too many approvals");
            let mut approvals = approval
                .iter()
                .map(|p| read_json::<AccountApproval>(p))
                .collect::<Result<Vec<_>>>()?;
            approvals.sort_by_key(|a| a.signer_index);
            policy.verify(&digest, &approvals)?;
            create_private_file(&out, &serde_json::to_vec_pretty(&approvals)?)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
        }
        Command::GenesisCheck { genesis } => {
            let g = checked_genesis(&genesis)?;
            let total = g.validate()?;
            let issuance = g.issuance()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema":REWARD_GENESIS_SCHEMA,"network":g.network,
                    "genesis_commitment":hex::encode(g.commitment()?),
                    "reward_epoch_blocks":g.reward_epoch_blocks,
                    "epoch_zero_first_claim_height":g.epochs()?.release_height(0)?,
                    "allocation_count":g.allocations.len(),"genesis_allocated_atoms":total,
                    "remaining_mining_atoms":issuance.mining_budget(),"max_supply_atoms":MAX_SUPPLY,
                    "block_one_subsidy_atoms":issuance.subsidy(1),
                    "treasury_address":PublicAccountAddress{network:g.network,policy:g.treasury_account()?}.encode()?,
                    "treasury_quorum":{"required":g.treasury_policy.required(),"members":g.treasury_policy.signer_hashes().len()},
                    "runtime_activation":false
                }))?
            );
        }
        Command::DevelopmentGenesis {
            out,
            reward_epoch_blocks,
            account_atoms,
        } => {
            ensure!(
                account_atoms > 0 && account_atoms <= MAX_SUPPLY / 2,
                "two fixture allocations must fit the supply budget"
            );
            let keys: Vec<_> = (0..9).map(fixture_key).collect();
            let treasury = AccountPolicy::threshold(
                5,
                keys[..7]
                    .iter()
                    .map(|k| account_key_hash(&k.verify_key()))
                    .collect(),
            )?;
            let mut allocations = keys[7..]
                .iter()
                .map(|k| {
                    Ok(GenesisAllocation {
                        account: AccountPolicy::single(&k.verify_key()).identifier()?,
                        amount: account_atoms,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            allocations.sort_by_key(|r| r.account);
            let mut discriminator = [0; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut discriminator);
            let g = RewardAccountsGenesis {
                network: AddressNetwork {
                    class: NetworkClass::Testnet,
                    discriminator,
                },
                reward_epoch_blocks,
                treasury_policy: treasury,
                allocations: BoundedVec::new(allocations).map_err(anyhow::Error::msg)?,
            };
            g.validate()?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&out)
                .context("create new public genesis (existing files are never overwritten)")?;
            file.write_all(&serde_json::to_vec_pretty(&g)?)?;
            file.write_all(b"\n")?;
            eprintln!("DISPOSABLE DEVELOPMENT GENESIS: fixture signing keys are public; never use for real funds.");
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"path":out,"network":g.network,"runtime_activation":false})
                )?
            );
        }
        Command::AddressFromPolicy { genesis, policy } => {
            let g = checked_genesis(&genesis)?;
            let policy: AccountPolicy = read_json(&policy)?;
            let id = policy.identifier()?;
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"address":PublicAccountAddress{network:g.network,policy:id}.encode()?,"policy_id":hex::encode(id.as_bytes())})
                )?
            );
        }
        Command::AddressCheck { genesis, address } => {
            let g = checked_genesis(&genesis)?;
            let output = if let Ok(a) = PublicAccountAddress::decode(&address, g.network) {
                json!({"kind":"public-account","address":a.encode()?,"policy_id":hex::encode(a.policy.as_bytes()),"network":g.network})
            } else {
                let a = NetworkShieldedAddress::decode(&address, g.network)?;
                json!({"kind":"shielded","address":a.encode()?,"network":g.network})
            };
            println!("{}", serde_json::to_string(&output)?);
        }
    }
    Ok(())
}
