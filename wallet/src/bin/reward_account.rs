//! Offline public-account/genesis tooling. No daemon admission or proof bypass.
use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
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
