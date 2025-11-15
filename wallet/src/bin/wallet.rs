use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    hashing::Felt,
    note::{InputNoteWitness, OutputNoteWitness},
    witness::TransactionWitness,
};

use wallet::{
    address::ShieldedAddress,
    keys::{DerivedKeys, RootSecret},
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    viewing::{IncomingViewingKey, OutgoingViewingKey},
};

#[derive(Parser)]
#[command(name = "wallet", version, about = "Synthetic currency wallet tooling")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Address {
        #[arg(long)]
        root: String,
        #[arg(long)]
        index: u32,
    },
    #[command(name = "tx-craft")]
    TxCraft {
        #[arg(long)]
        root: String,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        recipients: PathBuf,
        #[arg(long, default_value_t = 0)]
        merkle_root: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long)]
        witness_out: PathBuf,
        #[arg(long)]
        ciphertext_out: PathBuf,
        #[arg(long)]
        rng_seed: Option<u64>,
    },
    Scan {
        #[arg(long)]
        ivk: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { count, out } => cmd_generate(count, out),
        Commands::Address { root, index } => cmd_address(&root, index),
        Commands::TxCraft {
            root,
            inputs,
            recipients,
            merkle_root,
            fee,
            witness_out,
            ciphertext_out,
            rng_seed,
        } => cmd_tx_craft(TxCraftParams {
            root_hex: &root,
            inputs_path: inputs.as_path(),
            recipients_path: recipients.as_path(),
            witness_out: witness_out.as_path(),
            ciphertext_out: ciphertext_out.as_path(),
            merkle_root,
            fee,
            rng_seed,
        }),
        Commands::Scan { ivk, ledger, out } => cmd_scan(&ivk, &ledger, out.as_deref()),
    }
}

fn cmd_generate(count: u32, out: Option<PathBuf>) -> Result<()> {
    let mut rng = StdRng::from_entropy();
    let root = RootSecret::from_rng(&mut rng);
    let keys = root.derive();
    let export = WalletExport::from_keys(&root, &keys, count)?;
    let json = serde_json::to_string_pretty(&export)?;
    if let Some(path) = out {
        fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn cmd_address(root_hex: &str, index: u32) -> Result<()> {
    let root = parse_root(root_hex)?;
    let keys = root.derive();
    let address = map_wallet(keys.address(index))?.shielded_address();
    println!("{}", map_wallet(address.encode())?);
    Ok(())
}

struct TxCraftParams<'a> {
    root_hex: &'a str,
    inputs_path: &'a Path,
    recipients_path: &'a Path,
    witness_out: &'a Path,
    ciphertext_out: &'a Path,
    merkle_root: u64,
    fee: u64,
    rng_seed: Option<u64>,
}

fn cmd_tx_craft(params: TxCraftParams<'_>) -> Result<()> {
    let root = parse_root(params.root_hex)?;
    let keys = root.derive();
    let inputs: Vec<InputNoteWitness> = read_json(params.inputs_path)?;
    let recipients: Vec<RecipientSpec> = read_json(params.recipients_path)?;
    let mut rng = match params.rng_seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    for spec in recipients {
        let address = map_wallet(ShieldedAddress::decode(&spec.address))?;
        let memo_bytes = spec
            .memo
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(|err| anyhow!(err.to_string()))?
            .unwrap_or_default();
        let note = NotePlaintext::random(
            spec.value,
            spec.asset_id,
            MemoPlaintext::new(memo_bytes),
            &mut rng,
        );
        let ciphertext = map_wallet(NoteCiphertext::encrypt(&address, &note, &mut rng))?;
        ciphertexts.push(ciphertext);
        outputs.push(OutputNoteWitness {
            note: note.to_note_data(address.pk_recipient),
        });
    }
    let witness = TransactionWitness {
        inputs,
        outputs,
        sk_spend: keys.spend.to_bytes(),
        merkle_root: Felt::new(params.merkle_root),
        fee: params.fee,
    };
    write_json(params.witness_out, &witness)?;
    write_json(params.ciphertext_out, &ciphertexts)?;
    Ok(())
}

fn cmd_scan(ivk_path: &Path, ledger_path: &Path, out: Option<&Path>) -> Result<()> {
    let ivk: IncomingViewingKey = read_json(ivk_path)?;
    let ciphertexts: Vec<NoteCiphertext> = read_json(ledger_path)?;
    let mut totals: BTreeMap<u64, u64> = BTreeMap::new();
    let mut recovered = Vec::new();
    for (idx, ct) in ciphertexts.iter().enumerate() {
        if let Ok(note) = ivk.decrypt_note(ct) {
            *totals.entry(note.note.asset_id).or_default() += note.note.value;
            recovered.push(NoteSummary {
                index: idx as u64,
                asset_id: note.note.asset_id,
                value: note.note.value,
                address: map_wallet(note.address.encode())?,
            });
        }
    }
    let report = BalanceReport { totals, recovered };
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out {
        fs::write(path, &json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn parse_root(hex_str: &str) -> Result<RootSecret> {
    let bytes = hex::decode(hex_str.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("root secret must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(RootSecret::from_bytes(arr))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_slice(&data)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Serialize)]
struct WalletExport {
    root_secret: String,
    incoming_viewing_key: IncomingViewingKey,
    outgoing_viewing_key: OutgoingViewingKey,
    addresses: Vec<AddressExport>,
}

impl WalletExport {
    fn from_keys(root: &RootSecret, keys: &DerivedKeys, count: u32) -> Result<Self> {
        let root_hex = hex::encode(root.to_bytes());
        let ivk = IncomingViewingKey::from_keys(keys);
        let ovk = OutgoingViewingKey::from_keys(keys);
        let mut addresses = Vec::new();
        for index in 0..count {
            let shield = map_wallet(keys.address(index))?.shielded_address();
            let encoded = map_wallet(shield.encode())?;
            addresses.push(AddressExport {
                index,
                address: encoded,
            });
        }
        Ok(Self {
            root_secret: root_hex,
            incoming_viewing_key: ivk,
            outgoing_viewing_key: ovk,
            addresses,
        })
    }
}

fn map_wallet<T>(value: std::result::Result<T, wallet::WalletError>) -> Result<T> {
    value.map_err(|err| anyhow!(err.to_string()))
}

#[derive(Serialize)]
struct AddressExport {
    index: u32,
    address: String,
}

#[derive(Deserialize)]
struct RecipientSpec {
    address: String,
    value: u64,
    asset_id: u64,
    memo: Option<String>,
}

#[derive(Serialize)]
struct NoteSummary {
    index: u64,
    asset_id: u64,
    value: u64,
    address: String,
}

#[derive(Serialize)]
struct BalanceReport {
    totals: BTreeMap<u64, u64>,
    recovered: Vec<NoteSummary>,
}
