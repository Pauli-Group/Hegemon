//! Opt-in, expensive real-node recovery qualification. No fixture verifier,
//! capability override, root setter, or stored-proof acceptance shortcut.
//! Root wires this as #[cfg(all(test, feature="development-candidate"))] mod.
use super::*;
use codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path, time::Instant};
use transaction_circuit::{
    asset_policy_admin_v1 as old_admin, asset_recovery_admin_v1 as admin,
    asset_recovery_capsule_v1 as capsule, asset_recovery_spend_v1 as spend,
    asset_recovery_wire_v1 as wire,
    asset_spend_v1::{
        self as asset, AssetCredentialWitness, AssetSpendPublic, BURN, MINT, TRANSFER,
    },
    private_spend::{self, Note, PrivateInput},
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
        poseidon2_v8_single_key_authorization_digest,
    },
};
use transaction_core::{
    asset_recovery_v1 as recovery,
    asset_registry_v1::AssetPolicyV1,
    poseidon2_width16::Felt,
    stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
};
use wallet::{
    asset_recovery_build_v1 as build, asset_recovery_v1::RecoveryNoteMaterialV1,
    asset_spend_v1::AssetNotePayload,
};
type D = [u64; 7];
const ASSET: u32 = 1001;
const POLICY: D = [71; 7];
// Public disposable test credentials. Never production or operator material.
const ISSUER: D = [401, 402, 403, 404, 405, 406, 407];
const ADMIN: D = [0, 2, 3, 4, 5, 6, 7];
const ARCHIVE: [u8; 32] = [23; 32];
const DELEGATE1: D = [84; 7];
const DELEGATE2: D = [85; 7];
const DELEGATE_RECIPIENT1: [u64; 4] = [501; 4];
const DELEGATE_RECIPIENT2: [u64; 4] = [502; 4];
const EXPIRES: u64 = 9_999;
// Explicit disposable Development network target; every seal/import still runs
// the actual consensus PoW verifier and strict 48-byte work fork choice.
const TEST_POW_BITS: u32 = 0x207f_ffff;

fn words(d: [Felt; 7]) -> D {
    d.map(|x| x.as_canonical_u64())
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn recipient(keys: &wallet::DerivedKeys) -> [u64; 4] {
    let address = keys.poseidon2_v8_address(0).unwrap().shielded_address();
    core::array::from_fn(|i| {
        u64::from_le_bytes(address.pk_recipient[i * 8..i * 8 + 8].try_into().unwrap())
    })
}
fn authority(keys: &wallet::DerivedKeys) -> D {
    poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words().unwrap()).unwrap()
}
fn note_opening(n: Note) -> crypto::private_note_payload::NoteOpening {
    crypto::private_note_payload::NoteOpening {
        value: n.value,
        asset_id: n.asset_id,
        recipient_key: n.recipient_key,
        authorization_key: n.authorization_key,
        rho: n.rho,
        randomness: n.randomness,
    }
}

struct Credentials {
    root: D,
    paths: Vec<AssetCredentialWitness>,
    holder_revoked: bool,
}
impl Credentials {
    fn new(a: &wallet::DerivedKeys, b: &wallet::DerivedKeys, revoke_holder: Option<usize>) -> Self {
        let entries = [
            (recipient(a), authority(a)),
            (recipient(b), authority(b)),
            (
                DELEGATE_RECIPIENT1,
                recovery::delegate_action_commitment(DELEGATE1).unwrap(),
            ),
            (
                DELEGATE_RECIPIENT2,
                recovery::delegate_action_commitment(DELEGATE2).unwrap(),
            ),
        ];
        let mut layer = vec![[0; 7]; 16];
        for (i, (r, key)) in entries.into_iter().enumerate() {
            if Some(i) != revoke_holder {
                layer[i] = asset::credential_leaf(ASSET, 1, r, key, EXPIRES).unwrap();
            }
        }
        let mut paths = vec![Vec::new(); 4];
        for level in 0..4 {
            for i in 0..4 {
                paths[i].push(layer[(i >> level) ^ 1]);
            }
            layer = layer
                .chunks_exact(2)
                .map(|p| asset::credential_node(level, p[0], p[1]).unwrap())
                .collect();
        }
        Self {
            root: layer[0],
            holder_revoked: revoke_holder == Some(0),
            paths: paths
                .into_iter()
                .enumerate()
                .map(|(i, siblings)| AssetCredentialWitness {
                    index: i as u32,
                    expires_at: EXPIRES,
                    siblings,
                })
                .collect(),
        }
    }
}
fn genesis_row(credentials: &Credentials) -> AssetPolicyV1 {
    let tag = |x| core::array::from_fn(|i| Felt::from_u64(x + i as u64));
    AssetPolicyV1 {
        config: StablecoinPoseidon2V8Config {
            asset_id: ASSET,
            policy_version: 1,
            active: true,
            enabled_at: 1,
            retired_at: None,
            issuer_commitment: asset::issuer_commitment(ASSET, 1, ISSUER)
                .unwrap()
                .map(Felt::from_u64),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_submitted_at: 1,
            oracle_max_age: 20_000,
            oracle_price_numerator: 2,
            oracle_price_denominator: 1,
            collateral_amount: 10_000,
            attestation_created_at: 1,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 20_000,
            policy_admin_commitment: old_admin::policy_admin_commitment(ASSET, ADMIN)
                .unwrap()
                .map(Felt::from_u64),
            oracle_authority_commitment: tag(201),
            attestation_authority_commitment: tag(301),
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: tag(401),
        },
        counters: StablecoinPoseidon2V8Counters::default(),
        credential_root: credentials.root.map(Felt::from_u64),
        credential_depth: 4,
        frozen: false,
        mint_enabled: true,
    }
}
fn network(
    fee: &wallet::DerivedKeys,
    credentials: &Credentials,
) -> network_profile::NativeNetworkIdentity {
    let address = fee
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address()
        .encode()
        .unwrap();
    let mut manifest =
        network_profile::private_spend_only_development_candidate_manifest(&address).unwrap();
    manifest.pow_bits = TEST_POW_BITS;
    let source = manifest.development_candidate.as_mut().unwrap();
    source.max_proof_actions_per_block = 8; // Five actual recovery proofs plus reward capacity.
    source.max_total_proofs = 128;
    let row = genesis_row(credentials);
    source.assets = Some(
        network_profile::DevelopmentAssetsV1::compiled(vec![hex::encode(
            asset_state::encode_asset_policy_row(&row).unwrap(),
        )])
        .unwrap(),
    );
    source.recovery = Some(
        asset_recovery_profile::DevelopmentRecoveryV1::compiled(vec![
            asset_recovery_profile::RecoveryGenesisConfigV1 {
                asset_id: ASSET,
                stable_policy_id: POLICY,
                policy_admin_commitment: words(row.config.policy_admin_commitment),
                archive_key_commitment: recovery::archive_key_commitment(&ARCHIVE).unwrap(),
                maximum_powers_bits: 3,
                initial_delegate_commitment: recovery::delegate_action_commitment(DELEGATE1)
                    .unwrap(),
                initial_revoked: false,
                initial_powers_bits: 3,
            },
        ])
        .unwrap(),
    );
    // This is the production manifest/catalog gate. Never substitute a test
    // authority constructor if actual source geometry is not yet qualified.
    network_profile::NativeNetworkIdentity::from_manifest(manifest).unwrap()
}
fn config(
    path: &Path,
    network: &network_profile::NativeNetworkIdentity,
    fee: &wallet::DerivedKeys,
) -> NativeConfig {
    NativeConfig {
        network: network.clone(),
        dev: true,
        tmp: false,
        base_path: path.into(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        p2p_listen_addr: "127.0.0.1:0".into(),
        node_name: "actual-recovery-lifecycle".into(),
        rpc_methods: "unsafe".into(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: Some(
            fee.poseidon2_v8_address(0)
                .unwrap()
                .shielded_address()
                .encode()
                .unwrap(),
        ),
        pow_bits: TEST_POW_BITS,
    }
}
fn store(node: &NativeNode) -> poseidon2_v8_state::Poseidon2V8StateStore {
    let genesis = node.load_canonical_block_at_height_unverified(0).unwrap();
    let binding = node.native_proof_binding_for_replay().unwrap().unwrap();
    poseidon2_v8_state::Poseidon2V8StateStore::open_with_assets(
        &node.db,
        poseidon2_v8_state::Poseidon2V8Checkpoint::new(
            0,
            genesis.hash,
            binding.stablecoin_genesis_root(),
        ),
        binding.note_genesis_root(),
        node.poseidon2_v8_asset_genesis_bytes().unwrap().as_deref(),
    )
    .unwrap()
}
fn assets(node: &NativeNode) -> asset_state::AssetRegistryStateV1 {
    asset_state::AssetRegistryStateV1::decode_exact(&store(node).asset_tip().unwrap().unwrap())
        .unwrap()
}
#[derive(Clone, PartialEq, Eq)]
struct Canonical {
    height: u64,
    hash: [u8; 32],
    pool: poseidon2_v8_state::Poseidon2V8Checkpoint,
    note: poseidon2_v8_state::Poseidon2V8NoteTreeState,
    asset: Vec<u8>,
    proofs: u64,
}
fn snapshot(node: &NativeNode) -> Canonical {
    let s = store(node);
    let head = node.best_meta();
    Canonical {
        height: head.height,
        hash: head.hash,
        pool: s.tip().unwrap(),
        note: s.note_tip().unwrap(),
        asset: s.asset_tip().unwrap().unwrap(),
        proofs: s.proof_lifetime_count().unwrap().get(),
    }
}
fn assert_same(a: &NativeNode, b: &NativeNode) {
    assert!(snapshot(a) == snapshot(b));
    assert!(store(a).exact_rows_equal(&store(b)).unwrap());
}
// The retarget samples RETARGET_WINDOW-1 parent-to-anchor intervals.
// Whole-second 67s historical intervals give a 603s sample against the real
// 600s target. Retarget remains enabled without a synthetic rapid-chain /4
// escalation or a growing wall-clock future skew. No consensus knob changes.
const HISTORICAL_BLOCK_INTERVAL_MS: u64 = (consensus::reward::RETARGET_TIMESPAN_MS
    / (consensus::reward::RETARGET_WINDOW - 1))
    .div_ceil(1_000)
    * 1_000;
const MAX_MINING_ROUNDS_PER_BLOCK: u64 = 64;
fn mine_observed(node: &NativeNode) -> (NativeBlockMeta, u64) {
    let mut work = node.prepare_work().unwrap();
    let parent = node.best_meta();
    assert_eq!(work.parent_hash, parent.hash);
    retain_native_block(
        &node
            .load_canonical_block_at_height_unverified(parent.height)
            .unwrap(),
    );
    let timestamp_ms = node
        .config
        .network
        .genesis_timestamp_ms()
        .checked_add(
            work.height
                .checked_mul(HISTORICAL_BLOCK_INTERVAL_MS)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        timestamp_ms % 1_000,
        0,
        "ASIC timestamp must be integral seconds"
    );
    assert!(timestamp_ms > parent.timestamp_ms);
    assert!(
        timestamp_ms <= current_time_ms().saturating_add(consensus::reward::MAX_FUTURE_SKEW_MS),
        "historical fixture horizon exhausted; never bypass future-skew validation"
    );
    // Change only nTime and its committed prehash on this local template clone.
    // The source-selected chain id is mandatory: the constructor defaults to
    // the historical public-chain id before prepare_work overrides it too.
    work.timestamp_ms = timestamp_ms;
    let mut header = native_pow_header_from_parts(
        work.height,
        work.timestamp_ms,
        work.parent_hash,
        work.pow_bits,
        [0; 32],
        work.cumulative_work,
        &work.state_root,
        &work.kernel_root,
        &work.nullifier_root,
        &work.da_root,
        &work.extrinsics_root,
        &work.message_root,
        work.message_count,
        &work.header_mmr_root,
        work.header_mmr_len,
        work.supply_digest,
        work.tx_count,
    );
    header.chain_id = node.config.network.chain_id();
    work.pre_hash = header.pre_hash();
    let searched = mine_native_rounds(work.clone(), 0, MAX_MINING_ROUNDS_PER_BLOCK);
    let seal = searched
        .seal
        .expect("bounded actual scheduled-target PoW search");
    let block = node
        .import_mined_block(&work, seal)
        .unwrap()
        .expect("actual mined block must advance");
    assert_eq!(block.timestamp_ms, timestamp_ms);
    assert_eq!(block.pow_bits, work.pow_bits);
    retain_native_block(&block);
    (block, searched.hashes)
}
fn mine(node: &NativeNode) -> NativeBlockMeta {
    mine_observed(node).0
}
fn sync(from: &NativeNode, to: &NativeNode, first: u64) {
    for h in first..=from.best_height() {
        let meta = from.load_canonical_block_at_height_unverified(h).unwrap();
        retain_native_block(&meta);
        to.import_announced_block(meta).unwrap();
    }
}
fn rewards(
    block: &NativeBlockMeta,
) -> Vec<protocol_shielded_pool::poseidon2_v8_coinbase::Poseidon2V8CoinbaseNoteData> {
    let mut notes = Vec::new();
    for action in decode_block_actions(block).unwrap() {
        if action.action_id == ACTION_MINT_POSEIDON2_V8_REWARDS {
            let args: MintPoseidon2V8RewardsArgs =
                decode_scale_exact(&action.public_args, "recovery test rewards").unwrap();
            notes.push(args.miner_note);
            if let Some(n) = args.funding_note {
                notes.push(n)
            }
        } else if action.action_id == ACTION_MINT_POSEIDON2_V8_COINBASE {
            let args: MintPoseidon2V8CoinbaseArgs =
                decode_scale_exact(&action.public_args, "recovery test coinbase").unwrap();
            notes.push(args.miner_note);
        }
    }
    notes
}
fn canonical_notes(node: &NativeNode) -> Vec<D> {
    let mut notes = Vec::new();
    for h in 1..=node.best_height() {
        let block = node.load_canonical_block_at_height_unverified(h).unwrap();
        for action in decode_block_actions(&block).unwrap() {
            if action.action_id == asset_recovery_native::RECOVERY_SPEND_ACTION_ID {
                notes.extend(
                    wire::decode_spend_ref(&action.public_args)
                        .unwrap()
                        .public
                        .base
                        .commitments,
                );
            }
        }
        if h >= consensus::reward::COINBASE_MATURITY {
            let origin = h + 1 - consensus::reward::COINBASE_MATURITY;
            for n in rewards(
                &node
                    .load_canonical_block_at_height_unverified(origin)
                    .unwrap(),
            ) {
                notes.push(n.commitment)
            }
        }
    }
    assert_eq!(
        notes.len() as u64,
        store(node).note_tip().unwrap().leaf_count()
    );
    assert_eq!(
        membership(&notes, 0).0,
        store(node).note_tip().unwrap().root().limbs()
    );
    notes
}
fn membership(notes: &[D], position: u32) -> (D, [D; 32]) {
    let defaults = poseidon2_v8_default_note_nodes();
    let mut layer = notes
        .iter()
        .copied()
        .enumerate()
        .map(|(i, d)| (i as u32, d))
        .collect::<BTreeMap<_, _>>();
    let mut index = position;
    let mut path = [[0; 7]; 32];
    for level in 0..32 {
        path[level] = *layer.get(&(index ^ 1)).unwrap_or(&defaults[level]);
        let mut next = BTreeMap::new();
        for key in layer.keys() {
            let p = key >> 1;
            next.entry(p).or_insert_with(|| {
                poseidon2_v8_note_tree_compress(
                    *layer.get(&(p * 2)).unwrap_or(&defaults[level]),
                    *layer.get(&(p * 2 + 1)).unwrap_or(&defaults[level]),
                )
            });
        }
        layer = next;
        index >>= 1;
    }
    (*layer.get(&0).unwrap_or(&defaults[32]), path)
}
#[derive(Clone)]
struct Fee {
    note: Note,
    position: u32,
    key: [u64; 5],
    legacy: u64,
}
fn first_fee(node: &NativeNode, fee: &wallet::DerivedKeys) -> Fee {
    let first = node.load_canonical_block_at_height_unverified(1).unwrap();
    let note = wallet::poseidon2_v8_coinbase::public_poseidon2_v8_reward_opening(
        &rewards(&first)[0],
        &fee.poseidon2_v8_address(0).unwrap().shielded_address(),
    )
    .unwrap();
    let cm = private_spend::note_commitment(note).unwrap();
    let notes = canonical_notes(node);
    Fee {
        note,
        position: notes.iter().position(|x| *x == cm).unwrap() as u32,
        key: fee.spend.poseidon2_v8_words().unwrap(),
        legacy: 1,
    }
}
struct Built {
    body: Vec<u8>,
    public: spend::Public,
    outputs: [RecoveryNoteMaterialV1; 2],
    fee_note: Note,
    next_position: u32,
}
impl Built {
    fn change_fee(&self, key: [u64; 5]) -> Fee {
        Fee {
            note: self.fee_note,
            position: self.next_position + 2,
            key,
            legacy: 0,
        }
    }
}
// With explicit fresh evidence output, keep only disposable node chain state
// and public block metadata. Wallet/provider request and key scratch stays in
// its existing automatically removed TempDirs.
enum NativeLifecycleDirectory {
    Temporary(tempfile::TempDir),
    Retained(PathBuf),
}
impl NativeLifecycleDirectory {
    fn path(&self) -> &Path {
        match self {
            Self::Temporary(dir) => dir.path(),
            Self::Retained(path) => path,
        }
    }
}
fn create_native_evidence_directory(path: &Path) {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).unwrap();
}
fn retain_native_block(meta: &NativeBlockMeta) {
    use std::io::Write;
    let Some(root) = std::env::var_os("HEGEMON_RECOVERY_LIFECYCLE_OUT").map(PathBuf::from) else {
        return;
    };
    assert!(
        root.is_dir(),
        "Evidence::new must create the fresh evidence root first"
    );
    let dir = root.join("native-block-metas");
    if !dir.exists() {
        create_native_evidence_directory(&dir);
    }
    // This complete internal NativeBlockMeta retains exact header/seal/action
    // bytes, including randomized reward openings/ciphertexts. It is evidence,
    // not an alternate network format or an admission authority.
    let bytes = bincode::serialize(meta).unwrap();
    let path = dir.join(format!(
        "{:08}-{}.native-meta.bin",
        meta.height,
        hex::encode(meta.hash)
    ));
    if path.exists() {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        return;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}

struct Evidence {
    dir: Option<PathBuf>,
    proofs: Vec<Value>,
    checks: Vec<Value>,
    serial: u64,
}
impl Evidence {
    fn new() -> Self {
        let dir = std::env::var_os("HEGEMON_RECOVERY_LIFECYCLE_OUT").map(PathBuf::from);
        if let Some(p) = &dir {
            assert!(!p.exists(), "evidence path must be fresh");
            std::fs::create_dir_all(p).unwrap();
        }
        Self {
            dir,
            proofs: Vec::new(),
            checks: Vec::new(),
            serial: 0,
        }
    }
    fn native_chain_dir(&self, name: &str) -> NativeLifecycleDirectory {
        assert!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
        match &self.dir {
            None => NativeLifecycleDirectory::Temporary(tempfile::tempdir().unwrap()),
            Some(root) => {
                let parent = root.join("native-chain-dbs");
                if !parent.exists() {
                    create_native_evidence_directory(&parent);
                }
                let path = parent.join(name);
                create_native_evidence_directory(&path); // Exclusive fresh fixture path.
                NativeLifecycleDirectory::Retained(path)
            }
        }
    }
    fn retain(&self, name: &str, bytes: &[u8]) {
        if let Some(dir) = &self.dir {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .unwrap();
            f.write_all(bytes).unwrap();
        }
    }
    fn check(&mut self, name: &str) {
        self.checks.push(json!({"name":name,"passed":true}));
    }
    fn proof(&mut self, name: &str, route: &str, body: &[u8], elapsed: f64) {
        self.retain(&format!("{name}.action"), body);
        let (lengths, proof_hashes) = if route == "spend" {
            let a = wire::decode_spend_ref(body).unwrap();
            {
                let mut parts = vec![a.proof];
                for c in &a.capsules {
                    parts.extend(capsule::bundle_components(c.proof).unwrap());
                }
                (
                    parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
                    parts.iter().map(|p| hash(p)).collect::<Vec<_>>(),
                )
            }
        } else if route == "admin" {
            let a = wire::decode_admin_ref(body).unwrap();
            (vec![a.proof.len()], vec![hash(a.proof)])
        } else {
            let a =
                transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(body)
                    .unwrap();
            (vec![a.proof.len()], vec![hash(a.proof)])
        };
        self.proofs.push(json!({"name":name,"route":route,"body_bytes":body.len(),"body_sha256":hash(body),
            "proof_bytes":lengths,"proof_sha256":proof_hashes,"construction_and_proving_seconds":elapsed}));
    }
}
#[allow(clippy::too_many_arguments)]
fn build_spend(
    node: &NativeNode,
    e: &mut Evidence,
    name: &str,
    operation: u8,
    actor: usize,
    input: Option<(&RecoveryNoteMaterialV1, u32)>,
    fee: &Fee,
    a: &wallet::DerivedKeys,
    b: &wallet::DerivedKeys,
    f: &wallet::DerivedKeys,
    credentials: &Credentials,
) -> Built {
    let start = Instant::now();
    let current = assets(node);
    let old = current.registry().row(ASSET).unwrap();
    let row = *current.recovery().unwrap().row(ASSET).unwrap();
    let head = node.best_meta();
    let chain = node.config.network.chain_id();
    let notes = canonical_notes(node);
    let amount = if operation == MINT {
        10
    } else {
        input.unwrap().0.as_note().value
    };
    let burn = u64::from(operation == BURN);
    let payment = if operation == MINT { 4 } else { 1 };
    let outputs = [
        build::new_recovery_output_os(chain, ASSET, POLICY, payment, recipient(b), authority(b))
            .unwrap(),
        build::new_recovery_output_os(
            chain,
            ASSET,
            POLICY,
            amount - burn - payment,
            recipient(if credentials.holder_revoked { b } else { a }),
            authority(if credentials.holder_revoked { b } else { a }),
        )
        .unwrap(),
    ];
    let mut fee_note = Note {
        value: fee.note.value - 1,
        asset_id: 0,
        recipient_key: recipient(f),
        authorization_key: [0; 4],
        rho: [1_000 + e.serial; 4],
        randomness: [2_000 + e.serial; 4],
    };
    e.serial += 1;
    private_spend::set_note_owner(
        &mut fee_note,
        private_spend::ordinary_owner(authority(f)).unwrap(),
    );
    let fee_change = AssetNotePayload {
        recipient_index: 0,
        note: note_opening(fee_note),
        authority: authority(f),
    };
    let authorization = match input {
        None => build::RecoveryAuthorizationV1::Mint {
            dummy_secret: [101 + e.serial, 102, 103, 104, 105].into(),
            issuer_secret: ISSUER.into(),
        },
        Some((material, position)) => {
            let siblings = membership(&notes, position).1;
            let freeze_siblings = current
                .recovery()
                .unwrap()
                .freeze_witness(ASSET, position)
                .unwrap();
            if actor < 2 {
                build::RecoveryAuthorizationV1::Holder {
                    material,
                    position,
                    siblings,
                    freeze_siblings,
                    spend_key: (if actor == 1 { b } else { a })
                        .spend
                        .poseidon2_v8_words()
                        .unwrap()
                        .into(),
                }
            } else {
                build::RecoveryAuthorizationV1::Delegate {
                    material,
                    position,
                    siblings,
                    freeze_siblings,
                    delegate_secret: if actor == 2 {
                        DELEGATE1.into()
                    } else {
                        DELEGATE2.into()
                    },
                    credential_recipient: if actor == 2 {
                        DELEGATE_RECIPIENT1
                    } else {
                        DELEGATE_RECIPIENT2
                    },
                }
            }
        }
    };
    let public = spend::Public {
        row,
        base: AssetSpendPublic {
            chain_id: chain,
            reference_parent_hash: head.hash,
            parent_height: head.height,
            note_root: store(node).note_tip().unwrap().root().limbs(),
            registry_root: words(current.registry().root()),
            asset_id: ASSET,
            policy_version: old.config.policy_version,
            credential_root: words(old.credential_root),
            credential_depth: 4,
            frozen: old.frozen,
            mint_enabled: old.mint_enabled,
            issuer_commitment: words(old.config.issuer_commitment),
            operation,
            magnitude: if operation == MINT { 10 } else { burn },
            fee: 1,
            nullifiers: [[1; 7], [2; 7]],
            commitments: [[0; 7]; 3],
            ciphertext_commitments: [[0; 48]; 3],
            policy_mode: 0,
            secret_release: 0,
            released_secret: [0; 32],
        },
    };
    let recipients = [
        b.poseidon2_v8_address(0).unwrap(),
        (if credentials.holder_revoked { b } else { a })
            .poseidon2_v8_address(0)
            .unwrap(),
        f.poseidon2_v8_address(0).unwrap(),
    ];
    let keys = recipients.each_ref().map(|r| r.public_key());
    let mut provider = build::LocalArchiveProviderV1::new(ARCHIVE.into());
    let prepared = build::prepare_recovery_spend_os(
        build::RecoverySpendConstructionV1 {
            public,
            authorization,
            native_fee_input: build::NativeFeeInputV1::new(PrivateInput {
                occupied: 1,
                legacy_ordinary: fee.legacy,
                note: fee.note,
                position: fee.position,
                siblings: membership(&notes, fee.position).1,
                spend_key: fee.key,
                dummy_secret: [0; 5],
            })
            .unwrap(),
            outputs: [&outputs[0], &outputs[1]],
            native_fee_change: &fee_change,
            credentials: [
                credentials.paths[actor].clone(),
                credentials.paths[1].clone(),
                credentials.paths[if credentials.holder_revoked { 1 } else { 0 }].clone(),
            ],
        },
        [&keys[0], &keys[1], &keys[2]],
        &mut provider,
    )
    .unwrap();
    let artifact = prepared.prove_and_encode().unwrap();
    let body = artifact.as_bytes().to_vec();
    let public = artifact.public_statement().clone();
    let decoded = wire::decode_spend_ref(&body).unwrap();
    for i in 0..2 {
        let recovered =
            build::decrypt_archive_material(&decoded.capsules[i].public, &ARCHIVE).unwrap();
        assert!(
            recovered
                .material_words(&wallet::asset_recovery_v1::RecoveryNoteContextV1 {
                    chain_id: chain,
                    asset_id: ASSET,
                    stable_policy_id: POLICY,
                    output_commitment: public.base.commitments[i]
                })
                .unwrap()[..]
                == outputs[i]
                    .material_words(&wallet::asset_recovery_v1::RecoveryNoteContextV1 {
                        chain_id: chain,
                        asset_id: ASSET,
                        stable_policy_id: POLICY,
                        output_commitment: public.base.commitments[i]
                    })
                    .unwrap()[..]
        );
        assert!(build::decrypt_archive_material(&decoded.capsules[i].public, &[24; 32]).is_err());
        let holder = if i == 0 || credentials.holder_revoked {
            b
        } else {
            a
        };
        let delivered = build::decrypt_holder_output(
            &public,
            i as u8,
            decoded.ciphertexts[i],
            recipients[i].secret_key(),
            recipient(holder),
            authority(holder),
        )
        .unwrap();
        let context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
            chain_id: chain,
            asset_id: ASSET,
            stable_policy_id: POLICY,
            output_commitment: public.base.commitments[i],
        };
        assert!(
            delivered.material_words(&context).unwrap()[..]
                == outputs[i].material_words(&context).unwrap()[..]
        );
    }
    let delivered_fee = build::decrypt_native_fee_change(
        &public,
        decoded.ciphertexts[2],
        recipients[2].secret_key(),
        0,
        recipient(f),
        authority(f),
    )
    .unwrap();
    assert!(delivered_fee.as_note() == fee_note);
    e.proof(name, "spend", &body, start.elapsed().as_secs_f64());
    Built {
        body,
        public,
        outputs,
        fee_note,
        next_position: notes.len() as u32,
    }
}
// The coordinator supplies the freshly built Development walletd and its exact
// expected binary digest. These requests use disposable encrypted wallets only.
const ISSUER_CLI_PASSPHRASE: &[u8] = b"disposable-issuer-cli-only\n";
const ISSUER_CLI_TIMEOUT_SECONDS: u64 = 1_500;
fn issuer_cli_hash_file(path: &Path) -> String {
    use std::io::Read;
    let mut file = std::fs::File::open(path).expect("read pinned issuer CLI binary");
    let mut digest = Sha256::new();
    let mut block = [0u8; 65_536];
    loop {
        let n = file
            .read(&mut block)
            .expect("hash pinned issuer CLI binary");
        if n == 0 {
            break;
        }
        digest.update(&block[..n]);
    }
    hex::encode(digest.finalize())
}
fn issuer_cli_write_private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .expect("create exclusive disposable CLI file");
    file.write_all(bytes).expect("write disposable CLI file");
    file.sync_all().expect("sync disposable CLI file");
}
fn issuer_cli_public_params(params: &Value) -> Value {
    let mut public = params.clone();
    if let Some(fields) = public.as_object_mut() {
        for secret in [
            "archive_key",
            "issuer_secret",
            "delegate_secret",
            "admin_secret",
        ] {
            fields.remove(secret);
        }
    }
    public
}
fn issuer_cli_reply(stdout: &[u8], id: u64, success: bool) -> Result<Value, &'static str> {
    if !success || stdout.len() > 65_536 {
        return Err("walletd failed or exceeded reply bound");
    }
    let line = stdout
        .split(|b| *b == b'\n')
        .rfind(|line| !line.is_empty())
        .ok_or("walletd emitted no reply")?;
    let reply: Value =
        serde_json::from_slice(line).map_err(|_| "walletd emitted malformed reply")?;
    if reply["id"] != id || reply["ok"] != true {
        return Err("walletd rejected request");
    }
    reply.get("result").cloned().ok_or("walletd omitted result")
}
struct OwnedIssuerCliProcess(std::process::Child);
impl Drop for OwnedIssuerCliProcess {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill(); // Exact owned Child, never a foreign PID/group.
            let _ = self.0.wait();
        }
    }
}
struct IssuerCliFixture {
    work: tempfile::TempDir,
    binary: PathBuf,
    binary_sha256: String,
    wallet: PathBuf,
    manifest: PathBuf,
    reservation: Option<String>,
    calls: Vec<Value>,
    sequence: u64,
}
impl IssuerCliFixture {
    fn new(node: &NativeNode, fee: &wallet::DerivedKeys) -> Self {
        let binary = std::fs::canonicalize(
            std::env::var_os("HEGEMON_ISSUER_CLI_BIN")
                .expect("set HEGEMON_ISSUER_CLI_BIN to the freshly built Development walletd"),
        )
        .expect("canonical issuer CLI binary path");
        let expected = std::env::var("HEGEMON_ISSUER_CLI_SHA256")
            .expect("set HEGEMON_ISSUER_CLI_SHA256 from the retained walletd build");
        assert!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "expected CLI binary SHA256 must be exact lowercase hex"
        );
        let binary_sha256 = issuer_cli_hash_file(&binary);
        assert!(
            binary_sha256 == expected,
            "issuer CLI binary differs from expected build"
        );
        let work = tempfile::tempdir().expect("disposable issuer CLI scratch");
        let wallet = work.path().join("issuer.wallet");
        let seed = wallet::RootSecret::from_bytes([43; 32]);
        assert!(
            authority(&seed.derive()) == authority(fee),
            "CLI wallet must own actual mined fee"
        );
        // Existing key-only fixture construction; no note/root/reservation import.
        // Every fee note is subsequently discovered through genuine asset.sync.
        drop(
            wallet::WalletStore::create_from_root(&wallet, "disposable-issuer-cli-only", seed)
                .expect("create disposable encrypted issuer wallet"),
        );
        let manifest = work.path().join("manifest.json");
        issuer_cli_write_private(
            &manifest,
            &serde_json::to_vec(node.config.network.manifest().unwrap()).unwrap(),
        );
        Self {
            work,
            binary,
            binary_sha256,
            wallet,
            manifest,
            reservation: None,
            calls: Vec::new(),
            sequence: 0,
        }
    }
    fn call(&mut self, method: &'static str, params: Value) -> Value {
        use std::io::{Read, Write};
        assert!(
            issuer_cli_hash_file(&self.binary) == self.binary_sha256,
            "issuer CLI binary changed between process invocations"
        );
        self.sequence += 1;
        let id = self.sequence;
        let public_sha256 = hash(&serde_json::to_vec(&issuer_cli_public_params(&params)).unwrap());
        let request = self.work.path().join(format!("request-{id}.json"));
        issuer_cli_write_private(
            &request,
            &serde_json::to_vec(&json!({"id":id,"method":method,"params":params})).unwrap(),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&request).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let started = Instant::now();
        let mut child = OwnedIssuerCliProcess(
            std::process::Command::new(&self.binary)
                .arg("--store")
                .arg(&self.wallet)
                .arg("--mode")
                .arg("open")
                .arg("--request-file")
                .arg(&request)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                // Inherit the sole coordinator's owned process group.
                .spawn()
                .expect("start exact pinned issuer walletd"),
        );
        child
            .0
            .stdin
            .take()
            .expect("owned CLI stdin")
            .write_all(ISSUER_CLI_PASSPHRASE)
            .expect("provide disposable passphrase privately");
        let status = loop {
            assert!(
                started.elapsed().as_secs() < ISSUER_CLI_TIMEOUT_SECONDS,
                "bounded issuer CLI step timeout; owned child is terminated on unwind"
            );
            if let Some(status) = child.0.try_wait().expect("wait exact owned issuer CLI") {
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let mut stdout = Vec::new();
        child
            .0
            .stdout
            .take()
            .expect("owned CLI stdout")
            .take(65_537)
            .read_to_end(&mut stdout)
            .expect("read bounded CLI reply");
        // Raw stdin/stdout/stderr and private request bytes are never retained.
        let reply = issuer_cli_reply(&stdout, id, status.success())
            .unwrap_or_else(|_| panic!("walletd {method} failed; raw diagnostics discarded"));
        std::fs::remove_file(&request).expect("remove completed private request");
        self.calls.push(
            json!({"method":method,"elapsed_seconds":started.elapsed().as_secs_f64(),
            "public_params_sha256":public_sha256,"private_request_mode": "0600",
            "new_process":true,"reply_ok":true,"secret_request_retained":false}),
        );
        reply
    }
    fn online(&self, endpoint: &str, genesis: [u8; 32]) -> Value {
        json!({"ws_url":endpoint,"manifest":self.manifest,"expected_genesis":hex::encode(genesis)})
    }
    fn assert_journal(&mut self, status: &str, action_id: Option<[u8; 48]>) {
        let reply = self.call("recovery.journal", json!({}));
        let rows = reply.as_array().expect("public recovery journal rows");
        assert!(rows.len() == 1, "one durable issuer attempt expected");
        let id = hex::decode(self.reservation.as_ref().unwrap()).unwrap();
        let row = &rows[0];
        assert!(row["id"] == json!(id) && row["status"] == status);
        assert!(row["inputs_reserved"] == true && row["mined_in"].is_null());
        let expected_id = action_id.map(|id| id.to_vec()).unwrap_or_default();
        assert!(row["action_id"] == json!(expected_id));
    }
    fn export(&mut self, filename: &str) -> Vec<u8> {
        let path = self.work.path().join(filename);
        let reply = self.call(
            "recovery.export",
            json!({"reservation_id":self.reservation,
            "action_file":path}),
        );
        let length = std::fs::metadata(&path)
            .expect("exact CLI export exists")
            .len();
        assert!(
            length <= wire::MAX_SPEND_ACTION_BYTES as u64,
            "CLI export exceeds fresh route cap"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let body = std::fs::read(&path).expect("read exact public CLI export");
        assert!(
            reply["action_bytes"] == body.len(),
            "CLI export byte count differs"
        );
        body
    }
}
// The production router runs on its own Tokio worker while the owned walletd
// process executes. Always close and join it even if a CLI assertion unwinds.
fn issuer_cli_http<T>(node: &Arc<NativeNode>, operation: impl FnOnce(&str) -> T) -> T {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/",
                post(rpc_handler).get(root_handler).options(options_handler),
            )
            .route("/health", get(health_handler))
            .layer(DefaultBodyLimit::max(MAX_NATIVE_RPC_BODY_BYTES))
            .layer(ConcurrencyLimitLayer::new(
                MAX_NATIVE_RPC_CONCURRENT_REQUESTS,
            ))
            .with_state(Arc::clone(node));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        let result = tokio::task::block_in_place(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&endpoint)))
        });
        let _ = shutdown_tx.send(());
        match tokio::time::timeout(std::time::Duration::from_secs(30), server).await {
            Ok(Ok(Ok(()))) => (),
            _ => panic!("owned issuer CLI HTTP server failed bounded shutdown"),
        }
        match result {
            Ok(value) => value,
            Err(error) => std::panic::resume_unwind(error),
        }
    })
}
fn build_mint_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    fee: &Fee,
    a: &wallet::DerivedKeys,
    b: &wallet::DerivedKeys,
    f: &wallet::DerivedKeys,
    credentials: &Credentials,
) -> Built {
    let started = Instant::now();
    let before = snapshot(node);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let address_a = a.poseidon2_v8_address(0).unwrap();
    let address_b = b.poseidon2_v8_address(0).unwrap();
    let address_f = f.poseidon2_v8_address(0).unwrap();
    let public_reply = issuer_cli_http(node, |endpoint| {
        let address = cli.call("asset.address", json!({"index":0}));
        assert!(
            address["address"] == address_f.shielded_address().encode().unwrap(),
            "actual CLI fee address differs from mined recipient"
        );
        cli.call("asset.sync", cli.online(endpoint, genesis));
        let mut info = cli.online(endpoint, genesis);
        info["asset_id"] = json!(ASSET);
        let info = cli.call("recovery.info", info);
        assert!(info["context"]["parent_hash"] == hex::encode(before.hash));
        assert!(info["context"]["parent_height"] == before.height);
        let credential = |i: usize| {
            json!({"index":credentials.paths[i].index,
            "expires_at":credentials.paths[i].expires_at,"siblings":credentials.paths[i].siblings})
        };
        let mut request = cli.online(endpoint, genesis);
        let p = request.as_object_mut().unwrap();
        p.extend(json!({"confirm":true,"expected_parent_hash":hex::encode(before.hash),
            "expected_epoch":0,"asset_id":ASSET,"operation":"mint","route":"mint",
            "amount":10,"fee":1,"fee_position":fee.position,
            "recipient":address_a.shielded_address().encode().unwrap(),
            "change_recipient":address_b.shielded_address().encode().unwrap(),"native_change_index":0,
            "archive_key":hex::encode(ARCHIVE),"issuer_secret":ISSUER,
            "credentials":[{"index":0,"expires_at":0,"siblings":[]},credential(0),credential(1)]})
            .as_object().unwrap().clone());
        cli.call("recovery.prepare", request)
    });
    assert!(
        snapshot(node) == before,
        "CLI construction must not publish canonical state"
    );
    assert!(
        public_reply["status"] == "candidate" && public_reply["proof_units"] == wire::PROOF_UNITS
    );
    let reservation = public_reply["reservation_id"]
        .as_str()
        .expect("CLI reservation ID")
        .to_owned();
    assert!(hex::decode(&reservation).is_ok_and(|b| b.len() == 32));
    cli.reservation = Some(reservation);
    let body = cli.export("mint-initial.action");
    cli.assert_journal("Candidate", None);
    let decoded = wire::decode_spend_ref(&body).unwrap();
    let public = decoded.public.clone();
    assert!(public_reply["public_statement"] == json!(public.words().unwrap()));
    assert!(
        public.base.parent_height == before.height
            && public.base.reference_parent_hash == before.hash
    );
    assert!(public.base.operation == MINT && public.base.magnitude == 10 && public.base.fee == 1);
    assert!(
        public.base.nullifiers[1]
            == private_spend::real_nullifier(fee.key, fee.position, fee.note).unwrap()
    );
    assert!(decoded.proof.len() <= wire::MAX_PROOF_BYTES);
    for c in &decoded.capsules {
        assert!(capsule::bundle_components(c.proof)
            .unwrap()
            .iter()
            .all(|p| p.len() <= wire::MAX_PROOF_BYTES));
    }
    let outputs = std::array::from_fn(|i| {
        let material =
            build::decrypt_archive_material(&decoded.capsules[i].public, &ARCHIVE).unwrap();
        assert!(build::decrypt_archive_material(&decoded.capsules[i].public, &[24; 32]).is_err());
        let (holder, address) = if i == 0 {
            (a, &address_a)
        } else {
            (b, &address_b)
        };
        let delivered = build::decrypt_holder_output(
            &public,
            i as u8,
            decoded.ciphertexts[i],
            address.secret_key(),
            recipient(holder),
            authority(holder),
        )
        .unwrap();
        let context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
            chain_id: public.base.chain_id,
            asset_id: ASSET,
            stable_policy_id: POLICY,
            output_commitment: public.base.commitments[i],
        };
        assert!(
            material.material_words(&context).unwrap()[..]
                == delivered.material_words(&context).unwrap()[..]
        );
        material
    });
    // CLI mint semantics: all issuance to output0, authenticated zero output1.
    // The later holder/delegate race consumes output0 under the same holder A.
    assert!(outputs[0].as_note().value == 10 && outputs[1].as_note().value == 0);
    let fee_note = build::decrypt_native_fee_change(
        &public,
        decoded.ciphertexts[2],
        address_f.secret_key(),
        0,
        recipient(f),
        authority(f),
    )
    .unwrap()
    .as_note();
    assert!(fee_note.asset_id == 0 && fee_note.value == fee.note.value - 1);
    e.proof("mint", "spend", &body, started.elapsed().as_secs_f64());
    Built {
        body,
        public,
        outputs,
        fee_note,
        next_position: canonical_notes(node).len() as u32,
    }
}
fn submit_mine_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    mint: &Built,
) -> NativeBlockMeta {
    let before = snapshot(node);
    let expected = pending(
        node,
        &mint.body,
        asset_recovery_native::RECOVERY_SPEND_ACTION_ID,
    );
    let exact = expected.encode();
    let expected_hash = expected.tx_hash.into_bytes();
    assert!(cli.export("mint-before-submit.action") == mint.body);
    cli.assert_journal("Candidate", None);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let reply = issuer_cli_http(node, |endpoint| {
        let mut request = cli.online(endpoint, genesis);
        request["reservation_id"] = json!(cli.reservation);
        request["confirm"] = json!(true);
        cli.call("recovery.submit", request)
    });
    assert!(reply["status"] == "submitted" && reply["action_id"] == hex::encode(expected_hash));
    cli.assert_journal("Submitted", Some(expected_hash));
    assert!(
        cli.export("mint-after-submit.action") == mint.body,
        "separate walletd processes must preserve exact retained candidate bytes"
    );
    assert!(
        snapshot(node) == before,
        "CLI admission must not publish canonical state before mining"
    );
    assert!(issuer_cli_hash_file(&cli.binary) == cli.binary_sha256);
    let evidence = json!({"name":"issuer_cli_actual_prepare_export_submit_exact_HTTP18",
        "passed":true,"binary_sha256":cli.binary_sha256,"binary_expected_sha256_verified":true,
        "binary_source_binding":"coordinator retained build receipt required; source hashes below are compile inputs",
        "source_pins":{
            "walletd/src/main.rs":hash(include_bytes!("../../../walletd/src/main.rs")),
            "walletd/src/recovery.rs":hash(include_bytes!("../../../walletd/src/recovery.rs")),
            "walletd/src/asset.rs":hash(include_bytes!("../../../walletd/src/asset.rs")),
            "wallet/src/node_rpc.rs":hash(include_bytes!("../../../wallet/src/node_rpc.rs")),
            "wallet/src/asset_spend_rpc.rs":hash(include_bytes!("../../../wallet/src/asset_spend_rpc.rs")),
            "wallet/src/poseidon2_v8_sync.rs":hash(include_bytes!("../../../wallet/src/poseidon2_v8_sync.rs")),
            "wallet/src/poseidon2_v8_launch_sync.rs":hash(include_bytes!("../../../wallet/src/poseidon2_v8_launch_sync.rs")),
            "wallet/src/asset_recovery_build_v1.rs":hash(include_bytes!("../../../wallet/src/asset_recovery_build_v1.rs")),
            "wallet/src/asset_recovery_store.rs":hash(include_bytes!("../../../wallet/src/asset_recovery_store.rs")),
            "wallet/src/private_spend_rpc.rs":hash(include_bytes!("../../../wallet/src/private_spend_rpc.rs"))},
        "calls":cli.calls,"new_walletd_process_per_call":true,"request_files_mode0600":true,
        "durable_journal_candidate_then_submitted_with_inputs_reserved":true,
        "holder_ordinary_spend_secrets_provided_to_issuer_cli":false,
        "secret_requests_or_raw_process_streams_retained":false,
        "only_fixture_seeded_state":"existing encrypted wallet root; all mature fee notes discovered via actual asset.sync",
        "operation":"mint","amount":10,"output_values":[10,0],"proof_units":wire::PROOF_UNITS,
        "carrier_bytes":mint.body.len(),"carrier_sha256":hash(&mint.body),"action_id":18,
        "tx_hash":hex::encode(expected_hash),"exact_export_before_and_after_submit":true,
        "actual_HTTP":true,"production_router_limits_and_dispatch":true,"owned_HTTP_servers_joined":true});
    e.retain(
        "issuer-cli-acceptance.json",
        &serde_json::to_vec_pretty(&evidence).unwrap(),
    );
    e.checks.push(evidence);
    let block = mine(node);
    assert!(
        block.action_bytes.contains(&exact),
        "mined canonical action must equal exact CLI-submitted carrier"
    );
    block
}
#[test]
fn issuer_cli_public_request_projection_omits_secret_fields() {
    let private = json!({"archive_key":"never-retain","issuer_secret":[1,2],
        "delegate_secret":[3],"admin_secret":[4],"asset_id":1001,"amount":10});
    let public = issuer_cli_public_params(&private);
    assert!(public == json!({"asset_id":1001,"amount":10}));
}
#[test]
fn issuer_cli_reply_requires_success_exact_id_and_bounded_JSON() {
    assert!(issuer_cli_reply(
        br#"{"id":1,"ok":true,"result":{"status":"candidate"}}"#,
        1,
        true
    )
    .is_ok());
    assert!(issuer_cli_reply(br#"{"id":2,"ok":true,"result":{}}"#, 1, true).is_err());
    assert!(issuer_cli_reply(br#"{"id":1,"ok":false,"error":"discard"}"#, 1, true).is_err());
    assert!(issuer_cli_reply(br#"{"id":1,"ok":true,"result":{}}"#, 1, false).is_err());
    assert!(issuer_cli_reply(&vec![b'x'; 65_537], 1, true).is_err());
}

fn pending_result(
    node: &NativeNode,
    body: &[u8],
    action: u16,
) -> core::result::Result<PendingAction, String> {
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .map_err(|x| x.to_string())?;
    let startup =
        launch_v8_verifier::LaunchStartup::from_source(&node.config.network, genesis.hash)
            .map_err(|x| x.to_string())?
            .ok_or("missing source launch")?;
    let mut pending = asset_recovery_native::pending_recovery_action_from_inline_args(
        startup
            .recovery_authority()
            .ok_or("missing source recovery authority")?,
        node.best_height() + 1,
        asset_recovery_native::native_binding(),
        action,
        body.to_vec(),
    )?;
    pending.tx_hash = pending_action_hash(&pending);
    Ok(pending)
}
fn pending(node: &NativeNode, body: &[u8], action: u16) -> PendingAction {
    pending_result(node, body, action).unwrap()
}
fn submit_mine(node: &NativeNode, body: &[u8], action: u16) -> NativeBlockMeta {
    let pending = pending(node, body, action);
    let exact = pending.encode();
    node.stage_relayed_pending_action(pending)
        .unwrap()
        .expect("new exact action must stage");
    let block = mine(node);
    assert!(block.action_bytes.iter().any(|b| b == &exact));
    block
}
/// Production peer codecs and source-gated preflight, without a peer socket,
/// queue reservation, proof generation or canonical state mutation. The same
/// genuine carrier subsequently takes the HTTP and actual block-acceptance path.
fn peer_transport_roundtrip(node: &NativeNode, e: &mut Evidence, body: &[u8]) {
    let before = snapshot(node);
    let expected = pending(node, body, asset_recovery_native::RECOVERY_SPEND_ACTION_ID);
    let exact = expected.encode();
    assert!(native_action_payload_within_route_cap(&exact));
    assert!(exact.len() <= MAX_NATIVE_RECOVERY_PENDING_ACTION_BYTES);
    let exceeds_generic = exact.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES;
    let sync_payload = encode_sync_message(&NativeSyncMessage::PendingAction {
        action: exact.clone(),
    })
    .unwrap();
    // These are the active HNW1/postcard utilities used by the peer service,
    // rather than the bincode codec used for retained canonical block bodies.
    let encrypted_frame_bytes = native_sync_protocol_frame_bytes(&sync_payload).unwrap();
    let frame = network::wire::encode(
        &WireMessage::Proto(ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload: sync_payload.clone(),
        }),
        network::wire::MAX_WIRE_FRAME_LEN,
    )
    .unwrap();
    assert_eq!(encrypted_frame_bytes, frame.len() + AES_GCM_TAG_BYTES);
    assert!(encrypted_frame_bytes <= network::wire::MAX_WIRE_FRAME_LEN);
    let envelope: WireMessage =
        network::wire::decode(&frame, network::wire::MAX_WIRE_FRAME_LEN).unwrap();
    let payload = match envelope {
        WireMessage::Proto(protocol) => {
            assert_eq!(protocol.protocol, NATIVE_SYNC_PROTOCOL_ID);
            protocol.payload
        }
        other => panic!("expected actual protocol envelope: {other:?}"),
    };
    assert_eq!(payload, sync_payload);
    let relayed = match decode_sync_message(&payload).unwrap() {
        NativeSyncMessage::PendingAction { action } => action,
        other => panic!("expected actual pending-action message: {other:?}"),
    };
    assert_eq!(relayed, exact);
    assert!(native_action_payload_within_route_cap(&relayed));
    let decoded =
        decode_native_peer_pending_action_v3_for_node(node, &relayed, node.best_height() + 1)
            .unwrap();
    let (action_id, requires_proof) =
        preflight_native_peer_pending_action_for_node(node, &decoded, node.best_height()).unwrap();
    assert!(requires_proof);
    assert_eq!(action_id, expected.tx_hash);
    assert_eq!(decoded.tx_hash, pending_action_hash(&decoded));
    assert_eq!(decoded.encode(), exact);
    assert_eq!(decoded.public_args.as_slice(), body);
    assert!(decoded.nullifiers.is_empty() && decoded.commitments.is_empty());
    // Exact consumption and embedded identity checks are exercised on the
    // same real carrier; neither negative is admitted or queued.
    let mut trailing_frame = frame.clone();
    trailing_frame.push(0);
    assert!(network::wire::decode::<WireMessage>(
        &trailing_frame,
        network::wire::MAX_WIRE_FRAME_LEN
    )
    .is_err());
    let mut trailing_payload = payload.clone();
    trailing_payload.push(0);
    assert!(decode_sync_message(&trailing_payload).is_err());
    let mut forged = decoded.clone();
    forged.fee += 1;
    assert!(
        preflight_native_peer_pending_action_for_node(node, &forged, node.best_height()).is_err()
    );
    if exceeds_generic {
        // A large genuine recovery body earns only its typed route exception.
        // The same bytes cannot obtain that exception through a legacy route.
        let mut wrong_route = decoded.clone();
        wrong_route.action_id = PRIVATE_SPEND_ACTION_ID;
        assert!(!native_action_payload_within_route_cap(
            &wrong_route.encode()
        ));
    }
    assert!(snapshot(node) == before);
    let observed = json!({
        "name":"genuine_mint_production_peer_frame_and_source_preflight_roundtrip",
        "passed":true,"carrier_bytes":body.len(),"carrier_sha256":hash(body),
        "pending_action_bytes":exact.len(),"pending_action_sha256":hash(&exact),
        "sync_payload_bytes":payload.len(),"sync_payload_sha256":hash(&payload),
        "protocol_frame_bytes":frame.len(),"protocol_frame_sha256":hash(&frame),
        "encrypted_frame_budget_bytes":encrypted_frame_bytes,
        "generic_pending_action_cap":MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
        "recovery_pending_action_cap":MAX_NATIVE_RECOVERY_PENDING_ACTION_BYTES,
        "exceeds_generic_pending_action_budget":exceeds_generic,
        "large_typed_route_exception_exercised":exceeds_generic,
        "network_wire_codec":"HNW1/postcard","exact_action_id":hex::encode(action_id.as_bytes()),
        "production_utility_decoders":true,"source_gated_peer_preflight":true,
        "trailing_bytes_and_forged_identity_rejected":true,"canonical_unchanged":true,
        "live_peer_socket":false,"peer_queue_or_channel_crypto_exercised":false,
        "additional_proofs_generated":0
    });
    e.retain(
        "mint-peer-transport.json",
        &serde_json::to_vec_pretty(&observed).unwrap(),
    );
    e.checks.push(observed);
}
/// Real loopback HTTP, production router/limits/dispatcher and the wallet's
/// source-bound submit API. No direct dispatcher invocation or raw request
/// authority. Proof bytes are reused; only the final staging route changes.
fn submit_mine_http(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    body: &[u8],
    action_id: u16,
) -> NativeBlockMeta {
    let before = snapshot(node);
    let expected = pending(node, body, action_id);
    let exact = expected.encode();
    let expected_hash = expected.tx_hash.into_bytes();
    let selected_manifest = serde_json::to_vec(node.config.network.manifest().unwrap()).unwrap();
    let expected_genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let observed=runtime.block_on(async {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        // Exact service.rs assembly: default8MiB remains in force. Any larger
        // request must qualify through rpc.rs's source-owned recovery grammar.
        let router=Router::new()
            .route("/",post(rpc_handler).get(root_handler).options(options_handler))
            .route("/health",get(health_handler))
            .layer(DefaultBodyLimit::max(MAX_NATIVE_RPC_BODY_BYTES))
            .layer(ConcurrencyLimitLayer::new(MAX_NATIVE_RPC_CONCURRENT_REQUESTS))
            .with_state(Arc::clone(node));
        let (shutdown_tx,shutdown_rx)=tokio::sync::oneshot::channel::<()>();
        let server=tokio::spawn(async move {
            axum::serve(listener,router).with_graceful_shutdown(async {let _=shutdown_rx.await;}).await
        });
        let started=Instant::now();
        let operation=async {
            let mut config=wallet::node_rpc::NodeRpcConfig::with_endpoint(format!("http://{address}"));
            config.request_timeout=std::time::Duration::from_secs(600);
            config.max_reconnect_attempts=0;
            let client=wallet::node_rpc::NodeRpcClient::connect_with_config(config).await
                .map_err(|err|err.to_string())?;
            let metadata=client.get_chain_metadata().await.map_err(|err|err.to_string())?;
            let read_config=client.node_config().await.map_err(|err|err.to_string())?;
            let parameters=client.private_spend_parameters().await.map_err(|err|err.to_string())?;
            let token=wallet::private_spend_rpc::DevelopmentPrivateSpendAuthority::from_verified_node(
                &selected_manifest,expected_genesis,metadata.genesis_hash,&read_config,&parameters,
                metadata.block_number).map_err(|err|err.to_string())?;
            let recovery=client.recovery_snapshot(Some(ASSET),None).await.map_err(|err|err.to_string())?;
            if metadata.block_number!=before.height
                || recovery["context"]["parent_height"]!=before.height
                || recovery["context"]["chain_id"]!=hex::encode(node.config.network.chain_id())
                || recovery["parameters"]!=serde_json::to_value(node.config.network.development_recovery().unwrap()).unwrap() {
                return Err("HTTP source/current recovery readback differs from selected node".to_string());
            }
            let projection=match action_id {
                asset_recovery_native::RECOVERY_SPEND_ACTION_ID =>
                    wallet::private_spend_rpc::prepare_recovery_spend_request_local_candidate(
                        &token,before.height+1,body),
                asset_recovery_native::RECOVERY_ADMIN_ACTION_ID =>
                    wallet::private_spend_rpc::prepare_recovery_admin_request_local_candidate(
                        &token,before.height+1,body),
                _ => return Err("unexpected HTTP recovery action".to_string()),
            }.map_err(|err|err.to_string())?;
            let projection_bytes=serde_json::to_vec(&projection).map_err(|err|err.to_string())?.len();
            let returned=client.submit_native_recovery_action(&token,
                action_id,body).await.map_err(|err|err.to_string())?;
            if returned!=expected_hash {return Err("HTTP accepted a different exact action identity".to_string());}
            Ok::<_,String>(json!({"name":"wallet_source_bound_actual_HTTP_recovery_submission",
                "passed":true,"action_id":action_id,"carrier_bytes":body.len(),"carrier_sha256":hash(body),
                "request_projection_json_bytes":projection_bytes,
                "base64_public_args_characters":projection["public_args"].as_str().unwrap().len(),
                "exceeds_default_HTTP_budget":projection_bytes>MAX_NATIVE_RPC_BODY_BYTES,
                "tx_hash":hex::encode(returned),"source_and_current_snapshot_readback_verified":true,
                "actual_HTTP":true,"production_router_limits_and_dispatch":true,
                "submission_seconds":started.elapsed().as_secs_f64()}))
        };
        // Always close and join the owned loopback server before interpreting
        // the result. A timeout/error yields no receipt and no terminal pass.
        let result=tokio::time::timeout(std::time::Duration::from_secs(660),operation).await;
        let _=shutdown_tx.send(());
        let shutdown=tokio::time::timeout(std::time::Duration::from_secs(30),server).await;
        match shutdown {
            Ok(Ok(Ok(())))=>{},
            other=>panic!("owned HTTP server did not shut down cleanly: {other:?}"),
        }
        result.expect("bounded wallet HTTP operation timeout").expect("actual wallet HTTP recovery submission")
    });
    assert!(
        snapshot(node) == before,
        "HTTP admission must not publish canonical state before a block"
    );
    let mut observed = observed;
    observed["owned_HTTP_server_joined"] = json!(true);
    e.retain(
        &format!("action-{action_id}-http.json"),
        &serde_json::to_vec_pretty(&observed).unwrap(),
    );
    e.checks.push(observed);
    let block = mine(node);
    assert!(block.action_bytes.contains(&exact));
    block
}
fn reject(
    node: &NativeNode,
    e: &mut Evidence,
    name: &str,
    body: &[u8],
    action: u16,
    fragments: &[&str],
) {
    let before = snapshot(node);
    let (layer, error) = match pending_result(node, body, action) {
        Err(error) => ("source_owned_structural_constructor", error),
        Ok(p) => (
            "native_pending_admission",
            node.stage_relayed_pending_action(p)
                .expect_err("real source/state admission must reject")
                .to_string(),
        ),
    };
    assert!(
        fragments.is_empty() || fragments.iter().any(|x| error.contains(x)),
        "{name}: unexpected rejection: {error}"
    );
    assert!(snapshot(node) == before);
    e.checks.push(json!({"name":name,"passed":true,"error":error,"rejection_layer":layer,"canonical_unchanged":true}));
}
fn recovery_admin(
    node: &NativeNode,
    e: &mut Evidence,
    name: &str,
    freeze: Option<(u32, bool)>,
    delegate: Option<D>,
    revoked: Option<bool>,
) -> (Vec<u8>, [u8; 32]) {
    let now = Instant::now();
    let current = assets(node);
    let state = current.recovery().unwrap();
    let before = *state.row(ASSET).unwrap();
    let head = node.best_meta();
    let chain = node.config.network.chain_id();
    let mut next = before.controls;
    next.epoch += 1;
    if let Some(secret) = delegate {
        next.delegate_action_commitment = recovery::delegate_action_commitment(secret).unwrap()
    }
    if let Some(value) = revoked {
        next.revoked = value
    }
    let mut siblings = [[0; 7]; 32];
    let mutation = freeze.map(|(position, after_frozen)| {
        let (_, cm) = state.note_at(position).unwrap();
        siblings = state.freeze_witness(ASSET, position).unwrap();
        let before_frozen =
            recovery::freeze_root(&before.descriptor, chain, position, cm, true, &siblings)
                .unwrap()
                == before.controls.note_freeze_root;
        next.note_freeze_root = recovery::freeze_root(
            &before.descriptor,
            chain,
            position,
            cm,
            after_frozen,
            &siblings,
        )
        .unwrap();
        admin::FreezeMutation {
            position,
            note_commitment: cm,
            before_frozen,
            after_frozen,
        }
    });
    let prepared = recovery::prepare_controls_update(
        recovery::RecoveryContextV1 {
            chain_id: chain,
            parent_hash: head.hash,
            parent_height: head.height,
            row_commitment: before.commitment(chain).unwrap(),
        },
        before,
        next,
    )
    .unwrap();
    let public =
        admin::Public::from_prepared(&prepared, head.height + 12, [3_000 + e.serial; 7], mutation)
            .unwrap();
    e.serial += 1;
    let proof = admin::prove_candidate(
        &public,
        &admin::Witness {
            admin_secret: ADMIN,
            freeze_siblings: siblings,
        },
    )
    .unwrap();
    let body = wire::encode_admin(&public, &proof).unwrap();
    let id = public.action_id().unwrap();
    e.proof(name, "admin", &body, now.elapsed().as_secs_f64());
    (body, id)
}
fn old_controls(
    node: &NativeNode,
    e: &mut Evidence,
    name: &str,
    frozen: bool,
    credential_root: D,
) -> Vec<u8> {
    let now = Instant::now();
    let current = assets(node);
    let head = node.best_meta();
    let mut controls = current.registry().row(ASSET).unwrap().controls();
    controls.frozen = frozen;
    controls.credential_root = credential_root.map(Felt::from_u64);
    let prepared = current
        .registry()
        .prepare_controls_update(current.registry().context(), ASSET, controls)
        .unwrap();
    let public = old_admin::PolicyAdminPublicV1::from_prepared(
        &prepared,
        head.hash,
        head.height + 12,
        [4_000 + e.serial; 7],
    )
    .unwrap();
    e.serial += 1;
    let proof =
        old_admin::prove_candidate(&public, &old_admin::PolicyAdminWitnessV1 { secret: ADMIN })
            .unwrap();
    let body = transaction_circuit::asset_spend_v1_wire::encode_native_asset_admin_action_v1(
        &public, &proof,
    )
    .unwrap();
    e.proof(name, "old-controls", &body, now.elapsed().as_secs_f64());
    body
}
fn old_pending(node: &NativeNode, body: &[u8]) -> PendingAction {
    let genesis = node.load_canonical_block_at_height_unverified(0).unwrap();
    let startup =
        launch_v8_verifier::LaunchStartup::from_source(&node.config.network, genesis.hash)
            .unwrap()
            .unwrap();
    let mut p = launch_v8_verifier::pending_launch_action_from_inline_args(
        startup,
        node.best_height() + 1,
        asset_native::native_binding(),
        transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID,
        body.to_vec(),
    )
    .unwrap();
    p.tx_hash = pending_action_hash(&p);
    p
}
fn submit_old_controls(node: &NativeNode, body: &[u8]) -> NativeBlockMeta {
    let p = old_pending(node, body);
    let exact = p.encode();
    node.stage_relayed_pending_action(p).unwrap().unwrap();
    let block = mine(node);
    assert!(block.action_bytes.contains(&exact));
    block
}
fn reject_old_controls(node: &NativeNode, e: &mut Evidence, name: &str, body: &[u8]) {
    let before = snapshot(node);
    let error = node
        .stage_relayed_pending_action(old_pending(node, body))
        .expect_err("consumed ordinary admin must reject")
        .to_string();
    assert!(snapshot(node) == before);
    e.checks
        .push(json!({"name":name,"passed":true,"error":error,"canonical_unchanged":true}));
}
fn assert_outputs(node: &NativeNode, built: &Built) {
    let state = assets(node);
    let recovery = state.recovery().unwrap();
    let notes = canonical_notes(node);
    for i in 0..3 {
        assert_eq!(
            notes[built.next_position as usize + i],
            built.public.base.commitments[i]
        );
    }
    for i in 0..2 {
        assert_eq!(
            recovery.note_at(built.next_position + i),
            Some((ASSET, built.public.base.commitments[i as usize]))
        );
    }
    assert!(
        recovery.note_at(built.next_position + 2).is_none(),
        "HGN fee CM must never enter recovery index"
    );
    for nf in built.public.base.nullifiers {
        assert!(store(node)
            .is_nullifier_spent(poseidon2_v8_state::Poseidon2V8Nullifier::new(nf).unwrap())
            .unwrap());
    }
}
fn rewrite_spend(body: &[u8], change: impl FnOnce(&mut spend::Public)) -> Vec<u8> {
    let a = wire::decode_spend_ref(body).unwrap();
    let mut public = a.public.clone();
    change(&mut public);
    let ciphertexts = a.ciphertexts.map(|c| *c);
    wire::encode_spend(
        &public,
        &ciphertexts,
        a.proof,
        [
            (&a.capsules[0].public, a.capsules[0].proof),
            (&a.capsules[1].public, a.capsules[1].proof),
        ],
    )
    .unwrap()
}

/// Required cheap gate before generating any recovery proof. Uses the same
/// source-qualified Development manifest, template, historical nTime/seal and
/// actual import path as the expensive lifecycle below.
#[test]
#[ignore = "sole coordinator: zero-proof 120-block actual maturity/bootstrap gate"]
fn actual_native_recovery_zero_proof_maturity_bootstrap() {
    let started = Instant::now();
    let e = Evidence::new();
    let a = wallet::RootSecret::from_bytes([41; 32]).derive();
    let b = wallet::RootSecret::from_bytes([42; 32]).derive();
    let f = wallet::RootSecret::from_bytes([43; 32]).derive();
    let credentials = Credentials::new(&a, &b, None);
    let network = network(&f, &credentials);
    let dir = tempfile::tempdir().unwrap();
    let selected_config = config(dir.path(), &network, &f);
    let node = NativeNode::open(selected_config.clone()).unwrap();
    let mut blocks = Vec::new();
    let mut total_hashes = 0u64;
    let mut retargets = Vec::new();
    for height in 1..=consensus::reward::COINBASE_MATURITY {
        let parent = node.best_meta();
        let anchor =
            consensus::pow::pow_retarget_anchor_steps(parent.height, height).map(|steps| {
                retargets.push(height);
                node.load_canonical_block_at_height_unverified(parent.height - steps)
                    .unwrap()
                    .timestamp_ms
            });
        let expected_bits = native_asic_expected_pow_bits_from_schedule(
            TEST_POW_BITS,
            parent.pow_bits,
            parent.height,
            height,
            parent.timestamp_ms,
            anchor,
        )
        .unwrap();
        let (block, hashes) = mine_observed(&node);
        assert_eq!(block.height, height);
        assert_eq!(block.pow_bits, expected_bits);
        assert!(compare_work(&block.cumulative_work, &parent.cumulative_work).is_gt());
        assert_eq!(store(&node).proof_lifetime_count().unwrap().get(), 0);
        if height < consensus::reward::COINBASE_MATURITY {
            assert_eq!(store(&node).note_tip().unwrap().leaf_count(), 0);
        }
        total_hashes = total_hashes.checked_add(hashes).unwrap();
        blocks.push(json!({"height":height,"timestamp_ms":block.timestamp_ms,
            "pow_bits":block.pow_bits,"actual_hashes":hashes,"block_hash":hex::encode(block.hash)}));
    }
    assert_eq!(
        retargets,
        (20..=consensus::reward::COINBASE_MATURITY)
            .step_by(10)
            .collect::<Vec<_>>()
    );
    let fee = first_fee(&node, &f);
    assert_eq!(fee.note.asset_id, 0);
    assert!(fee.note.value > 1);
    let notes = canonical_notes(&node);
    assert_eq!(
        notes.len(),
        rewards(&node.load_canonical_block_at_height_unverified(1).unwrap()).len()
    );
    assert_eq!(
        notes[fee.position as usize],
        private_spend::note_commitment(fee.note).unwrap()
    );
    assert!(!store(&node)
        .is_nullifier_spent(
            poseidon2_v8_state::Poseidon2V8Nullifier::new(
                private_spend::real_nullifier(fee.key, fee.position, fee.note).unwrap()
            )
            .unwrap()
        )
        .unwrap());
    let current = assets(&node);
    assert_eq!(
        current.registry().row(ASSET).unwrap().counters,
        StablecoinPoseidon2V8Counters::default()
    );
    assert!(current.recovery().unwrap().note_at(fee.position).is_none());
    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh = NativeNode::open(config(fresh_dir.path(), &network, &f)).unwrap();
    // Announced import checks wall-clock future skew as well as the actual
    // schedule/PoW; local mined import alone does not establish this join.
    sync(&node, &fresh, 1);
    assert_same(&node, &fresh);
    drop(fresh);
    let before_restart = snapshot(&node);
    drop(current);
    drop(node);
    let reopened = NativeNode::reopen_after_sled_release_for_test(selected_config).unwrap();
    assert!(snapshot(&reopened) == before_restart);
    assert_eq!(first_fee(&reopened, &f).position, fee.position);
    let report = json!({"schema":"hegemon.actual-native-recovery-bootstrap.v1","status":"PASSED",
        "scope":"zero-proof real NativeNode maturity and historical-nTime scheduled-PoW bootstrap",
        "height":reopened.best_height(),"maturity":consensus::reward::COINBASE_MATURITY,
        "proof_components_generated":0,"canonical_proof_units":0,"actual_hashes":total_hashes,
        "retarget_heights":retargets,"historical_block_interval_ms":HISTORICAL_BLOCK_INTERVAL_MS,
        "max_rounds_per_block":MAX_MINING_ROUNDS_PER_BLOCK,"genesis_timestamp_ms":network.genesis_timestamp_ms(),
        "actual_seals_expected_bits_and_import_verified":true,"future_skew_checked_by_announced_sync":true,
        "reward_matures_only_at_protocol_height":true,"native_fee_note_in_shared_tree":true,
        "cold_restart_exact_snapshot":true,"fresh_sync_exact_rows":true,"recovery_output_index_untouched":true,
        "chain_id":hex::encode(network.chain_id()),"manifest_digest":network.manifest_digest().map(hex::encode),
        "blocks":blocks,"elapsed_seconds":started.elapsed().as_secs_f64(),"production_authority":false});
    e.retain(
        "bootstrap-receipt.json",
        &serde_json::to_vec_pretty(&report).unwrap(),
    );
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}

/// Expensive sole-coordinator endpoint. This test uses public disposable keys;
/// all acceptance goes through current source-owned NativeNode admission,
/// mining/import and cold replay. An unqualified profile fails at network().
#[test]
#[ignore = "real NativeNode lifecycle: 46 fresh proof components, 120+ PoW blocks; sole coordinator only"]
fn actual_native_recovery_mint_holder_delegate_admin_restart_and_reorg() {
    let started = Instant::now();
    let mut e = Evidence::new();
    let a = wallet::RootSecret::from_bytes([41; 32]).derive();
    let b = wallet::RootSecret::from_bytes([42; 32]).derive();
    let f = wallet::RootSecret::from_bytes([43; 32]).derive();
    let credentials = Credentials::new(&a, &b, None);
    let revoked_credentials = Credentials::new(&a, &b, Some(0));
    let revoked_surviving_holder = Credentials::new(&a, &b, Some(1));
    let network = network(&f, &credentials);
    let dir_a = e.native_chain_dir("full-a");
    let dir_b = e.native_chain_dir("full-b");
    let dir_c = e.native_chain_dir("full-fresh");
    let config_a = config(dir_a.path(), &network, &f);
    let node_a = NativeNode::open(config_a.clone()).unwrap();
    let mut issuer_cli = IssuerCliFixture::new(&node_a, &f);
    let node_b = NativeNode::open(config(dir_b.path(), &network, &f)).unwrap();
    let spend_id = asset_recovery_native::RECOVERY_SPEND_ACTION_ID;
    let admin_id = asset_recovery_native::RECOVERY_ADMIN_ACTION_ID;
    for _ in 0..consensus::reward::COINBASE_MATURITY {
        mine(&node_a);
    }
    let fee0 = first_fee(&node_a, &f);
    assert_eq!(fee0.note.asset_id, 0);
    e.check("actual_mined_reward_matures_into_shared_note_tree");

    let mint = build_mint_via_cli(
        &node_a,
        &mut e,
        &mut issuer_cli,
        &fee0,
        &a,
        &b,
        &f,
        &credentials,
    );
    // Honest real proof, wrong current credential root: host authentication must
    // reject before publishing any snapshot/NF/commitment changes.
    let wrong_credentials = rewrite_spend(&mint.body, |p| {
        p.base.credential_root = revoked_credentials.root
    });
    reject(
        &node_a,
        &mut e,
        "wrong_current_credentials_atomic",
        &wrong_credentials,
        spend_id,
        &[],
    );
    let decoded = wire::decode_spend_ref(&mint.body).unwrap();
    let decoded_ciphertexts = decoded.ciphertexts.map(|c| *c);
    let mut wrong_cm = decoded.public.clone();
    wrong_cm.base.commitments[0] = [99; 7];
    assert!(wire::encode_spend(
        &wrong_cm,
        &decoded_ciphertexts,
        decoded.proof,
        [
            (&decoded.capsules[0].public, decoded.capsules[0].proof),
            (&decoded.capsules[1].public, decoded.capsules[1].proof)
        ]
    )
    .is_err());
    let mut wrong_archive = decoded.public.clone();
    wrong_archive.row.descriptor.archive_key_commitment = [98; 7];
    assert!(wire::encode_spend(
        &wrong_archive,
        &decoded_ciphertexts,
        decoded.proof,
        [
            (&decoded.capsules[0].public, decoded.capsules[0].proof),
            (&decoded.capsules[1].public, decoded.capsules[1].proof)
        ]
    )
    .is_err());
    e.check("wrong_output_CM_and_archive_binding_rejected_by_exact_carrier");
    let mut corrupted = mint.body.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    // Keep canonical source/frame, change an actual segment proof byte. This
    // must fail real parsing/verification, never be accepted as a parser token.
    reject(
        &node_a,
        &mut e,
        "modified_actual_capsule_proof_atomic",
        &corrupted,
        spend_id,
        &[],
    );
    peer_transport_roundtrip(&node_a, &mut e, &mint.body);
    submit_mine_via_cli(&node_a, &mut e, &mut issuer_cli, &mint);
    assert_outputs(&node_a, &mint);
    assert_eq!(
        assets(&node_a)
            .registry()
            .row(ASSET)
            .unwrap()
            .counters
            .total_debt,
        10
    );
    assert_eq!(snapshot(&node_a).proofs, wire::PROOF_UNITS as u64);
    e.check("mint_actual_issuer_and_all_five_proofs_accounting_native_fee_index");
    sync(&node_a, &node_b, 1);
    assert_same(&node_a, &node_b);
    let common = node_a.best_height();
    let common_fee = mint.change_fee(fee0.key);
    let holder = build_spend(
        &node_a,
        &mut e,
        "holder_competing",
        TRANSFER,
        0,
        Some((&mint.outputs[0], mint.next_position)),
        &common_fee,
        &a,
        &b,
        &f,
        &credentials,
    );
    let delegate = build_spend(
        &node_a,
        &mut e,
        "delegate_competing",
        TRANSFER,
        2,
        Some((&mint.outputs[0], mint.next_position)),
        &common_fee,
        &a,
        &b,
        &f,
        &credentials,
    );
    assert_eq!(
        holder.public.base.nullifiers,
        delegate.public.base.nullifiers
    );
    assert_ne!(
        holder.public.base.commitments,
        delegate.public.base.commitments
    );
    submit_mine(&node_a, &holder.body, spend_id);
    assert_outputs(&node_a, &holder);
    reject(
        &node_a,
        &mut e,
        "holder_then_delegate_common_NF_atomic",
        &delegate.body,
        spend_id,
        &["NF", "nullifier"],
    );
    submit_mine(&node_b, &delegate.body, spend_id);
    assert_outputs(&node_b, &delegate);
    reject(
        &node_b,
        &mut e,
        "delegate_then_holder_common_NF_atomic",
        &holder.body,
        spend_id,
        &["NF", "nullifier"],
    );
    mine(&node_b);
    assert!(node_b.best_meta().cumulative_work > node_a.best_meta().cumulative_work);
    sync(&node_b, &node_a, common + 1);
    assert_same(&node_a, &node_b);
    assert_outputs(&node_a, &delegate);
    assert_ne!(
        assets(&node_a)
            .recovery()
            .unwrap()
            .note_at(holder.next_position),
        Some((ASSET, holder.public.base.commitments[0]))
    );
    e.check("strict_actual_work_reorg_replaces_holder_outputs_with_delegate_outputs");

    let delegate_fee = delegate.change_fee(fee0.key);
    let target = delegate.next_position + 1;
    let historic = build_spend(
        &node_a,
        &mut e,
        "delegate_before_freeze",
        TRANSFER,
        2,
        Some((&delegate.outputs[1], target)),
        &delegate_fee,
        &a,
        &b,
        &f,
        &credentials,
    );
    let before_freeze = node_a.best_height();
    let (orphan_freeze, orphan_id) = recovery_admin(
        &node_a,
        &mut e,
        "orphan_note_freeze",
        Some((target, true)),
        None,
        None,
    );
    submit_mine(&node_a, &orphan_freeze, admin_id);
    assert!(assets(&node_a)
        .recovery()
        .unwrap()
        .admin_action_is_consumed(&orphan_id));
    reject(
        &node_a,
        &mut e,
        "current_target_freeze_rejects_previous_live_delegate",
        &historic.body,
        spend_id,
        &["CURRENT", "control", "epoch"],
    );
    mine(&node_b);
    mine(&node_b);
    assert!(node_b.best_meta().cumulative_work > node_a.best_meta().cumulative_work);
    sync(&node_b, &node_a, before_freeze + 1);
    assert_same(&node_a, &node_b);
    assert!(!assets(&node_a)
        .recovery()
        .unwrap()
        .admin_action_is_consumed(&orphan_id));
    assert_eq!(
        assets(&node_a)
            .recovery()
            .unwrap()
            .row(ASSET)
            .unwrap()
            .controls
            .epoch,
        0
    );
    e.check("actual_admin_reorg_restores_epoch_freeze_and_semantic_replay_set");

    let (freeze, freeze_id) = recovery_admin(
        &node_a,
        &mut e,
        "note_freeze",
        Some((target, true)),
        None,
        None,
    );
    submit_mine_http(&node_a, &mut e, &freeze, admin_id);
    let frozen = assets(&node_a);
    let fr = frozen.recovery().unwrap();
    let row = *fr.row(ASSET).unwrap();
    let path = fr.freeze_witness(ASSET, target).unwrap();
    assert_eq!(
        recovery::freeze_root(
            &row.descriptor,
            network.chain_id(),
            target,
            delegate.public.base.commitments[1],
            true,
            &path
        )
        .unwrap(),
        row.controls.note_freeze_root
    );
    assert_ne!(
        recovery::freeze_root(
            &row.descriptor,
            network.chain_id(),
            target,
            delegate.public.base.commitments[0],
            true,
            &path
        )
        .unwrap(),
        row.controls.note_freeze_root
    );
    e.check("freeze_targets_exact_canonical_position_and_CM");
    // Even replacing the historical statement with the exact CURRENT row
    // cannot turn the previous genuine proof into authority for a frozen note.
    let rewrapped_frozen = rewrite_spend(&historic.body, |p| p.row = row);
    reject(
        &node_a,
        &mut e,
        "current_frozen_row_cannot_rewrap_old_genuine_proof",
        &rewrapped_frozen,
        spend_id,
        &[],
    );
    let (unfreeze, unfreeze_id) = recovery_admin(
        &node_a,
        &mut e,
        "note_unfreeze",
        Some((target, false)),
        None,
        None,
    );
    submit_mine(&node_a, &unfreeze, admin_id);
    let (rotation, rotation_id) = recovery_admin(
        &node_a,
        &mut e,
        "delegate_rotate",
        None,
        Some(DELEGATE2),
        None,
    );
    submit_mine(&node_a, &rotation, admin_id);
    reject(
        &node_a,
        &mut e,
        "rotation_rejects_historic_delegate_row",
        &historic.body,
        spend_id,
        &["CURRENT", "control", "epoch"],
    );
    let holder_revoked_for_recovery = old_controls(
        &node_a,
        &mut e,
        "old_holder_revoked_before_delegate_recovery",
        false,
        revoked_credentials.root,
    );
    submit_old_controls(&node_a, &holder_revoked_for_recovery);
    let burn = build_spend(
        &node_a,
        &mut e,
        "rotated_delegate_burn",
        BURN,
        3,
        Some((&delegate.outputs[1], target)),
        &delegate_fee,
        &a,
        &b,
        &f,
        &revoked_credentials,
    );
    submit_mine(&node_a, &burn.body, spend_id);
    assert_outputs(&node_a, &burn);
    assert_eq!(
        assets(&node_a)
            .registry()
            .row(ASSET)
            .unwrap()
            .counters
            .total_debt,
        9
    );
    e.check("rotated_current_delegate_burn_updates_issued_debt_and_shared_fee_NF");
    e.check("selected_current_delegate_recovers_with_revoked_old_holder_credential");
    let holder_restored_after_recovery = old_controls(
        &node_a,
        &mut e,
        "holder_restore_after_delegate_recovery",
        false,
        credentials.root,
    );
    submit_old_controls(&node_a, &holder_restored_after_recovery);
    let burn_fee = burn.change_fee(fee0.key);
    let pending_delegate = build_spend(
        &node_a,
        &mut e,
        "delegate_before_revocation",
        TRANSFER,
        3,
        Some((&burn.outputs[1], burn.next_position + 1)),
        &burn_fee,
        &a,
        &b,
        &f,
        &credentials,
    );
    let (revoke, revoke_id) =
        recovery_admin(&node_a, &mut e, "delegate_revoke", None, None, Some(true));
    submit_mine(&node_a, &revoke, admin_id);
    reject(
        &node_a,
        &mut e,
        "current_revocation_rejects_prebuilt_delegate",
        &pending_delegate.body,
        spend_id,
        &["CURRENT", "control", "epoch"],
    );
    let mut holder_after = build_spend(
        &node_a,
        &mut e,
        "holder_after_delegate_revocation",
        TRANSFER,
        1,
        Some((&burn.outputs[1], burn.next_position + 1)),
        &burn_fee,
        &a,
        &b,
        &f,
        &credentials,
    );
    let whole_freeze = old_controls(
        &node_a,
        &mut e,
        "whole_asset_freeze",
        true,
        credentials.root,
    );
    submit_old_controls(&node_a, &whole_freeze);
    reject(
        &node_a,
        &mut e,
        "whole_asset_freeze_rejects_holder_even_with_live_note",
        &holder_after.body,
        spend_id,
        &[],
    );
    let whole_unfreeze = old_controls(
        &node_a,
        &mut e,
        "whole_asset_unfreeze",
        false,
        credentials.root,
    );
    submit_old_controls(&node_a, &whole_unfreeze);
    let credential_revoke = old_controls(
        &node_a,
        &mut e,
        "holder_credential_revoke",
        false,
        revoked_surviving_holder.root,
    );
    submit_old_controls(&node_a, &credential_revoke);
    reject(
        &node_a,
        &mut e,
        "current_holder_credential_revocation_atomic",
        &holder_after.body,
        spend_id,
        &[],
    );
    let credential_restore = old_controls(
        &node_a,
        &mut e,
        "holder_credential_restore",
        false,
        credentials.root,
    );
    submit_old_controls(&node_a, &credential_restore);
    reject_old_controls(
        &node_a,
        &mut e,
        "whole_asset_admin_replay_after_root_cycle",
        &whole_freeze,
    );
    assert!(node_a.best_height() - holder_after.public.base.parent_height <= 12);
    // This proof intentionally survives four intervening control blocks. Its
    // historical H, input positions and exact bytes stay unchanged; only this
    // fixture's prospective output index must advance with matured rewards.
    let reference_height = holder_after.public.base.parent_height;
    assert_eq!(node_a.best_height() - reference_height, 4);
    let matured_while_pending = (reference_height + 1..=node_a.best_height())
        .map(|height| {
            assert!(height >= consensus::reward::COINBASE_MATURITY);
            let origin = height + 1 - consensus::reward::COINBASE_MATURITY;
            rewards(
                &node_a
                    .load_canonical_block_at_height_unverified(origin)
                    .unwrap(),
            )
            .len()
        })
        .sum::<usize>();
    let inclusion_output_start = u32::try_from(canonical_notes(&node_a).len()).unwrap();
    assert_eq!(
        inclusion_output_start,
        holder_after
            .next_position
            .checked_add(u32::try_from(matured_while_pending).unwrap())
            .unwrap()
    );
    holder_after.next_position = inclusion_output_start;
    submit_mine(&node_a, &holder_after.body, spend_id);
    assert_outputs(&node_a, &holder_after);
    assert_eq!(
        assets(&node_a)
            .registry()
            .row(ASSET)
            .unwrap()
            .counters
            .total_debt,
        9
    );
    assert_eq!(holder_after.fee_note.value, fee0.note.value - 4);
    assert_eq!(snapshot(&node_a).proofs, 4 * wire::PROOF_UNITS as u64 + 10);
    e.check("holder_still_authorized_after_delegate_revoke_and_current_controls_restore");

    let final_state = snapshot(&node_a);
    e.retain("final-asset-snapshot.scale", &final_state.asset);
    drop(node_a);
    let reopened = NativeNode::reopen_after_sled_release_for_test(config_a).unwrap();
    assert!(snapshot(&reopened) == final_state);
    for id in [freeze_id, unfreeze_id, rotation_id, revoke_id] {
        assert!(assets(&reopened)
            .recovery()
            .unwrap()
            .admin_action_is_consumed(&id));
    }
    assert!(!assets(&reopened)
        .recovery()
        .unwrap()
        .admin_action_is_consumed(&orphan_id));
    e.check("cold_restart_reverifies_exact_body_chain_snapshots_and_admin_replay_history");
    let fresh = NativeNode::open(config(dir_c.path(), &network, &f)).unwrap();
    sync(&reopened, &fresh, 1);
    assert_same(&reopened, &fresh);
    sync(&reopened, &node_b, node_b.best_height() + 1);
    assert_same(&reopened, &node_b);
    e.check("fresh_sync_and_existing_peer_replay_all_canonical_exact_rows");
    let components = e
        .proofs
        .iter()
        .map(|p| p["proof_bytes"].as_array().unwrap().len())
        .sum::<usize>();
    assert_eq!(components, 7 * wire::PROOF_UNITS + 11);
    let report = json!({"schema":"hegemon.actual-native-recovery-lifecycle.v1","status":"PASSED",
        "scope":"finite Development NativeNode mining/import/restart/reorg with genuine source proofs",
        "issuer_cli_actual_online_prepare_export_submit":true,
        "issuer_cli_binary_sha256":issuer_cli.binary_sha256,
        "proof_components_generated":components,"carrier_candidates_generated":e.proofs.len(),
        "canonical_proof_units":final_state.proofs,"checks":e.checks,"proof_candidates":e.proofs,
        "final_height":final_state.height,"final_hash":hex::encode(final_state.hash),
        "final_asset_snapshot_sha256":hash(&final_state.asset),
        "final_asset_snapshot_bytes":final_state.asset.len(),
        "final_note_leaf_count":final_state.note.leaf_count(),"native_fees_paid":4,"total_debt":9,
        "chain_id":hex::encode(network.chain_id()),"manifest_digest":network.manifest_digest().map(hex::encode),
        "wire_version":wire::VERSION,"spend_relation":hex::encode(spend::relation_digest()),
        "admin_relation":hex::encode(admin::relation_digest()),"capsule_relation":hex::encode(capsule::relation_digest()),
        "elapsed_seconds":started.elapsed().as_secs_f64(),"fixture_secrets_are_public_disposable_constants":true,
        "production_authority":false,"unconditional_security_closure":false});
    e.retain("receipt.json", &serde_json::to_vec_pretty(&report).unwrap());
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}

// The archive custodian is a separate, explicitly selected local process. This
// checks the holder-facing request boundary, not OS isolation against a hostile
// process running as the same user. No archive/action key belongs in this JSON.
fn cooperative_holder_request_is_separated(
    request: &Value,
    executable: &Path,
    key_file: &Path,
) -> bool {
    fn no_secret_fields(value: &Value) -> bool {
        match value {
            Value::Object(fields) => fields.iter().all(|(name, value)| {
                ![
                    "archive_key",
                    "archive_secret",
                    "issuer_secret",
                    "delegate_secret",
                    "admin_secret",
                    "spend_key",
                    "spend_secret",
                ]
                .contains(&name.as_str())
                    && no_secret_fields(value)
            }),
            Value::Array(values) => values.iter().all(no_secret_fields),
            _ => true,
        }
    }
    no_secret_fields(request)
        && request["route"] == "holder"
        && request["archive_provider"]
            == json!({"executable":executable,
                "args":["--recovery-archive-worker","--archive-key-file",key_file],
                "timeout_seconds":600})
}

fn cooperative_cli_journal(
    cli: &mut IssuerCliFixture,
    reservation: &str,
    status: &str,
    action_id: Option<[u8; 48]>,
    mined: Option<(u64, [u8; 32])>,
    expected_rows: usize,
) {
    let rows = cli.call("recovery.journal", json!({}));
    let rows = rows.as_array().expect("cooperative public journal");
    assert_eq!(rows.len(), expected_rows);
    let id = hex::decode(reservation).unwrap();
    let matching = rows
        .iter()
        .filter(|row| row["id"] == json!(id))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    let row = matching[0];
    assert!(row["status"] == status && row["inputs_reserved"] == true);
    assert!(row["action_id"] == json!(action_id.map(|id| id.to_vec()).unwrap_or_default()));
    assert!(row["mined_in"] == json!(mined));
}

fn cooperative_cli_owned_input(cli: &mut IssuerCliFixture, node: &Arc<NativeNode>, mint: &Built) {
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    issuer_cli_http(node, |endpoint| {
        cli.call("asset.sync", cli.online(endpoint, genesis));
    });
    let notes = cli.call("recovery.notes", json!({}));
    let owned = notes["recovery_notes"].as_array().unwrap();
    let input = owned
        .iter()
        .find(|n| n["position"] == mint.next_position)
        .unwrap();
    let context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
        chain_id: mint.public.base.chain_id,
        asset_id: ASSET,
        stable_policy_id: POLICY,
        output_commitment: mint.public.base.commitments[0],
    };
    assert!(input["asset_id"] == ASSET && input["value"] == 10);
    assert!(input["commitment"] == json!(mint.public.base.commitments[0]));
    assert!(
        input["nullifier"]
            == json!(mint.outputs[0]
                .common_nullifier(&context, mint.next_position)
                .unwrap())
    );
    assert!(input["spent"] == false && input["reserved"] == false);
    assert!(input["created_height"] == node.best_height());
    assert!(input["created_block_hash"] == json!(node.best_meta().hash));
    let fee = notes["native_fee_notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["position"] == mint.next_position + 2)
        .unwrap();
    assert!(fee["value"] == mint.fee_note.value && fee["spent"] == false);
}

#[cfg(unix)]
fn build_cooperative_holder_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    mint: &Built,
    a: &wallet::DerivedKeys,
    b: &wallet::DerivedKeys,
    credentials: &Credentials,
) -> Built {
    use std::os::unix::fs::PermissionsExt;
    let started = Instant::now();
    let before = snapshot(node);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let address_a = a.poseidon2_v8_address(0).unwrap();
    let address_b = b.poseidon2_v8_address(0).unwrap();
    // This file is configured by the disposable custodian/test operator. Only
    // its path reaches the holder request; the worker alone reads its raw key.
    let key_file = cli.work.path().join("cooperative-archive-key.bin");
    issuer_cli_write_private(&key_file, &ARCHIVE);
    assert_eq!(
        std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    let reply = issuer_cli_http(node, |endpoint| {
        let mut info = cli.online(endpoint, genesis);
        info["asset_id"] = json!(ASSET);
        info["position"] = json!(mint.next_position);
        let info = cli.call("recovery.info", info);
        assert!(info["context"]["parent_hash"] == hex::encode(before.hash));
        assert!(info["context"]["parent_height"] == before.height);
        let credential = |i: usize| {
            json!({"index":credentials.paths[i].index,
            "expires_at":credentials.paths[i].expires_at,"siblings":credentials.paths[i].siblings})
        };
        let mut request = cli.online(endpoint, genesis);
        request.as_object_mut().unwrap().extend(json!({
            "confirm":true,"expected_parent_hash":hex::encode(before.hash),"expected_epoch":0,
            "asset_id":ASSET,"operation":"transfer","route":"holder","amount":4,"fee":1,
            "input_position":mint.next_position,"fee_position":mint.next_position+2,
            "recipient":address_b.shielded_address().encode().unwrap(),
            "change_recipient":address_a.shielded_address().encode().unwrap(),"native_change_index":0,
            "archive_provider":{"executable":cli.binary,
                "args":["--recovery-archive-worker","--archive-key-file",key_file],"timeout_seconds":600},
            "credentials":[credential(0),credential(1),credential(0)]
        }).as_object().unwrap().clone());
        assert!(
            cooperative_holder_request_is_separated(&request, &cli.binary, &key_file),
            "ordinary holder request must contain provider configuration only"
        );
        cli.call("recovery.prepare", request)
    });
    // A retained proof is sufficient for all subsequent exports/submission.
    // No archive worker/key is available for those later process invocations.
    std::fs::remove_file(&key_file).unwrap();
    assert!(!key_file.exists());
    assert!(
        snapshot(node) == before,
        "holder construction must not publish canonical state"
    );
    assert!(reply["status"] == "candidate" && reply["proof_units"] == wire::PROOF_UNITS);
    let reservation = reply["reservation_id"].as_str().unwrap().to_owned();
    assert!(hex::decode(&reservation).is_ok_and(|id| id.len() == 32));
    cli.reservation = Some(reservation.clone());
    let body = cli.export("cooperative-holder-initial.action");
    cooperative_cli_journal(cli, &reservation, "Candidate", None, None, 2);
    let decoded = wire::decode_spend_ref(&body).unwrap();
    let public = decoded.public.clone();
    assert_eq!(public.words().unwrap().len(), 182);
    assert!(reply["public_statement"] == json!(public.words().unwrap()));
    assert!(
        public.base.parent_height == before.height
            && public.base.reference_parent_hash == before.hash
    );
    assert!(
        public.base.operation == TRANSFER && public.base.magnitude == 0 && public.base.fee == 1
    );
    assert!(public.row == mint.public.row);
    let input_context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
        chain_id: public.base.chain_id,
        asset_id: ASSET,
        stable_policy_id: POLICY,
        output_commitment: mint.public.base.commitments[0],
    };
    assert!(
        public.base.nullifiers[0]
            == mint.outputs[0]
                .common_nullifier(&input_context, mint.next_position)
                .unwrap()
    );
    assert!(
        public.base.nullifiers[1]
            == private_spend::real_nullifier(
                a.spend.poseidon2_v8_words().unwrap(),
                mint.next_position + 2,
                mint.fee_note
            )
            .unwrap()
    );
    assert!(decoded.proof.len() <= wire::MAX_PROOF_BYTES);
    for c in &decoded.capsules {
        assert_eq!(c.public.words().unwrap().len(), 82);
        assert!(capsule::bundle_components(c.proof)
            .unwrap()
            .iter()
            .all(|p| p.len() <= wire::MAX_PROOF_BYTES));
    }
    let outputs = std::array::from_fn(|i| {
        let (holder, address) = if i == 0 {
            (b, &address_b)
        } else {
            (a, &address_a)
        };
        let delivered = build::decrypt_holder_output(
            &public,
            i as u8,
            decoded.ciphertexts[i],
            address.secret_key(),
            recipient(holder),
            authority(holder),
        )
        .unwrap();
        // These checks run in the privileged TEST coordinator, not walletd's
        // ordinary holder invocation or the provider's request/response pipes.
        let archived =
            build::decrypt_archive_material(&decoded.capsules[i].public, &ARCHIVE).unwrap();
        let context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
            chain_id: public.base.chain_id,
            asset_id: ASSET,
            stable_policy_id: POLICY,
            output_commitment: public.base.commitments[i],
        };
        assert!(
            delivered.material_words(&context).unwrap()[..]
                == archived.material_words(&context).unwrap()[..]
        );
        assert!(build::decrypt_archive_material(&decoded.capsules[i].public, &[24; 32]).is_err());
        let mut wrong_context = context;
        wrong_context.output_commitment = public.base.commitments[1 - i];
        assert!(delivered.validate(&wrong_context).is_err());
        delivered
    });
    assert!(outputs[0].as_note().value == 4 && outputs[1].as_note().value == 6);
    let fee_note = build::decrypt_native_fee_change(
        &public,
        decoded.ciphertexts[2],
        address_a.secret_key(),
        0,
        recipient(a),
        authority(a),
    )
    .unwrap()
    .as_note();
    assert!(fee_note.asset_id == 0 && fee_note.value == mint.fee_note.value - 1);
    e.proof(
        "cooperative-holder",
        "spend",
        &body,
        started.elapsed().as_secs_f64(),
    );
    e.check("holder_provider_only_request_and_two_real_capsule_deliveries");
    Built {
        body,
        public,
        outputs,
        fee_note,
        next_position: canonical_notes(node).len() as u32,
    }
}

fn submit_cooperative_holder_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    holder: &Built,
) -> NativeBlockMeta {
    let before = snapshot(node);
    let expected = pending(
        node,
        &holder.body,
        asset_recovery_native::RECOVERY_SPEND_ACTION_ID,
    );
    let exact = expected.encode();
    let expected_hash = expected.tx_hash.into_bytes();
    let reservation = cli.reservation.clone().unwrap();
    assert!(cli.export("cooperative-holder-before-submit.action") == holder.body);
    cooperative_cli_journal(cli, &reservation, "Candidate", None, None, 2);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let reply = issuer_cli_http(node, |endpoint| {
        let mut request = cli.online(endpoint, genesis);
        request["reservation_id"] = json!(reservation);
        request["confirm"] = json!(true);
        cli.call("recovery.submit", request)
    });
    assert!(reply["status"] == "submitted" && reply["action_id"] == hex::encode(expected_hash));
    cooperative_cli_journal(cli, &reservation, "Submitted", Some(expected_hash), None, 2);
    assert!(cli.export("cooperative-holder-after-submit.action") == holder.body);
    assert!(snapshot(node) == before);
    assert!(issuer_cli_hash_file(&cli.binary) == cli.binary_sha256);
    e.checks.push(
        json!({"name":"cooperative_holder_exact_HTTP18_submit_after_key_file_removed",
        "passed":true,"action_id":18,"action_hash":hex::encode(expected_hash),
        "carrier_bytes":holder.body.len(),"carrier_sha256":hash(&holder.body),
        "exact_export_before_and_after_submit":true,"new_walletd_process_per_call":true,
        "public_source_bound_submit":true,"production_router_limits_and_dispatch":true,
        "archive_key_required_for_export_or_submit":false}),
    );
    let block = mine(node);
    assert!(block.action_bytes.contains(&exact));
    let included = decode_block_actions(&block).unwrap();
    assert!(included
        .iter()
        .any(|a| a.action_id == 18 && a.public_args == holder.body));
    block
}

/// Independent positive trusted-cooperation endpoint. This does not replace the
/// full46-component lifecycle, which remains byte-identical above. Both issuer
/// holder, delegate and administrator candidates are freshly generated through
/// actual walletd processes.
#[cfg(unix)]
#[test]
#[ignore = "real four-role archive-provider CLI: 16 fresh proof components, 120+ PoW blocks; sole coordinator only"]
fn actual_native_recovery_cooperative_holder_archive_provider_cli() {
    let started = Instant::now();
    let mut e = Evidence::new();
    // Existing CLI root43 owns both the mined fee and the first recoverable note.
    let a = wallet::RootSecret::from_bytes([43; 32]).derive();
    let f = wallet::RootSecret::from_bytes([43; 32]).derive();
    let b = wallet::RootSecret::from_bytes([42; 32]).derive();
    let credentials = Credentials::new(&a, &b, None);
    let selected_network = network(&f, &credentials);
    let dir = e.native_chain_dir("provider-a");
    let selected_config = config(dir.path(), &selected_network, &f);
    let node = NativeNode::open(selected_config.clone()).unwrap();
    let mut cli = IssuerCliFixture::new(&node, &f);
    for _ in 0..consensus::reward::COINBASE_MATURITY {
        mine(&node);
    }
    let fee = first_fee(&node, &f);
    assert_eq!(fee.note.asset_id, 0);
    e.check("cooperative_fixture_actual_mined_fee_maturity");
    let mint = build_mint_via_cli(&node, &mut e, &mut cli, &fee, &a, &b, &f, &credentials);
    let mint_reservation = cli.reservation.clone().unwrap();
    let mint_hash = pending(&node, &mint.body, 18).tx_hash.into_bytes();
    peer_transport_roundtrip(&node, &mut e, &mint.body);
    let mint_block = submit_mine_via_cli(&node, &mut e, &mut cli, &mint);
    assert_outputs(&node, &mint);
    assert_eq!(snapshot(&node).proofs, wire::PROOF_UNITS as u64);
    cooperative_cli_owned_input(&mut cli, &node, &mint);
    cooperative_cli_journal(
        &mut cli,
        &mint_reservation,
        "Submitted",
        Some(mint_hash),
        Some((mint_block.height, mint_block.hash)),
        1,
    );
    e.check("holder_input_and_fee_change_discovered_by_actual_authenticated_sync");
    let holder =
        build_cooperative_holder_via_cli(&node, &mut e, &mut cli, &mint, &a, &b, &credentials);
    let holder_reservation = cli.reservation.clone().unwrap();
    let holder_hash = pending(&node, &holder.body, 18).tx_hash.into_bytes();
    let holder_block = submit_cooperative_holder_via_cli(&node, &mut e, &mut cli, &holder);
    assert_outputs(&node, &holder);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    issuer_cli_http(&node, |endpoint| {
        cli.call("asset.sync", cli.online(endpoint, genesis));
    });
    let owned = cli.call("recovery.notes", json!({}));
    let rows = owned["recovery_notes"].as_array().unwrap();
    let old = rows
        .iter()
        .find(|n| n["position"] == mint.next_position)
        .unwrap();
    assert!(old["spent"] == true && old["value"] == 10);
    let change = rows
        .iter()
        .find(|n| n["position"] == holder.next_position + 1)
        .unwrap();
    assert!(change["spent"] == false && change["reserved"] == false && change["value"] == 6);
    assert!(change["commitment"] == json!(holder.public.base.commitments[1]));
    let native_fee = owned["native_fee_notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["position"] == holder.next_position + 2)
        .unwrap();
    assert!(native_fee["spent"] == false && native_fee["value"] == fee.note.value - 2);
    cooperative_cli_journal(
        &mut cli,
        &holder_reservation,
        "Submitted",
        Some(holder_hash),
        Some((holder_block.height, holder_block.hash)),
        2,
    );
    assert!(cli.export("cooperative-holder-after-inclusion.action") == holder.body);
    assert_eq!(
        assets(&node)
            .registry()
            .row(ASSET)
            .unwrap()
            .counters
            .total_debt,
        10
    );
    assert_eq!(snapshot(&node).proofs, 2 * wire::PROOF_UNITS as u64);
    e.check("cooperative_holder_real_inclusion_and_persistent_global_NF_sync");
    // Privileged recovery targets B's four-unit note. This wallet contains only
    // root43; B's root42 ordinary spend secret is absent from its encrypted store
    // and from the delegate request. Root43 independently pays the native fee.
    let delegate =
        build_privileged_delegate_via_cli(&node, &mut e, &mut cli, &holder, &a, &b, &credentials);
    let delegate_reservation = cli.reservation.clone().unwrap();
    let delegate_hash = pending(&node, &delegate.body, 18).tx_hash.into_bytes();
    let delegate_block = submit_privileged_delegate_via_cli(&node, &mut e, &mut cli, &delegate);
    assert_outputs(&node, &delegate);
    issuer_cli_http(&node, |endpoint| {
        cli.call("asset.sync", cli.online(endpoint, genesis));
    });
    let owned_after_delegate = cli.call("recovery.notes", json!({}));
    let rows_after_delegate = owned_after_delegate["recovery_notes"].as_array().unwrap();
    let recovered = rows_after_delegate
        .iter()
        .find(|n| n["position"] == delegate.next_position)
        .unwrap();
    assert!(
        recovered["spent"] == false && recovered["reserved"] == false && recovered["value"] == 4
    );
    assert!(recovered["commitment"] == json!(delegate.public.base.commitments[0]));
    let surviving_change = rows_after_delegate
        .iter()
        .find(|n| n["position"] == holder.next_position + 1)
        .unwrap();
    assert!(surviving_change["spent"] == false && surviving_change["value"] == 6);
    let fee_after_delegate = owned_after_delegate["native_fee_notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["position"] == delegate.next_position + 2)
        .unwrap();
    assert!(
        fee_after_delegate["spent"] == false && fee_after_delegate["value"] == fee.note.value - 3
    );
    cooperative_cli_journal(
        &mut cli,
        &delegate_reservation,
        "Submitted",
        Some(delegate_hash),
        Some((delegate_block.height, delegate_block.hash)),
        3,
    );
    assert!(cli.export("privileged-delegate-after-inclusion.action") == delegate.body);
    e.check("privileged_delegate_real_inclusion_and_persistent_independent_fee_sync");
    let (_admin_body, admin_semantic_id) = rotate_policy_admin_via_cli(&node, &mut e, &mut cli);
    let current_delegate = recovery::delegate_action_commitment(DELEGATE2).unwrap();
    issuer_cli_http(&node, |endpoint| {
        cli.call("asset.sync", cli.online(endpoint, genesis));
        let mut request = cli.online(endpoint, genesis);
        request["asset_id"] = json!(ASSET);
        let info = cli.call("recovery.info", request);
        assert!(info["context"]["parent_hash"] == hex::encode(node.best_meta().hash));
        let rows = info["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0]["asset_id"] == ASSET
                && rows[0]["epoch"] == 1
                && rows[0]["delegate_action_commitment"] == json!(current_delegate)
        );
    });
    e.check("policy_admin_rotation_authenticated_wallet_sync_and_current_role_readback");
    let post_admin = assets(&node);
    let current_row = post_admin.recovery().unwrap().row(ASSET).unwrap();
    assert!(
        current_row.controls.epoch == 1
            && current_row.controls.delegate_action_commitment == current_delegate
    );
    assert!(post_admin
        .recovery()
        .unwrap()
        .admin_action_is_consumed(&admin_semantic_id));
    reject(
        &node,
        &mut e,
        "rotated_current_authority_readback_and_old_delegate_carrier_rejection",
        &delegate.body,
        asset_recovery_native::RECOVERY_SPEND_ACTION_ID,
        &[],
    );
    // The consumed semantic ID and current role are checked independently; an
    // exact replay can fail at an earlier current-context or duplicate gate.
    assert_eq!(
        assets(&node)
            .registry()
            .row(ASSET)
            .unwrap()
            .counters
            .total_debt,
        10
    );
    assert_eq!(snapshot(&node).proofs, 3 * wire::PROOF_UNITS as u64 + 1);
    let final_state = snapshot(&node);
    e.retain("final-asset-snapshot.scale", &final_state.asset);
    drop(post_admin);
    drop(node);
    let reopened = NativeNode::reopen_after_sled_release_for_test(selected_config).unwrap();
    assert!(snapshot(&reopened) == final_state);
    let peer_dir = e.native_chain_dir("provider-fresh");
    let peer = NativeNode::open(config(peer_dir.path(), &selected_network, &f)).unwrap();
    sync(&reopened, &peer, 1);
    assert_same(&reopened, &peer);
    for replayed in [&reopened, &peer] {
        let state = assets(replayed);
        let recovery_state = state.recovery().unwrap();
        let row = recovery_state.row(ASSET).unwrap();
        assert!(
            row.controls.epoch == 1 && row.controls.delegate_action_commitment == current_delegate
        );
        assert!(recovery_state.admin_action_is_consumed(&admin_semantic_id));
        assert_outputs(replayed, &delegate);
    }
    e.check("cooperative_four_carriers_cold_restart_and_fresh_peer_reverify");
    let components = e
        .proofs
        .iter()
        .map(|p| {
            let parts = p["proof_bytes"].as_array().unwrap();
            assert_eq!(
                parts.len(),
                if p["route"] == "admin" {
                    1
                } else {
                    wire::PROOF_UNITS
                }
            );
            assert!(parts
                .iter()
                .all(|n| n.as_u64().unwrap() <= wire::MAX_PROOF_BYTES as u64));
            parts.len()
        })
        .sum::<usize>();
    assert_eq!(components, 16);
    assert_eq!(e.proofs.len(), 4);
    let mut report = json!({"schema":"hegemon.actual-native-recovery-cooperative-provider.v2","status":"PASSED",
        "scope":"finite Development issuance, trusted archive cooperation, privileged recovery and policy administration through genuine CLI and NativeNode HTTP18/19",
        "actual_roles":{"issuance_cli":true,"cooperative_holder_cli":true,"privileged_delegate_cli":true,"policy_admin_cli":true},
        "binary_sha256":cli.binary_sha256,"binary_expected_sha256_verified":true,
        "source_pins":{
            "node/src/native/asset_recovery_lifecycle_tests.rs":hash(include_bytes!("asset_recovery_lifecycle_tests.rs")),
            "walletd/src/main.rs":hash(include_bytes!("../../../walletd/src/main.rs")),
            "walletd/src/recovery.rs":hash(include_bytes!("../../../walletd/src/recovery.rs")),
            "walletd/src/recovery_archive_process.rs":hash(include_bytes!("../../../walletd/src/recovery_archive_process.rs")),
            "wallet/src/asset_recovery_build_v1.rs":hash(include_bytes!("../../../wallet/src/asset_recovery_build_v1.rs")),
            "wallet/src/asset_recovery_store.rs":hash(include_bytes!("../../../wallet/src/asset_recovery_store.rs"))},
        "calls":cli.calls,"new_walletd_process_per_call":true,"private_files_mode0600":true,
        "holder_prepare_has_inline_archive_or_action_secret":false,
        "provider":"explicit pinned local worker; private key file configured by disposable custodian",
        "provider_automatic_network_service":false,"provider_proof_receipts_trusted_without_verification":false,
        "key_file_removed_before_export_and_submit":true,"secret_requests_or_raw_process_streams_retained":false,
        "same_user_hostile_process_isolation_claim":false,"proof_components_generated":components,
        "carrier_candidates_generated":e.proofs.len(),"canonical_proof_units":final_state.proofs});
    let report_details = json!({"checks":e.checks,"proof_candidates":e.proofs,"final_height":final_state.height,
        "final_hash":hex::encode(final_state.hash),"final_note_leaf_count":final_state.note.leaf_count(),
        "final_asset_snapshot_sha256":hash(&final_state.asset),"final_asset_snapshot_bytes":final_state.asset.len(),
        "native_fees_paid":3,"total_debt":10,
        "holder_transfer_output_values":[4,6],"privileged_delegate_target_value":4,
        "privileged_delegate_output_values":[4,0],"privileged_delegate_has_input_holder_spend_secret":false,
        "privileged_delegate_archive_key_supplied":true,"admin_semantic_action_id":hex::encode(admin_semantic_id),
        "admin_epoch_after":1,"admin_current_delegate_commitment":current_delegate,
        "admin_semantic_id_consumed":true,"admin_replay_rejected":true,
        "chain_id":hex::encode(selected_network.chain_id()),
        "manifest_digest":selected_network.manifest_digest().map(hex::encode),
        "wire_version":wire::VERSION,"spend_relation":hex::encode(spend::relation_digest()),
        "capsule_relation":hex::encode(capsule::relation_digest()),
        "admin_relation":hex::encode(admin::relation_digest()),"elapsed_seconds":started.elapsed().as_secs_f64(),
        "fixture_secrets_are_public_disposable_constants":true,"production_authority":false,
        "unconditional_security_closure":false});
    report
        .as_object_mut()
        .unwrap()
        .extend(report_details.as_object().unwrap().clone());
    e.retain("receipt.json", &serde_json::to_vec_pretty(&report).unwrap());
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}

// Privileged recovery is a different process invocation from ordinary holder
// cooperation. Root43 pays the native fee; the target recipient is root42, whose
// ordinary spend key is never supplied to this delegate invocation.
#[cfg(unix)]
fn build_privileged_delegate_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    holder: &Built,
    a: &wallet::DerivedKeys,
    b: &wallet::DerivedKeys,
    credentials: &Credentials,
) -> Built {
    let started = Instant::now();
    let before = snapshot(node);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let address_a = a.poseidon2_v8_address(0).unwrap();
    let address_b = b.poseidon2_v8_address(0).unwrap();
    assert!(authority(a) != authority(b));
    assert!(holder.outputs[0].as_note().recipient_key == recipient(b));
    assert_eq!(holder.outputs[0].as_note().value, 4);
    // This address supplies only the public delegate credential recipient. Its
    // authority comes from the current delegate action key, not pk_auth here.
    let mut delegate_address = address_a.shielded_address();
    delegate_address.pk_recipient =
        transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_to_bytes(
            DELEGATE_RECIPIENT1,
        );
    let delegate_address = delegate_address.encode().unwrap();
    let input_file = cli
        .work
        .path()
        .join("cooperative-holder-after-inclusion.action");
    assert!(std::fs::read(&input_file).unwrap() == holder.body);
    let input_context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
        chain_id: holder.public.base.chain_id,
        asset_id: ASSET,
        stable_policy_id: POLICY,
        output_commitment: holder.public.base.commitments[0],
    };
    let input_nf = holder.outputs[0]
        .common_nullifier(&input_context, holder.next_position)
        .unwrap();
    let reply = issuer_cli_http(node, |endpoint| {
        let mut inspect = cli.online(endpoint, genesis);
        inspect.as_object_mut().unwrap().extend(
            json!({
                "asset_id":ASSET,"position":holder.next_position,"input_action_file":input_file,
                "input_output":0,"archive_key":hex::encode(ARCHIVE)
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let inspected = cli.call("recovery.inspectInput", inspect);
        assert!(
            inspected["value"] == 4
                && inspected["commitment"] == json!(holder.public.base.commitments[0])
        );
        assert!(inspected["nullifier"] == json!(input_nf) && inspected["epoch"] == 0);
        assert!(
            inspected["parent_hash"] == hex::encode(before.hash) && inspected["frozen"] == false
        );
        assert!(inspected["action_authority_granted"] == false);
        let credential = |i: usize| {
            json!({"index":credentials.paths[i].index,
            "expires_at":credentials.paths[i].expires_at,"siblings":credentials.paths[i].siblings})
        };
        let mut request = cli.online(endpoint, genesis);
        request.as_object_mut().unwrap().extend(json!({
            "confirm":true,"expected_parent_hash":hex::encode(before.hash),"expected_epoch":0,
            "asset_id":ASSET,"operation":"transfer","route":"delegate","amount":4,"fee":1,
            "input_position":holder.next_position,"input_action_file":input_file,"input_output":0,
            "fee_position":holder.next_position+2,"recipient":address_a.shielded_address().encode().unwrap(),
            "change_recipient":address_b.shielded_address().encode().unwrap(),"native_change_index":0,
            "archive_key":hex::encode(ARCHIVE),"delegate_secret":DELEGATE1,
            "delegate_credential_recipient":delegate_address,
            "credentials":[credential(2),credential(0),credential(1)]
        }).as_object().unwrap().clone());
        for key in [
            "issuer_secret",
            "admin_secret",
            "spend_key",
            "spend_secret",
            "archive_provider",
        ] {
            assert!(request.get(key).is_none());
        }
        cli.call("recovery.prepare", request)
    });
    assert!(snapshot(node) == before);
    assert!(reply["status"] == "candidate" && reply["proof_units"] == wire::PROOF_UNITS);
    let reservation = reply["reservation_id"].as_str().unwrap().to_owned();
    assert!(hex::decode(&reservation).is_ok_and(|id| id.len() == 32));
    cli.reservation = Some(reservation.clone());
    let body = cli.export("privileged-delegate-initial.action");
    cooperative_cli_journal(cli, &reservation, "Candidate", None, None, 3);
    let decoded = wire::decode_spend_ref(&body).unwrap();
    let public = decoded.public.clone();
    assert!(reply["public_statement"] == json!(public.words().unwrap()));
    assert!(
        public.base.parent_height == before.height
            && public.base.reference_parent_hash == before.hash
    );
    assert!(
        public.base.operation == TRANSFER && public.base.magnitude == 0 && public.base.fee == 1
    );
    assert!(public.row == holder.public.row && public.row.controls.epoch == 0);
    assert!(
        public.row.controls.delegate_action_commitment
            == recovery::delegate_action_commitment(DELEGATE1).unwrap()
    );
    assert!(public.base.nullifiers[0] == input_nf);
    assert!(
        public.base.nullifiers[1]
            == private_spend::real_nullifier(
                a.spend.poseidon2_v8_words().unwrap(),
                holder.next_position + 2,
                holder.fee_note
            )
            .unwrap()
    );
    assert!(decoded.proof.len() <= wire::MAX_PROOF_BYTES);
    for c in &decoded.capsules {
        assert!(capsule::bundle_components(c.proof)
            .unwrap()
            .iter()
            .all(|p| p.len() <= wire::MAX_PROOF_BYTES));
    }
    let outputs = std::array::from_fn(|i| {
        let (recipient_keys, address) = if i == 0 {
            (a, &address_a)
        } else {
            (b, &address_b)
        };
        let delivered = build::decrypt_holder_output(
            &public,
            i as u8,
            decoded.ciphertexts[i],
            address.secret_key(),
            recipient(recipient_keys),
            authority(recipient_keys),
        )
        .unwrap();
        let archived =
            build::decrypt_archive_material(&decoded.capsules[i].public, &ARCHIVE).unwrap();
        let context = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
            chain_id: public.base.chain_id,
            asset_id: ASSET,
            stable_policy_id: POLICY,
            output_commitment: public.base.commitments[i],
        };
        assert!(
            delivered.material_words(&context).unwrap()[..]
                == archived.material_words(&context).unwrap()[..]
        );
        delivered
    });
    assert!(outputs[0].as_note().value == 4 && outputs[1].as_note().value == 0);
    let fee_note = build::decrypt_native_fee_change(
        &public,
        decoded.ciphertexts[2],
        address_a.secret_key(),
        0,
        recipient(a),
        authority(a),
    )
    .unwrap()
    .as_note();
    assert!(fee_note.value == holder.fee_note.value - 1 && fee_note.asset_id == 0);
    e.proof(
        "privileged-delegate",
        "spend",
        &body,
        started.elapsed().as_secs_f64(),
    );
    e.check(
        "privileged_delegate_inspects_canonical_receiver_note_and_proves_without_input_holder_key",
    );
    Built {
        body,
        public,
        outputs,
        fee_note,
        next_position: canonical_notes(node).len() as u32,
    }
}

fn submit_privileged_delegate_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
    delegate: &Built,
) -> NativeBlockMeta {
    let before = snapshot(node);
    let expected = pending(
        node,
        &delegate.body,
        asset_recovery_native::RECOVERY_SPEND_ACTION_ID,
    );
    let exact = expected.encode();
    let expected_hash = expected.tx_hash.into_bytes();
    let reservation = cli.reservation.clone().unwrap();
    assert!(cli.export("privileged-delegate-before-submit.action") == delegate.body);
    cooperative_cli_journal(cli, &reservation, "Candidate", None, None, 3);
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let reply = issuer_cli_http(node, |endpoint| {
        let mut request = cli.online(endpoint, genesis);
        request["reservation_id"] = json!(reservation);
        request["confirm"] = json!(true);
        cli.call("recovery.submit", request)
    });
    assert!(reply["status"] == "submitted" && reply["action_id"] == hex::encode(expected_hash));
    cooperative_cli_journal(cli, &reservation, "Submitted", Some(expected_hash), None, 3);
    assert!(cli.export("privileged-delegate-after-submit.action") == delegate.body);
    assert!(snapshot(node) == before);
    let block = mine(node);
    assert!(block.action_bytes.contains(&exact));
    assert!(decode_block_actions(&block)
        .unwrap()
        .iter()
        .any(|a| a.action_id == 18 && a.public_args == delegate.body));
    e.checks.push(
        json!({"name":"privileged_delegate_exact_HTTP18_forced_transfer",
        "passed":true,"actual_HTTP":true,"action_id":18,"action_hash":hex::encode(expected_hash),
        "carrier_bytes":delegate.body.len(),"carrier_sha256":hash(&delegate.body),
        "input_holder_spend_secret_supplied":false,"local_archive_key_supplied":true,
        "current_delegate_key_supplied":true,"independent_native_fee_owner":true,
        "target_value":4,"output_values":[4,0],"exact_export_before_and_after_submit":true,
        "production_router_limits_and_dispatch":true,"actual_canonical_inclusion":true}),
    );
    block
}

#[cfg(unix)]
fn rotate_policy_admin_via_cli(
    node: &Arc<NativeNode>,
    e: &mut Evidence,
    cli: &mut IssuerCliFixture,
) -> (Vec<u8>, [u8; 32]) {
    use std::os::unix::fs::PermissionsExt;
    let started = Instant::now();
    let before = snapshot(node);
    let before_row = *assets(node).recovery().unwrap().row(ASSET).unwrap();
    assert_eq!(before_row.controls.epoch, 0);
    let new_delegate = recovery::delegate_action_commitment(DELEGATE2).unwrap();
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let action_file = cli.work.path().join("privileged-admin-rotation.action");
    assert!(!action_file.exists());
    let prepared =
        issuer_cli_http(node, |endpoint| {
            let mut request = cli.online(endpoint, genesis);
            request.as_object_mut().unwrap().extend(json!({
            "confirm":true,"expected_parent_hash":hex::encode(before.hash),"expected_epoch":0,
            "asset_id":ASSET,"operation":"rotate","admin_secret":ADMIN,"expires_at":EXPIRES,
            "action_intent":[1201,1202,1203,1204,1205,1206,1207],"action_file":action_file,
            "new_delegate_commitment":new_delegate
        }).as_object().unwrap().clone());
            for key in [
                "archive_key",
                "archive_provider",
                "issuer_secret",
                "delegate_secret",
                "spend_key",
                "spend_secret",
            ] {
                assert!(request.get(key).is_none());
            }
            cli.call("recovery.adminPrepare", request)
        });
    assert!(snapshot(node) == before);
    assert_eq!(
        std::fs::metadata(&action_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(std::fs::metadata(&action_file).unwrap().len() <= wire::MAX_ADMIN_ACTION_BYTES as u64);
    let body = std::fs::read(&action_file).unwrap();
    let decoded = wire::decode_admin_ref(&body).unwrap();
    let semantic_id = decoded.public.action_id().unwrap();
    assert!(prepared["status"] == "candidate" && prepared["action_bytes"] == body.len());
    assert!(prepared["administrator_action_id"] == hex::encode(semantic_id));
    assert_eq!(
        hex::decode(prepared["administrator_action_id"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert!(prepared["public_statement"] == json!(decoded.public.words().unwrap().to_vec()));
    assert!(decoded.public.before == before_row && decoded.public.freeze.is_none());
    assert!(
        decoded.public.context.parent_hash == before.hash
            && decoded.public.context.parent_height == before.height
    );
    assert!(
        decoded.public.after.epoch == 1
            && decoded.public.after.delegate_action_commitment == new_delegate
    );
    let mut expected_controls = before_row.controls;
    expected_controls.epoch = 1;
    expected_controls.delegate_action_commitment = new_delegate;
    assert!(decoded.public.after == expected_controls);
    assert!(decoded.proof.len() <= wire::MAX_PROOF_BYTES);
    let expected = pending(node, &body, asset_recovery_native::RECOVERY_ADMIN_ACTION_ID);
    let exact = expected.encode();
    let action_hash = expected.tx_hash.into_bytes();
    let submitted = issuer_cli_http(node, |endpoint| {
        let mut request = cli.online(endpoint, genesis);
        request["action_file"] = json!(action_file);
        request["expected_action_id"] = json!(hex::encode(semantic_id));
        request["confirm"] = json!(true);
        cli.call("recovery.adminSubmit", request)
    });
    assert!(
        submitted["status"] == "submitted" && submitted["action_id"] == hex::encode(action_hash)
    );
    assert!(submitted["administrator_action_id"] == hex::encode(semantic_id));
    assert!(std::fs::read(&action_file).unwrap() == body && snapshot(node) == before);
    let block = mine(node);
    assert!(block.action_bytes.contains(&exact));
    assert!(decode_block_actions(&block)
        .unwrap()
        .iter()
        .any(|a| a.action_id == 19 && a.public_args == body));
    let current = assets(node);
    let recovery_state = current.recovery().unwrap();
    let after_row = recovery_state.row(ASSET).unwrap();
    assert!(
        after_row.descriptor == before_row.descriptor && after_row.controls == expected_controls
    );
    assert!(recovery_state.admin_action_is_consumed(&semantic_id));
    e.proof(
        "admin-rotation",
        "admin",
        &body,
        started.elapsed().as_secs_f64(),
    );
    e.checks.push(
        json!({"name":"policy_admin_actual_CLI_prepare0600_semanticID_HTTP19_rotation",
        "passed":true,"actual_HTTP":true,"action_id":19,"action_hash":hex::encode(action_hash),
        "semantic_action_id":hex::encode(semantic_id),"semantic_id_bytes":32,
        "carrier_bytes":body.len(),"carrier_sha256":hash(&body),"action_file_mode0600":true,
        "exact_file_preserved_after_submit":true,"epoch_before":0,"epoch_after":1,
        "current_delegate_commitment":new_delegate,"semantic_id_consumed":true,
        "production_router_limits_and_dispatch":true,"actual_canonical_inclusion":true}),
    );
    reject(
        node,
        e,
        "admin_CLI_exact_carrier_replay_rejected_with_consumed_semantic_ID",
        &body,
        asset_recovery_native::RECOVERY_ADMIN_ACTION_ID,
        &[],
    );
    assert!(assets(node)
        .recovery()
        .unwrap()
        .admin_action_is_consumed(&semantic_id));
    (body, semantic_id)
}
