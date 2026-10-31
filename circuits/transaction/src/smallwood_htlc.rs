//! Complete constrained native-note HTLC successor, development qualification only.
//!
//! Lock consumes one ordinary V8 note and creates a conditional V8 note.
//! Claim/refund consume that same note and shared nullifier, proving private
//! credential ownership, SHA-256 (claim), authenticated-height maturity (refund),
//! Merkle inclusion, exact recipient and value conservation in one relation.
//! Production authorization, transport routing and security evidence are separate.
#![forbid(unsafe_code)]

#[path = "smallwood_htlc/circuit.rs"]
pub(crate) mod circuit;
#[path = "smallwood_htlc/sha256.rs"]
mod sha256;
use crate::{
    smallwood_engine::{
        prove_statement_with_transcript_backend_profile_and_domain,
        verify_statement_with_transcript_backend_profile_and_domain, SmallwoodDecsEvaluationDomain,
        SmallwoodTranscriptBackend, STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
    },
    smallwood_poseidon2_v8_hash_schedule::{
        SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN as NULLIFIER_DOMAIN,
        SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN as SINGLE_KEY_DOMAIN,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8Digest as NativeDigest, SmallwoodPoseidon2V8NoteOpening as Note,
    },
    TransactionCircuitError,
};
use circuit::{boolean, equal, input, nonzero, range, select, Scope, Word};
pub use circuit::{HtlcAdapter, HtlcGeometry};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS};
use sha2::{Digest as _, Sha512};
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG},
    poseidon2_width16::{
        poseidon2_width16_compress14, poseidon2_width16_compress14_ring, poseidon2_width16_sponge,
        poseidon2_width16_sponge_ring, Felt,
    },
};

pub const RELATION_ID: &str = "hegemon.native.htlc.HGV9HT01.v1";
pub const HTLC_POLICY_VERSION: u32 = 1;
pub const HTLC_STATEMENT_VERSION: u32 = 1;
pub const MAX_HEIGHT: u64 = (1u64 << 48) - 1;
pub const MAX_VALUE: u64 = (1u64 << 56) - 1;
pub const POLICY_DOMAIN: u64 = 0x4848_544c_504f_0001;
pub const OWNER_DOMAIN: u64 = 0x4848_544c_4f57_0001;
pub const DEVELOPMENT_PROOF_DOMAIN: &[u8] =
    b"hegemon.native.htlc.HGV9HT01.strict-smz1.development.v1";
/// Bound for the new development envelope, distinct from unchanged RP05 caps.
/// Size is a denial-of-service bound only and confers no production authority.
pub const MAX_DEVELOPMENT_PROOF_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HtlcAction {
    Lock,
    Claim,
    Refund,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecretRelease {
    HiddenOnHegemon,
    PublicOnHegemon,
}

/// Policy opening stays private. The hashlock uses ordinary single SHA-256 of
/// an exact 32-byte preimage, matching the supported Bitcoin regtest contract.
/// Both authorization commitments retain all seven native field words.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HtlcPolicy {
    pub version: u32,
    pub network_id: [u8; 32],
    pub hashlock: [u8; 32],
    pub claim_authority: NativeDigest,
    pub refund_authority: NativeDigest,
    pub claim_recipient: [u64; 4],
    pub refund_recipient: [u64; 4],
    pub timeout_height: u64,
    pub secret_release: SecretRelease,
}

/// Verifier-owned public surface. Native admission must reconstruct the network,
/// exact parent hash/height and note root from its authenticated chain state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtlcStatement {
    pub version: u32,
    pub action: HtlcAction,
    pub network_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
    pub merkle_root: NativeDigest,
    pub nullifier: NativeDigest,
    pub output_commitment: NativeDigest,
    #[serde(with = "bytes48")]
    pub ciphertext_commitment: [u8; 48],
    pub fee: u64,
    pub revealed_secret: Option<[u8; 32]>,
}

/// No Debug or serde implementation: credentials, locked opening, policy and
/// preimage never enter retained public receipts or transport encodings.
pub struct HtlcWitness {
    pub policy: HtlcPolicy,
    pub policy_nullifier_key: [u64; 5],
    pub input_note: Note,
    pub input_position: u32,
    pub input_siblings: [NativeDigest; 32],
    pub spend_key: [u64; 5],
    pub secret: [u8; 32],
    pub output_note: Note,
}

fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}
fn bytes_words(bytes: [u8; 32]) -> [u64; 8] {
    core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()) as u64)
}
fn policy_words(policy: HtlcPolicy) -> Vec<u64> {
    let mut words = vec![policy.version as u64];
    words.extend(bytes_words(policy.network_id));
    words.extend(bytes_words(policy.hashlock));
    words.extend(policy.claim_authority);
    words.extend(policy.refund_authority);
    words.extend(policy.claim_recipient);
    words.extend(policy.refund_recipient);
    words.push(policy.timeout_height);
    words.push(match policy.secret_release {
        SecretRelease::HiddenOnHegemon => 0,
        SecretRelease::PublicOnHegemon => 1,
    });
    words
}
fn note_words(note: Note) -> [u64; 18] {
    [
        note.value,
        note.asset_id,
        note.recipient_key[0],
        note.recipient_key[1],
        note.recipient_key[2],
        note.recipient_key[3],
        note.rho[0],
        note.rho[1],
        note.rho[2],
        note.rho[3],
        note.randomness[0],
        note.randomness[1],
        note.randomness[2],
        note.randomness[3],
        note.authorization_key[0],
        note.authorization_key[1],
        note.authorization_key[2],
        note.authorization_key[3],
    ]
}
fn owner_words(note: &[Word; 18]) -> [Word; 7] {
    [
        note[14], note[15], note[16], note[17], note[10], note[11], note[12],
    ]
}
fn canonical(words: &[u64]) -> Result<(), TransactionCircuitError> {
    if words.iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
        Err(error("HTLC noncanonical field word"))
    } else {
        Ok(())
    }
}
fn host_sponge(domain: u64, words: &[u64]) -> Result<NativeDigest, TransactionCircuitError> {
    canonical(words)?;
    poseidon2_width16_sponge(
        domain,
        &words
            .iter()
            .copied()
            .map(Felt::from_u64)
            .collect::<Vec<_>>(),
    )
    .map(|digest| digest.map(|v| v.as_canonical_u64()))
    .map_err(|_| error("HTLC hash input"))
}

pub fn htlc_policy_digest(policy: HtlcPolicy) -> Result<NativeDigest, TransactionCircuitError> {
    if policy.version != HTLC_POLICY_VERSION
        || policy.timeout_height == 0
        || policy.timeout_height > MAX_HEIGHT
    {
        return Err(error("HTLC policy version/timeout"));
    }
    host_sponge(POLICY_DOMAIN, &policy_words(policy))
}
pub fn htlc_locked_owner(
    policy: HtlcPolicy,
    nullifier_key: [u64; 5],
) -> Result<NativeDigest, TransactionCircuitError> {
    canonical(&nullifier_key)?;
    if nullifier_key[0] == 0 {
        return Err(error("HTLC zero shared nullifier key"));
    }
    let mut key = [0; 7];
    key[..5].copy_from_slice(&nullifier_key);
    Ok(poseidon2_width16_compress14(
        OWNER_DOMAIN,
        &key.map(Felt::from_u64),
        &htlc_policy_digest(policy)?.map(Felt::from_u64),
    )
    .map(|v| v.as_canonical_u64()))
}
/// Install the conditional owner into the same complete seven-word owner slots
/// used by RP05. It is domain separated from SingleKey and threshold owners.
pub fn bind_locked_note(
    mut note: Note,
    policy: HtlcPolicy,
    nullifier_key: [u64; 5],
) -> Result<Note, TransactionCircuitError> {
    let owner = htlc_locked_owner(policy, nullifier_key)?;
    note.authorization_key.copy_from_slice(&owner[..4]);
    note.randomness[..3].copy_from_slice(&owner[4..]);
    Ok(note)
}
/// Exactly the native nullifier PRF/key/position/rho grammar; independent of
/// action, branch authority, output, fee, parent context and secret release.
pub fn htlc_nullifier(
    nullifier_key: [u64; 5],
    position: u32,
    note: Note,
) -> Result<NativeDigest, TransactionCircuitError> {
    let mut words = nullifier_key.to_vec();
    words.extend([0, 0, position as u64]);
    words.extend(note.rho);
    host_sponge(NULLIFIER_DOMAIN, &words)
}

impl HtlcStatement {
    pub fn validate_structure(&self) -> Result<(), TransactionCircuitError> {
        if self.version != HTLC_STATEMENT_VERSION
            || self.network_id == [0; 32]
            || self.parent_height > MAX_HEIGHT
            || self.fee > MAX_VALUE
        {
            return Err(error("HTLC public version/network/height/fee"));
        }
        canonical(&self.merkle_root)?;
        canonical(&self.nullifier)?;
        canonical(&self.output_commitment)?;
        if self.merkle_root == [0; 7]
            || self.nullifier == [0; 7]
            || self.output_commitment == [0; 7]
            || self.ciphertext_commitment == [0; 48]
        {
            return Err(error("HTLC zero public commitment"));
        }
        if self.action != HtlcAction::Claim && self.revealed_secret.is_some() {
            return Err(error("HTLC secret release outside claim"));
        }
        Ok(())
    }
    /// Explicit fixed-width canonical binding; no JSON/bincode ambiguity.
    /// The complete 256-bit network and parent hashes are preserved bytewise.
    pub fn binding_bytes(&self) -> Result<Vec<u8>, TransactionCircuitError> {
        self.validate_structure()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DEVELOPMENT_PROOF_DOMAIN);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&relation_digest());
        bytes.push(match self.action {
            HtlcAction::Lock => 0,
            HtlcAction::Claim => 1,
            HtlcAction::Refund => 2,
        });
        bytes.push(u8::from(self.revealed_secret.is_some()));
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.parent_height.to_le_bytes());
        for word in self
            .merkle_root
            .into_iter()
            .chain(self.nullifier)
            .chain(self.output_commitment)
        {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&self.ciphertext_commitment);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.revealed_secret.unwrap_or([0; 32]));
        bytes.resize(bytes.len().div_ceil(8) * 8, 0);
        Ok(bytes)
    }
    /// Cheap native context check precedes expensive proof admission and is
    /// repeated at ordered block application. A supplied height is insufficient.
    pub fn validate_context(
        &self,
        network_id: [u8; 32],
        parent_hash: [u8; 32],
        parent_height: u64,
        merkle_root: NativeDigest,
    ) -> Result<(), TransactionCircuitError> {
        self.validate_structure()?;
        if self.network_id != network_id
            || self.parent_hash != parent_hash
            || self.parent_height != parent_height
            || self.merkle_root != merkle_root
        {
            return Err(error("HTLC authenticated parent/network mismatch"));
        }
        Ok(())
    }
}

/// Exact source-owned successor identity, not an RP05 compatibility alias.
pub fn relation_digest() -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(RELATION_ID.as_bytes());
    hash.update(include_bytes!("smallwood_htlc.rs"));
    hash.update(include_bytes!("smallwood_htlc/circuit.rs"));
    hash.update(include_bytes!("smallwood_htlc/sha256.rs"));
    hash.update(include_bytes!(
        "../src/smallwood_poseidon2_v8_hash_schedule.rs"
    ));
    hash.update(include_bytes!(
        "../../transaction-core/src/poseidon2_width16.rs"
    ));
    hash.update(include_bytes!("../../transaction-core/src/constants.rs"));
    hash.update(include_bytes!("../../hegemon-field/src/lib.rs"));
    hash.update(include_bytes!("smallwood_engine.rs"));
    hash.update(include_bytes!("smallwood_semantics.rs"));
    hash.update(include_bytes!(
        "../../../protocol/versioning/src/launch_candidate_identity.rs"
    ));
    hash.finalize().into()
}

impl HtlcAdapter {
    /// The verifier supplies only the public statement. No hidden opening,
    /// preimage-derived target, signature-valid flag or host callback is used.
    pub fn from_statement(statement: &HtlcStatement) -> Result<Self, TransactionCircuitError> {
        statement.validate_structure()?;
        let scope = Scope::start();
        let policy: [Word; 41] = core::array::from_fn(|_| input());
        let shared_key: [Word; 5] = core::array::from_fn(|_| input());
        let input_note: [Word; 18] = core::array::from_fn(|_| input());
        let position = input();
        let siblings: [[Word; 7]; 32] = core::array::from_fn(|_| core::array::from_fn(|_| input()));
        let spend_key: [Word; 5] = core::array::from_fn(|_| input());
        let secret_bits: [Word; 256] = core::array::from_fn(|_| input());
        let output_note: [Word; 18] = core::array::from_fn(|_| input());
        equal(policy[0], Word::from_u64(HTLC_POLICY_VERSION as u64));
        for (wire, value) in policy[1..9].iter().zip(bytes_words(statement.network_id)) {
            equal(*wire, Word::from_u64(value));
        }
        for value in &policy[9..17] {
            range(*value, 32);
        }
        range(policy[39], 48);
        nonzero(policy[39]);
        boolean(policy[40]);
        nonzero(shared_key[0]);
        nonzero(spend_key[0]);
        range(input_note[0], 56);
        range(output_note[0], 56);
        nonzero(input_note[0]);
        nonzero(output_note[0]);
        equal(input_note[1], Word::ZERO);
        equal(output_note[1], Word::ZERO);
        equal(
            input_note[0],
            output_note[0] + Word::from_u64(statement.fee),
        );
        let position_bits = range(position, 32);
        let policy_digest = poseidon2_width16_sponge_ring(POLICY_DOMAIN, &policy)
            .map_err(|_| error("HTLC policy compiler hash"))?;
        let shared_key7: [Word; 7] =
            core::array::from_fn(|i| shared_key.get(i).copied().unwrap_or(Word::ZERO));
        let locked_owner =
            poseidon2_width16_compress14_ring(OWNER_DOMAIN, &shared_key7, &policy_digest);
        let spend_key7: [Word; 7] =
            core::array::from_fn(|i| spend_key.get(i).copied().unwrap_or(Word::ZERO));
        let signer = poseidon2_width16_sponge_ring(SINGLE_KEY_DOMAIN, &spend_key7)
            .map_err(|_| error("HTLC signer compiler hash"))?;
        let (expected_input_owner, expected_output_owner, required_recipient, nullifier_key) =
            match statement.action {
                HtlcAction::Lock => {
                    range(
                        policy[39] - Word::from_u64(statement.parent_height) - Word::ONE,
                        48,
                    );
                    (signer, locked_owner, None, spend_key7)
                }
                HtlcAction::Claim => {
                    for bit in secret_bits {
                        boolean(bit);
                    }
                    if let Some(secret) = statement.revealed_secret {
                        equal(policy[40], Word::ONE);
                        for (i, bit) in secret_bits.iter().enumerate() {
                            equal(
                                *bit,
                                Word::from_u64(((secret[i / 8] >> (i % 8)) & 1) as u64),
                            );
                        }
                    } else {
                        equal(policy[40], Word::ZERO);
                    }
                    let digest = sha(secret_bits);
                    for (word, expected) in digest.into_iter().zip(policy[9..17].iter().copied()) {
                        equal(word, expected);
                    }
                    for (a, b) in signer.into_iter().zip(policy[17..24].iter().copied()) {
                        equal(a, b);
                    }
                    (locked_owner, signer, Some(&policy[31..35]), shared_key7)
                }
                HtlcAction::Refund => {
                    range(Word::from_u64(statement.parent_height) - policy[39], 48);
                    for (a, b) in signer.into_iter().zip(policy[24..31].iter().copied()) {
                        equal(a, b);
                    }
                    (locked_owner, signer, Some(&policy[35..39]), shared_key7)
                }
            };
        if statement.action != HtlcAction::Claim {
            for bit in secret_bits {
                equal(bit, Word::ZERO);
            }
        }
        for (a, b) in owner_words(&input_note)
            .into_iter()
            .zip(expected_input_owner)
        {
            equal(a, b);
        }
        for (a, b) in owner_words(&output_note)
            .into_iter()
            .zip(expected_output_owner)
        {
            equal(a, b);
        }
        if let Some(recipient) = required_recipient {
            for (a, b) in output_note[2..6].iter().zip(recipient) {
                equal(*a, *b);
            }
        }
        let input_commitment = poseidon2_width16_sponge_ring(NOTE_DOMAIN_TAG, &input_note)
            .map_err(|_| error("HTLC note compiler hash"))?;
        let mut root = input_commitment;
        for (level, sibling) in siblings.iter().enumerate() {
            let direction = position_bits[level];
            let left = core::array::from_fn(|i| select(direction, root[i], sibling[i]));
            let right = core::array::from_fn(|i| select(direction, sibling[i], root[i]));
            root = poseidon2_width16_compress14_ring(MERKLE_DOMAIN_TAG, &left, &right);
        }
        for (a, b) in root.into_iter().zip(statement.merkle_root) {
            equal(a, Word::from_u64(b));
        }
        let mut nullifier_preimage = nullifier_key.to_vec();
        nullifier_preimage.push(position);
        nullifier_preimage.extend(input_note[6..10].iter().copied());
        let nullifier = poseidon2_width16_sponge_ring(NULLIFIER_DOMAIN, &nullifier_preimage)
            .map_err(|_| error("HTLC nullifier compiler hash"))?;
        for (a, b) in nullifier.into_iter().zip(statement.nullifier) {
            equal(a, Word::from_u64(b));
        }
        let output_commitment = poseidon2_width16_sponge_ring(NOTE_DOMAIN_TAG, &output_note)
            .map_err(|_| error("HTLC output compiler hash"))?;
        for (a, b) in output_commitment
            .into_iter()
            .zip(statement.output_commitment)
        {
            equal(a, Word::from_u64(b));
        }
        Ok(Self::from_graph(scope.finish()))
    }
}

pub(crate) fn sha(input: [Word; 256]) -> [Word; 8] {
    use sha256::BooleanGate as Gate;
    let topology = sha256::Sha256Hashlock::new();
    let mut wires = input.to_vec();
    for gate in topology.gates() {
        let out = match *gate {
            Gate::Constant(v) => Word::from_u64(v as u64),
            Gate::Not(a) => Word::ONE - wires[a],
            Gate::Xor(a, b) => xor(wires[a], wires[b]),
            Gate::And(a, b) => wires[a] * wires[b],
            Gate::Parity(a, b, c) => xor(xor(wires[a], wires[b]), wires[c]),
            Gate::Majority(a, b, c) => {
                wires[a] * wires[b] + wires[a] * wires[c] + wires[b] * wires[c]
                    - Word::TWO * wires[a] * wires[b] * wires[c]
            }
        };
        wires.push(out);
    }
    core::array::from_fn(|word| {
        let mut value = Word::ZERO;
        for bit in 0..32 {
            value += wires[topology.output_wires()[word * 32 + bit]] * Word::from_u64(1u64 << bit);
        }
        value
    })
}
fn xor(a: Word, b: Word) -> Word {
    a + b - Word::TWO * a * b
}

impl HtlcWitness {
    fn inputs(&self) -> Vec<u64> {
        let mut inputs = policy_words(self.policy);
        inputs.extend(self.policy_nullifier_key);
        inputs.extend(note_words(self.input_note));
        inputs.push(self.input_position as u64);
        for sibling in self.input_siblings {
            inputs.extend(sibling);
        }
        inputs.extend(self.spend_key);
        inputs.extend((0..256).map(|i| ((self.secret[i / 8] >> (i % 8)) & 1) as u64));
        inputs.extend(note_words(self.output_note));
        inputs
    }
}
/// Lower and audit the whole relation before invoking the development prover.
pub fn compile(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
) -> Result<(HtlcAdapter, Vec<u64>), TransactionCircuitError> {
    let adapter = HtlcAdapter::from_statement(statement)?;
    let packed = adapter.evaluate(&witness.inputs())?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
/// Retained development proof; not admitted by ordinary RP05/native routes.
pub fn prove_development(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(statement, witness)?;
    let proof = prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &statement.binding_bytes()?,
        STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Level5,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    if proof.len() > MAX_DEVELOPMENT_PROOF_BYTES {
        return Err(error(
            "HTLC development proof exceeds successor envelope bound",
        ));
    }
    Ok(proof)
}
pub fn verify_development(
    statement: &HtlcStatement,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    if proof.len() > MAX_DEVELOPMENT_PROOF_BYTES {
        return Err(error(
            "HTLC development proof exceeds successor envelope bound",
        ));
    }
    let adapter = HtlcAdapter::from_statement(statement)?;
    verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &statement.binding_bytes()?,
        proof,
        STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Level5,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

mod bytes48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 48], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|_| {
            serde::de::Error::custom("expected exactly 48 ciphertext commitment bytes")
        })
    }
}

/// Qualification-only unchecked engine seam. Ordinary builds omit it and no
/// consensus route is allowed to select this development proof identity.
#[cfg(feature = "htlc-dev-artifacts")]
pub fn prove_development_unchecked_for_qualification(
    statement: &HtlcStatement,
    packed: &[u64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let adapter = HtlcAdapter::from_statement(statement)?;
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        packed,
        &statement.binding_bytes()?,
        STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Level5,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

#[cfg(feature = "htlc-dev-artifacts")]
pub fn unchecked_packed_witness_for_qualification(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
) -> Result<Vec<u64>, TransactionCircuitError> {
    HtlcAdapter::from_statement(statement)?.evaluate(&witness.inputs())
}

/// Dedicated q58 candidate preamble is injected byte-for-byte in every strict
/// Merkle leaf. Historical SMZA's 1104-byte prefix remains unchanged.
pub const CANDIDATE_PREAMBLE_MAGIC: [u8; 8] = *b"HGV9HB01";
pub const CANDIDATE_PREAMBLE_BYTES: usize = 576;
pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZC";
pub const MAX_CANDIDATE_PROOF_BYTES: usize =
    crate::smallwood_engine::SMALLWOOD_NATIVE_HTLC_SMZC_MAX_INNER_PROOF_BYTES;
impl HtlcStatement {
    pub fn candidate_binding_bytes(
        &self,
    ) -> Result<[u8; CANDIDATE_PREAMBLE_BYTES], TransactionCircuitError> {
        use protocol_versioning::launch_candidate::{
            HTLC_ACTION_ID, HTLC_DOMAIN_SET, HTLC_PROFILE_ID, HTLC_VERSION_BINDING,
            LAUNCH_SHIELDED_FAMILY_ID,
        };
        self.validate_structure()?;
        let adapter = HtlcAdapter::from_statement(self)?;
        let mut bytes = Vec::with_capacity(CANDIDATE_PREAMBLE_BYTES);
        bytes.extend_from_slice(&CANDIDATE_PREAMBLE_MAGIC);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&HTLC_VERSION_BINDING.circuit.to_le_bytes());
        bytes.extend_from_slice(&HTLC_VERSION_BINDING.crypto.to_le_bytes());
        bytes.extend_from_slice(&LAUNCH_SHIELDED_FAMILY_ID.to_le_bytes());
        bytes.extend_from_slice(&HTLC_ACTION_ID.to_le_bytes());
        bytes.push(protocol_versioning::TxProofBackend::SmallwoodCandidate as u8);
        bytes.push(HTLC_PROFILE_ID);
        bytes.extend_from_slice(&HTLC_DOMAIN_SET.to_le_bytes());
        bytes.push(match self.action {
            HtlcAction::Lock => 0,
            HtlcAction::Claim => 1,
            HtlcAction::Refund => 2,
        });
        bytes.push(0);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.parent_height.to_le_bytes());
        for word in self
            .nullifier
            .into_iter()
            .chain(self.merkle_root)
            .chain(self.output_commitment)
        {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&self.ciphertext_commitment);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.push(u8::from(self.revealed_secret.is_some()));
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&self.revealed_secret.unwrap_or([0; 32]));
        bytes.extend_from_slice(&relation_digest());
        bytes.extend_from_slice(&(adapter.geometry().rows as u64).to_le_bytes());
        bytes.extend_from_slice(&64u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&CANDIDATE_PROOF_MAGIC);
        if bytes.len() > CANDIDATE_PREAMBLE_BYTES {
            return Err(error("HTLC candidate preamble overflow"));
        }
        bytes.resize(CANDIDATE_PREAMBLE_BYTES, 0);
        Ok(bytes.try_into().unwrap())
    }
}
/// Read-only source-owned byte hint; a projection is not retained proof evidence.
pub fn candidate_proof_size_hint(
    statement: &HtlcStatement,
) -> Result<usize, TransactionCircuitError> {
    let mut adapter = HtlcAdapter::from_statement(statement)?;
    adapter.use_smzc();
    crate::smallwood_engine::projected_native_htlc_smzc_inner_proof_bytes(&adapter)
}
/// Cryptographic candidate operation only; release capability remains separately
/// required by every native admission/authoring route.
pub fn prove_candidate(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (mut adapter, packed) = compile(statement, witness)?;
    adapter.use_smzc();
    let binding = statement.candidate_binding_bytes()?;
    let profile = crate::smallwood_engine::NATIVE_HTLC_SMZC_SMALLWOOD_NO_GRINDING_PROFILE;
    let backend = SmallwoodTranscriptBackend::Sha512NativeHtlcSmzc;
    let domain = SmallwoodDecsEvaluationDomain::Radix2DisjointCoset;
    if crate::smallwood_engine::smallwood_low_ram_enabled() {
        let prefix = crate::smallwood_engine::start_smallwood_prove(
            &adapter,
            &packed,
            &binding,
            profile,
            backend,
            domain,
        )?;
        drop(adapter);
        crate::smallwood_engine::log_low_ram_stage("circuit_released");
        let committed = crate::smallwood_engine::commit_smallwood_prove(prefix)?;
        let mut adapter = HtlcAdapter::from_statement(statement)?;
        adapter.use_smzc();
        crate::smallwood_engine::log_low_ram_stage("circuit_rebuilt");
        let proof = crate::smallwood_engine::finish_smallwood_prove(&adapter, committed)?;
        return crate::smallwood_engine::encode_smallwood_proof_bytes_v1(&proof);
    }
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &binding,
        profile,
        backend,
        domain,
    )
}
pub fn verify_candidate(
    statement: &HtlcStatement,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    if proof.len() > MAX_CANDIDATE_PROOF_BYTES
        || proof.get(..4) != Some(CANDIDATE_PROOF_MAGIC.as_slice())
    {
        return Err(error("HTLC requires exact SMZC wire and independent cap"));
    }
    let mut adapter = HtlcAdapter::from_statement(statement)?;
    adapter.use_smzc();
    verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &statement.candidate_binding_bytes()?,
        proof,
        crate::smallwood_engine::NATIVE_HTLC_SMZC_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512NativeHtlcSmzc,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}
#[cfg(feature = "htlc-dev-artifacts")]
pub fn prove_candidate_unchecked_for_qualification(
    statement: &HtlcStatement,
    packed: &[u64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut adapter = HtlcAdapter::from_statement(statement)?;
    adapter.use_smzc();
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        packed,
        &statement.candidate_binding_bytes()?,
        crate::smallwood_engine::NATIVE_HTLC_SMZC_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512NativeHtlcSmzc,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

