//! Wallet construction and recovery for the public V8 coinbase opening.

use codec::{Decode, Encode};
use rand::{CryptoRng, RngCore};

use protocol_shielded_pool::{
    poseidon2_v8_coinbase::{
        MintPoseidon2V8CoinbaseArgs, Poseidon2V8CoinbaseNoteData, Poseidon2V8CoinbaseNoteOpening,
    },
    types::EncryptedNote,
};
use transaction_circuit::constants::{FIELD_MODULUS_U64, MAX_IN_CIRCUIT_VALUE, NATIVE_ASSET_ID};
use transaction_circuit::{
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_commitment, poseidon2_v8_two_note_frontier,
        poseidon2_v8_words_from_canonical_bytes, poseidon2_v8_words_to_bytes,
    },
    smallwood_poseidon2_v8_hash_schedule::{
        build_smallwood_poseidon2_v8_hash_schedule, SmallwoodPoseidon2V8HashDigestRef,
        SmallwoodPoseidon2V8HashFinalBinding, SmallwoodPoseidon2V8HashScheduleMaterial,
    },
    smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8Digest,
        SmallwoodPoseidon2V8InlineCiphertexts, SmallwoodPoseidon2V8InputWitness,
        SmallwoodPoseidon2V8NoteOpening, SmallwoodPoseidon2V8OutputWitness,
        SmallwoodPoseidon2V8PublicStatement, SmallwoodPoseidon2V8Witness,
        SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES, SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH,
    },
};

use crate::{
    address::{ShieldedAddress, POSEIDON2_V8_ADDRESS_VERSION},
    error::WalletError,
    keys::{AddressKeyMaterial, SpendKey},
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
};

fn random_field_words<R: RngCore + ?Sized>(rng: &mut R) -> [u64; 4] {
    loop {
        let words = core::array::from_fn(|_| loop {
            let word = rng.next_u64();
            if word < FIELD_MODULUS_U64 {
                break word;
            }
        });
        if words != [0; 4] {
            return words;
        }
    }
}

fn address_authorization_extension(address: &ShieldedAddress) -> Result<[u64; 3], WalletError> {
    if address.version != POSEIDON2_V8_ADDRESS_VERSION {
        return Err(WalletError::AddressEncoding(
            "V8 authorization extension requires an address-v5 recipient".into(),
        ));
    }
    authorization_extension_words(address.pk_auth_extension)
}

fn authorization_extension_words(bytes: [u8; 24]) -> Result<[u64; 3], WalletError> {
    let mut words = [0u64; 3];
    for (limb, chunk) in bytes.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().expect("eight-byte auth-extension limb"));
        if word >= FIELD_MODULUS_U64 {
            return Err(WalletError::AddressEncoding(
                "non-canonical V8 authorization extension".into(),
            ));
        }
        words[limb] = word;
    }
    Ok(words)
}

fn random_single_key_note_randomness<R: RngCore + ?Sized>(
    address: &ShieldedAddress,
    rng: &mut R,
) -> Result<[u64; 4], WalletError> {
    let extension = address_authorization_extension(address)?;
    let fresh = random_field_words(rng);
    Ok([extension[0], extension[1], extension[2], fresh[0]])
}

pub fn protocol_opening_to_relation(
    opening: Poseidon2V8CoinbaseNoteOpening,
) -> SmallwoodPoseidon2V8NoteOpening {
    SmallwoodPoseidon2V8NoteOpening {
        value: opening.value,
        asset_id: opening.asset_id,
        recipient_key: opening.recipient_key,
        authorization_key: opening.authorization_key,
        rho: opening.rho,
        randomness: opening.randomness,
    }
}

pub fn build_poseidon2_v8_coinbase_args<R: RngCore + ?Sized>(
    address: &ShieldedAddress,
    amount: u64,
    rng: &mut R,
) -> Result<MintPoseidon2V8CoinbaseArgs, WalletError> {
    let recipient_key = poseidon2_v8_words_from_canonical_bytes(address.pk_recipient)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 recipient key".into()))?;
    let authorization_key = poseidon2_v8_words_from_canonical_bytes(address.pk_auth)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 authorization key".into()))?;
    let opening = Poseidon2V8CoinbaseNoteOpening {
        value: amount,
        asset_id: NATIVE_ASSET_ID,
        recipient_key,
        authorization_key,
        rho: random_field_words(rng),
        randomness: random_single_key_note_randomness(address, rng)?,
    };
    build_poseidon2_v8_coinbase_args_from_opening(address, opening, rng)
}

/// Encrypt one exact source opening to its owning V8 wallet address.
///
/// This is used by retained lifecycle vectors and recovery tools. Consensus
/// still recomputes the commitment and subsidy amount from the public action;
/// this helper cannot authorize issuance.
pub fn build_poseidon2_v8_coinbase_args_from_opening<R: RngCore + ?Sized>(
    address: &ShieldedAddress,
    opening: Poseidon2V8CoinbaseNoteOpening,
    rng: &mut R,
) -> Result<MintPoseidon2V8CoinbaseArgs, WalletError> {
    if address.version != POSEIDON2_V8_ADDRESS_VERSION
        || address.crypto_suite != protocol_versioning::CRYPTO_SUITE_ETA
    {
        return Err(WalletError::AddressEncoding(
            "V8 coinbase requires an address-v5/Eta recipient".into(),
        ));
    }
    if opening.value == 0 || u128::from(opening.value) > MAX_IN_CIRCUIT_VALUE {
        return Err(WalletError::Serialization(
            "V8 coinbase amount is zero or exceeds the relation value range".into(),
        ));
    }
    if opening.asset_id != NATIVE_ASSET_ID {
        return Err(WalletError::Serialization(
            "V8 coinbase opening must use the native asset".into(),
        ));
    }
    let recipient_key = poseidon2_v8_words_from_canonical_bytes(address.pk_recipient)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 recipient key".into()))?;
    let authorization_key = poseidon2_v8_words_from_canonical_bytes(address.pk_auth)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 authorization key".into()))?;
    let authorization_extension = address_authorization_extension(address)?;
    if recipient_key == [0; 4]
        || authorization_key == [0; 4]
        || opening.rho == [0; 4]
        || opening.randomness == [0; 4]
    {
        return Err(WalletError::AddressEncoding(
            "zero V8 recipient, authorization key, rho, or randomness".into(),
        ));
    }
    if opening.recipient_key != recipient_key
        || opening.authorization_key != authorization_key
        || opening.randomness[..3] != authorization_extension
    {
        return Err(WalletError::AddressEncoding(
            "V8 coinbase opening is not owned by the supplied address".into(),
        ));
    }
    // Round-trip decoding is the public-field canonicality check; it performs
    // no modular normalization.
    for (label, words) in [("rho", opening.rho), ("randomness", opening.randomness)] {
        poseidon2_v8_words_from_canonical_bytes(poseidon2_v8_words_to_bytes(words)).map_err(
            |_| WalletError::Serialization(format!("non-canonical V8 coinbase {label}")),
        )?;
    }
    let plaintext = NotePlaintext {
        value: opening.value,
        asset_id: NATIVE_ASSET_ID,
        rho: poseidon2_v8_words_to_bytes(opening.rho),
        r: poseidon2_v8_words_to_bytes(opening.randomness),
        memo: MemoPlaintext::default(),
    };
    let ciphertext = NoteCiphertext::encrypt(address, &plaintext, rng)?;
    let chain_bytes = ciphertext.to_chain_bytes()?;
    let encrypted_note = EncryptedNote::decode(&mut &chain_bytes[..]).map_err(|error| {
        WalletError::Serialization(format!("decode V8 coinbase encrypted note: {error}"))
    })?;
    let commitment =
        poseidon2_v8_note_commitment(protocol_opening_to_relation(opening)).map_err(|error| {
            WalletError::Serialization(format!("hash V8 coinbase opening: {error:?}"))
        })?;
    Ok(MintPoseidon2V8CoinbaseArgs {
        miner_note: Poseidon2V8CoinbaseNoteData {
            opening,
            commitment,
            encrypted_note,
        },
    })
}

pub fn decrypt_poseidon2_v8_coinbase_opening(
    args: &MintPoseidon2V8CoinbaseArgs,
    material: &AddressKeyMaterial,
) -> Result<SmallwoodPoseidon2V8NoteOpening, WalletError> {
    let chain = args.miner_note.encrypted_note.encode();
    let ciphertext = NoteCiphertext::from_chain_bytes(&chain)?;
    let plaintext = ciphertext.decrypt(material)?;
    let recovered = SmallwoodPoseidon2V8NoteOpening {
        value: plaintext.value,
        asset_id: plaintext.asset_id,
        recipient_key: poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
            .map_err(|_| WalletError::NoteMismatch("non-canonical V8 recipient key"))?,
        authorization_key: poseidon2_v8_words_from_canonical_bytes(material.pk_auth)
            .map_err(|_| WalletError::NoteMismatch("non-canonical V8 authorization key"))?,
        rho: poseidon2_v8_words_from_canonical_bytes(plaintext.rho)
            .map_err(|_| WalletError::NoteMismatch("non-canonical V8 rho"))?,
        randomness: poseidon2_v8_words_from_canonical_bytes(plaintext.r)
            .map_err(|_| WalletError::NoteMismatch("non-canonical V8 randomness"))?,
    };
    if recovered.randomness[..3] != material.poseidon2_v8_authorization_extension_words()? {
        return Err(WalletError::NoteMismatch(
            "V8 coinbase authorization extension mismatch",
        ));
    }
    if recovered != protocol_opening_to_relation(args.miner_note.opening) {
        return Err(WalletError::NoteMismatch(
            "V8 coinbase ciphertext/opening mismatch",
        ));
    }
    let commitment = poseidon2_v8_note_commitment(recovered)
        .map_err(|_| WalletError::NoteMismatch("invalid V8 coinbase opening"))?;
    if commitment != args.miner_note.commitment {
        return Err(WalletError::NoteMismatch("V8 coinbase commitment mismatch"));
    }
    Ok(recovered)
}

/// Exact wallet scan boundary for an action-11 public argument payload.
pub fn decode_and_decrypt_poseidon2_v8_coinbase_action(
    public_args: &[u8],
    material: &AddressKeyMaterial,
) -> Result<SmallwoodPoseidon2V8NoteOpening, WalletError> {
    if public_args.len()
        != protocol_shielded_pool::poseidon2_v8_coinbase::POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES
    {
        return Err(WalletError::Serialization(
            "wrong Poseidon2 V8 coinbase action length".into(),
        ));
    }
    let mut cursor = public_args;
    let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor).map_err(|error| {
        WalletError::Serialization(format!("decode V8 coinbase action: {error}"))
    })?;
    if !cursor.is_empty() || args.encode().as_slice() != public_args {
        return Err(WalletError::Serialization(
            "noncanonical Poseidon2 V8 coinbase action encoding".into(),
        ));
    }
    decrypt_poseidon2_v8_coinbase_opening(&args, material)
}

/// Turn two wallet-recovered V8 notes and their canonical paths into the exact
/// SingleKey relation input witnesses.
///
/// The spend words are derived internally from the wallet `SpendKey`; callers
/// cannot inject a different relation key. Path and position data remain
/// public chain-state inputs and are checked for field/range canonicality.
pub fn build_poseidon2_v8_owned_spend_inputs(
    material: &AddressKeyMaterial,
    spend_key: &SpendKey,
    notes: [SmallwoodPoseidon2V8NoteOpening; 2],
    positions: [u64; 2],
    paths: [[SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]; 2],
) -> Result<[SmallwoodPoseidon2V8InputWitness; 2], WalletError> {
    if material.version() != POSEIDON2_V8_ADDRESS_VERSION
        || material.crypto_suite() != protocol_versioning::CRYPTO_SUITE_ETA
    {
        return Err(WalletError::AddressEncoding(
            "V8 spend inputs require address-v5/Eta key material".into(),
        ));
    }
    if positions[0] == positions[1]
        || positions
            .into_iter()
            .any(|position| position >= (1u64 << SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH))
    {
        return Err(WalletError::Serialization(
            "V8 spend input positions are duplicate or outside the depth-32 tree".into(),
        ));
    }
    if paths
        .iter()
        .flatten()
        .flatten()
        .any(|word| *word >= FIELD_MODULUS_U64)
    {
        return Err(WalletError::Serialization(
            "V8 spend path contains a non-canonical field word".into(),
        ));
    }
    let recipient_key = poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 recipient key".into()))?;
    let authorization_key = poseidon2_v8_words_from_canonical_bytes(material.pk_auth)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 authorization key".into()))?;
    let spend_words = spend_key.poseidon2_v8_words()?;
    let derived_authorization = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(spend_words)
        .map_err(|error| WalletError::Serialization(format!("V8 spend authorization derivation failed: {error:?}")))?;
    let authorization_extension = authorization_extension_words(material.pk_auth_extension)?;
    if derived_authorization[..4] != authorization_key
        || derived_authorization[4..] != authorization_extension
    {
        return Err(WalletError::NoteMismatch(
            "V8 spend key does not authorize the supplied wallet address",
        ));
    }
    for note in notes {
        if note.value == 0
            || note.asset_id != NATIVE_ASSET_ID
            || note.recipient_key != recipient_key
            || note.authorization_key != authorization_key
            || note.randomness[..3] != authorization_extension
        {
            return Err(WalletError::NoteMismatch(
                "V8 spend note is not a positive native note owned by this wallet",
            ));
        }
        poseidon2_v8_note_commitment(note)
            .map_err(|_| WalletError::NoteMismatch("invalid V8 spend note opening"))?;
    }
    Ok(core::array::from_fn(|input| {
        SmallwoodPoseidon2V8InputWitness {
            active: true,
            spend_key: spend_words,
            note: notes[input],
            position: positions[input],
            siblings: paths[input],
            balance_slot_selectors: [true, false, false, false],
        }
    }))
}

fn build_poseidon2_v8_owned_spend_input(
    material: &AddressKeyMaterial,
    spend_key: &SpendKey,
    note: SmallwoodPoseidon2V8NoteOpening,
    position: u64,
    path: [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH],
) -> Result<SmallwoodPoseidon2V8InputWitness, WalletError> {
    if material.version() != POSEIDON2_V8_ADDRESS_VERSION
        || material.crypto_suite() != protocol_versioning::CRYPTO_SUITE_ETA
        || position >= (1u64 << SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH)
        || path.iter().flatten().any(|word| *word >= FIELD_MODULUS_U64)
    {
        return Err(WalletError::Serialization(
            "invalid wallet-owned V8 spend input context".into(),
        ));
    }
    let recipient_key = poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 recipient key".into()))?;
    let authorization_key = poseidon2_v8_words_from_canonical_bytes(material.pk_auth)
        .map_err(|_| WalletError::AddressEncoding("non-canonical V8 authorization key".into()))?;
    let spend_words = spend_key.poseidon2_v8_words()?;
    let derived_authorization = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(spend_words)
        .map_err(|error| WalletError::Serialization(format!("V8 spend authorization derivation failed: {error:?}")))?;
    let authorization_extension = authorization_extension_words(material.pk_auth_extension)?;
    if note.value == 0
        || note.asset_id != NATIVE_ASSET_ID
        || note.recipient_key != recipient_key
        || note.authorization_key != authorization_key
        || note.randomness[..3] != authorization_extension
        || derived_authorization[..4] != authorization_key
        || derived_authorization[4..] != authorization_extension
    {
        return Err(WalletError::NoteMismatch(
            "V8 spend note is not owned by the selected wallet address",
        ));
    }
    poseidon2_v8_note_commitment(note)
        .map_err(|_| WalletError::NoteMismatch("invalid V8 spend note opening"))?;
    Ok(SmallwoodPoseidon2V8InputWitness {
        active: true,
        spend_key: spend_words,
        note,
        position,
        siblings: path,
        balance_slot_selectors: [true, false, false, false],
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8SpendMaterial {
    pub statement: SmallwoodPoseidon2V8PublicStatement,
    pub witness: SmallwoodPoseidon2V8Witness,
    pub inline_ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
}

/// Select semantic digests, independent of schedule call-number changes.
fn bind_spend_hash_outputs(
    statement: &mut SmallwoodPoseidon2V8PublicStatement,
    hashes: &SmallwoodPoseidon2V8HashScheduleMaterial,
) -> Result<(), WalletError> {
    let digest = |wanted| {
        hashes
            .calls
            .iter()
            .find(|call| call.final_binding == SmallwoodPoseidon2V8HashFinalBinding::Digest(wanted))
            .map(|call| call.final_digest())
            .ok_or(WalletError::InvalidState("V8 spend digest binding missing"))
    };
    for input in 0..2 {
        statement.nullifiers[input] =
            digest(SmallwoodPoseidon2V8HashDigestRef::InputNullifier { input })?;
    }
    for output in 0..2 {
        statement.commitments[output] =
            digest(SmallwoodPoseidon2V8HashDigestRef::OutputNote { output })?;
    }
    Ok(())
}

/// Build a complete two-input/two-output SingleKey V8 self-spend from exact
/// action-11 carrier bytes owned by one wallet root.
///
/// The wallet derives both note openings, the depth-32 paths, root, spend key,
/// outputs, ciphertexts, nullifiers, and commitments internally. No private
/// witness component is accepted from the caller.
pub fn build_poseidon2_v8_two_coinbase_self_spend<R: RngCore + CryptoRng + ?Sized>(
    root: &crate::keys::RootSecret,
    source_address_index: u32,
    coinbase_action_args: [&[u8]; 2],
    parent_height: u64,
    output_address_indices: [u32; 2],
    rng: &mut R,
) -> Result<Poseidon2V8SpendMaterial, WalletError> {
    if parent_height >= FIELD_MODULUS_U64 {
        return Err(WalletError::Serialization(
            "V8 spend parent height is not a canonical field word".into(),
        ));
    }
    let keys = root.derive();
    let source_material = keys.poseidon2_v8_address(source_address_index)?;
    let mut notes = [SmallwoodPoseidon2V8NoteOpening::ZERO; 2];
    let mut commitments = [[0u64; 7]; 2];
    for input in 0..2 {
        let bytes = coinbase_action_args[input];
        if bytes.len()
            != protocol_shielded_pool::poseidon2_v8_coinbase::POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES
        {
            return Err(WalletError::Serialization(
                "wrong V8 coinbase action length".into(),
            ));
        }
        let mut cursor = bytes;
        let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor).map_err(|error| {
            WalletError::Serialization(format!("decode V8 coinbase action: {error}"))
        })?;
        if !cursor.is_empty() || args.encode().as_slice() != bytes {
            return Err(WalletError::Serialization(
                "noncanonical V8 coinbase action encoding".into(),
            ));
        }
        notes[input] = decrypt_poseidon2_v8_coinbase_opening(&args, &source_material)?;
        commitments[input] = args.miner_note.commitment;
        if poseidon2_v8_note_commitment(notes[input])
            .map_err(|_| WalletError::NoteMismatch("invalid V8 coinbase opening"))?
            != commitments[input]
        {
            return Err(WalletError::NoteMismatch(
                "V8 coinbase commitment differs from recovered opening",
            ));
        }
    }
    if commitments[0] == commitments[1] {
        return Err(WalletError::NoteMismatch(
            "duplicate V8 coinbase commitments cannot form a two-note spend",
        ));
    }
    let frontier = poseidon2_v8_two_note_frontier(commitments)
        .map_err(|_| WalletError::NoteMismatch("invalid V8 coinbase commitment frontier"))?;
    let inputs = build_poseidon2_v8_owned_spend_inputs(
        &source_material,
        &keys.spend,
        notes,
        [0, 1],
        frontier.paths,
    )?;

    let mut output_witnesses = [SmallwoodPoseidon2V8OutputWitness::ZERO; 2];
    let mut raw_ciphertexts = [[0u8; SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES]; 2];
    for output in 0..2 {
        let material = keys.poseidon2_v8_address(output_address_indices[output])?;
        let address = material.shielded_address();
        let recipient_key =
            poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).map_err(|_| {
                WalletError::AddressEncoding("non-canonical V8 output recipient".into())
            })?;
        let authorization_key =
            poseidon2_v8_words_from_canonical_bytes(address.pk_auth).map_err(|_| {
                WalletError::AddressEncoding("non-canonical V8 output authorization".into())
            })?;
        let authorization_extension = address_authorization_extension(&address)?;
        if authorization_key != notes[0].authorization_key
            || notes[0].randomness[..3] != authorization_extension
        {
            return Err(WalletError::AddressEncoding(
                "V8 SingleKey output address is not authorized by the source spend key".into(),
            ));
        }
        let rho = random_field_words(rng);
        let randomness = random_single_key_note_randomness(&address, rng)?;
        let note = SmallwoodPoseidon2V8NoteOpening {
            value: notes[output].value,
            asset_id: NATIVE_ASSET_ID,
            recipient_key,
            authorization_key,
            rho,
            randomness,
        };
        let plaintext = NotePlaintext {
            value: note.value,
            asset_id: note.asset_id,
            rho: poseidon2_v8_words_to_bytes(rho),
            r: poseidon2_v8_words_to_bytes(randomness),
            memo: MemoPlaintext::default(),
        };
        let ciphertext = NoteCiphertext::encrypt(&address, &plaintext, rng)?;
        let raw = ciphertext.to_da_bytes()?;
        raw_ciphertexts[output] = raw.try_into().map_err(|bytes: Vec<u8>| {
            WalletError::Serialization(format!(
                "V8 output ciphertext has {} bytes instead of {}",
                bytes.len(),
                SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
            ))
        })?;
        output_witnesses[output] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note,
            balance_slot_selectors: [true, false, false, false],
        };
    }

    let inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: [Some(raw_ciphertexts[0]), Some(raw_ciphertexts[1])],
    };
    let mut statement = SmallwoodPoseidon2V8PublicStatement {
        input_flags: [true, true],
        output_flags: [true, true],
        merkle_root: frontier.root,
        ..SmallwoodPoseidon2V8PublicStatement::default()
    };
    statement.stablecoin.parent_height = parent_height;
    for output in 0..2 {
        statement.ciphertext_commitments[output] =
            smallwood_poseidon2_v8_ciphertext_commitment(&raw_ciphertexts[output]);
    }
    let witness = SmallwoodPoseidon2V8Witness {
        inputs,
        outputs: output_witnesses,
        ..SmallwoodPoseidon2V8Witness::default()
    };
    let hashes =
        build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).map_err(|error| {
            WalletError::Serialization(format!("V8 spend hash schedule: {error:?}"))
        })?;
    bind_spend_hash_outputs(&mut statement, &hashes)?;
    statement.validate_public_structure().map_err(|error| {
        WalletError::Serialization(format!("V8 self-spend statement: {error:?}"))
    })?;
    witness
        .validate_against_statement(&statement)
        .map_err(|error| WalletError::Serialization(format!("V8 self-spend witness: {error:?}")))?;
    inline_ciphertexts
        .validate_against_statement(&statement)
        .map_err(|error| {
            WalletError::Serialization(format!("V8 self-spend ciphertexts: {error:?}"))
        })?;
    Ok(Poseidon2V8SpendMaterial {
        statement,
        witness,
        inline_ciphertexts,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8WalletSpend {
    pub tip: crate::poseidon2_v8_sync::Poseidon2V8CanonicalTip,
    pub material: Poseidon2V8SpendMaterial,
}

/// Build the production V8 self-spend exclusively from durable wallet notes
/// and the mirror's single canonical tip anchor.
///
/// The caller chooses only destination diversifiers. Input openings,
/// positions, paths, nullifiers, and the anchor are selected from the
/// encrypted wallet store.
pub fn build_poseidon2_v8_wallet_self_spend<R: RngCore + CryptoRng + ?Sized>(
    store: &crate::store::WalletStore,
    output_address_indices: [u32; 2],
    rng: &mut R,
) -> Result<Poseidon2V8WalletSpend, WalletError> {
    let context = store.poseidon2_v8_spend_context()?;
    if context.tip.height >= FIELD_MODULUS_U64
        || context.notes[0].position == context.notes[1].position
        || context
            .notes
            .iter()
            .any(|note| note.spent || note.anchor != context.tip.anchor || note.opening.value == 0)
    {
        return Err(WalletError::InvalidState(
            "wallet V8 spend context is not canonical and spendable",
        ));
    }
    let root = crate::keys::RootSecret::from_bytes(store.signing_seed()?);
    let keys = root.derive();
    let build_input = |input: usize| {
        let note = &context.notes[input];
        let material = keys.poseidon2_v8_address(note.diversifier_index)?;
        build_poseidon2_v8_owned_spend_input(
            &material,
            &keys.spend,
            note.opening,
            note.position,
            note.path,
        )
    };
    let inputs = [build_input(0)?, build_input(1)?];

    let mut output_witnesses = [SmallwoodPoseidon2V8OutputWitness::ZERO; 2];
    let mut raw_ciphertexts = [[0u8; SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES]; 2];
    for output in 0..2 {
        let material = keys.poseidon2_v8_address(output_address_indices[output])?;
        let address = material.shielded_address();
        let recipient_key =
            poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).map_err(|_| {
                WalletError::AddressEncoding("non-canonical V8 output recipient".into())
            })?;
        let authorization_key =
            poseidon2_v8_words_from_canonical_bytes(address.pk_auth).map_err(|_| {
                WalletError::AddressEncoding("non-canonical V8 output authorization".into())
            })?;
        let authorization_extension = address_authorization_extension(&address)?;
        if authorization_key != context.notes[0].opening.authorization_key
            || context.notes[0].opening.randomness[..3] != authorization_extension
        {
            return Err(WalletError::AddressEncoding(
                "V8 SingleKey output address is not authorized by the source spend key".into(),
            ));
        }
        let rho = random_field_words(rng);
        let randomness = random_single_key_note_randomness(&address, rng)?;
        let note = SmallwoodPoseidon2V8NoteOpening {
            value: context.notes[output].opening.value,
            asset_id: NATIVE_ASSET_ID,
            recipient_key,
            authorization_key,
            rho,
            randomness,
        };
        let plaintext = NotePlaintext {
            value: note.value,
            asset_id: note.asset_id,
            rho: poseidon2_v8_words_to_bytes(rho),
            r: poseidon2_v8_words_to_bytes(randomness),
            memo: MemoPlaintext::default(),
        };
        let ciphertext = NoteCiphertext::encrypt(&address, &plaintext, rng)?;
        let raw = ciphertext.to_da_bytes()?;
        raw_ciphertexts[output] = raw.try_into().map_err(|bytes: Vec<u8>| {
            WalletError::Serialization(format!(
                "V8 output ciphertext has {} bytes instead of {}",
                bytes.len(),
                SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES
            ))
        })?;
        output_witnesses[output] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note,
            balance_slot_selectors: [true, false, false, false],
        };
    }

    let inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: [Some(raw_ciphertexts[0]), Some(raw_ciphertexts[1])],
    };
    let mut statement = SmallwoodPoseidon2V8PublicStatement {
        input_flags: [true, true],
        output_flags: [true, true],
        merkle_root: context.tip.anchor,
        ..SmallwoodPoseidon2V8PublicStatement::default()
    };
    let stablecoin_root = context
        .tip
        .stablecoin_root
        .ok_or(WalletError::InvalidState(
            "V8 wallet mirror has no release-bound stablecoin root",
        ))?;
    let stablecoin_root = stablecoin_root.map(hegemon_field::Goldilocks::new);
    statement.stablecoin.parent_height = context.tip.height;
    statement.stablecoin.before_root = stablecoin_root;
    statement.stablecoin.after_root = stablecoin_root;
    for output in 0..2 {
        statement.ciphertext_commitments[output] =
            smallwood_poseidon2_v8_ciphertext_commitment(&raw_ciphertexts[output]);
    }
    let witness = SmallwoodPoseidon2V8Witness {
        inputs,
        outputs: output_witnesses,
        ..SmallwoodPoseidon2V8Witness::default()
    };
    let hashes =
        build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).map_err(|error| {
            WalletError::Serialization(format!("V8 spend hash schedule: {error:?}"))
        })?;
    bind_spend_hash_outputs(&mut statement, &hashes)?;
    statement.validate_public_structure().map_err(|error| {
        WalletError::Serialization(format!("V8 wallet self-spend statement: {error:?}"))
    })?;
    witness
        .validate_against_statement(&statement)
        .map_err(|error| {
            WalletError::Serialization(format!("V8 wallet self-spend witness: {error:?}"))
        })?;
    inline_ciphertexts
        .validate_against_statement(&statement)
        .map_err(|error| {
            WalletError::Serialization(format!("V8 wallet self-spend ciphertexts: {error:?}"))
        })?;
    Ok(Poseidon2V8WalletSpend {
        tip: context.tip,
        material: Poseidon2V8SpendMaterial {
            statement,
            witness,
            inline_ciphertexts,
        },
    })
}

#[cfg(test)]
mod tests {
    use codec::Encode;
    use rand::{rngs::StdRng, SeedableRng};
    use sha2::{Digest, Sha512};

    use protocol_shielded_pool::poseidon2_v8_coinbase::{
        POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES, POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
    };
    use protocol_shielded_pool::poseidon2_v8_retained_vectors::{
        RETAINED_V8_COINBASE_0_SCALE, RETAINED_V8_COINBASE_1_SCALE,
        RETAINED_V8_INLINE_CIPHERTEXT_SHA512, RETAINED_V8_OUTPUT_0_RAW, RETAINED_V8_OUTPUT_1_RAW,
        RETAINED_V8_OUTPUT_OPENINGS, RETAINED_V8_STATEMENT_SHA512, RETAINED_V8_WITNESS_SHA512,
    };

    use crate::keys::RootSecret;
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_key;

    use super::*;

    fn sha512_hex(bytes: &[u8]) -> String {
        hex::encode(Sha512::digest(bytes))
    }

    #[test]
    fn v8_coinbase_encrypts_decrypts_and_binds_exact_opening() {
        let keys = RootSecret::from_bytes([0x31; 32]).derive();
        let material = keys.poseidon2_v8_address(7).unwrap();
        let address = material.shielded_address();
        let mut rng = StdRng::seed_from_u64(8);
        let args = build_poseidon2_v8_coinbase_args(&address, 499_429_223, &mut rng).unwrap();
        assert_eq!(args.encode().len(), POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES);
        assert_eq!(
            args.miner_note.encrypted_note.ciphertext.len()
                + args.miner_note.encrypted_note.kem_ciphertext.len(),
            POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES
        );
        let opening = decrypt_poseidon2_v8_coinbase_opening(&args, &material).unwrap();
        assert_eq!(opening.value, 499_429_223);
        assert_eq!(opening.asset_id, NATIVE_ASSET_ID);
        assert_eq!(
            opening.authorization_key,
            poseidon2_v8_single_key_authorization_key(keys.spend.poseidon2_v8_words().unwrap())
                .unwrap()
        );
        assert_eq!(
            decode_and_decrypt_poseidon2_v8_coinbase_action(&args.encode(), &material).unwrap(),
            opening
        );
    }

    #[test]
    fn commitment_or_ciphertext_opening_mutation_rejects() {
        let keys = RootSecret::from_bytes([0x32; 32]).derive();
        let material = keys.poseidon2_v8_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        let mut args =
            build_poseidon2_v8_coinbase_args(&material.shielded_address(), 499_429_223, &mut rng)
                .unwrap();
        args.miner_note.opening.rho[0] ^= 1;
        assert!(decrypt_poseidon2_v8_coinbase_opening(&args, &material).is_err());
    }

    #[test]
    fn retained_root_secret_vector_is_wallet_owned() {
        let keys = RootSecret::from_bytes([0x51; 32]).derive();
        let material = keys.poseidon2_v8_address(9).unwrap();
        let address = material.shielded_address();
        let spend = keys.spend.poseidon2_v8_words().unwrap();
        let recipient = poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).unwrap();
        let authorization = poseidon2_v8_words_from_canonical_bytes(address.pk_auth).unwrap();
        assert_eq!(
            authorization,
            [
                4_878_808_653_854_375_386,
                15_704_130_448_495_857_300,
                420_778_687_531_148_047,
                1_878_863_322_166_853_742
            ]
        );
        assert_eq!(
            material
                .poseidon2_v8_authorization_extension_words()
                .unwrap(),
            [
                5_551_091_740_101_773_036,
                4_468_278_513_200_243_473,
                13_630_218_852_427_362_977
            ]
        );
        assert_eq!(
            spend,
            [
                7_168_953_366_546_811_868,
                2_906_145_813_326_798_190,
                1_270_714_600_746_738_463,
                12_813_674_516_097_660_753,
                0,
            ]
        );
        assert_eq!(
            recipient,
            [
                14_132_942_956_216_209_493,
                7_685_267_610_787_277_800,
                16_563_171_182_421_170_277,
                17_300_113_818_709_955_652,
            ]
        );
        assert_ne!(
            authorization,
            [
                1_741_146_651_100_274_088,
                9_539_478_460_468_656_252,
                7_097_725_263_314_205_436,
                1_436_916_868_072_586_276,
            ]
        );
        assert_eq!(
            authorization,
            poseidon2_v8_single_key_authorization_key(spend).unwrap()
        );

        for (rho, mut randomness, seed) in [
            ([31, 32, 33, 34], [41, 42, 43, 44], 101),
            ([51, 52, 53, 54], [61, 62, 63, 64], 102),
        ] {
            randomness[..3].copy_from_slice(
                &material
                    .poseidon2_v8_authorization_extension_words()
                    .unwrap(),
            );
            let opening = Poseidon2V8CoinbaseNoteOpening {
                value: 499_429_223,
                asset_id: NATIVE_ASSET_ID,
                recipient_key: recipient,
                authorization_key: authorization,
                rho,
                randomness,
            };
            let mut rng = StdRng::seed_from_u64(seed);
            let args =
                build_poseidon2_v8_coinbase_args_from_opening(&address, opening, &mut rng).unwrap();
            assert_eq!(
                decode_and_decrypt_poseidon2_v8_coinbase_action(&args.encode(), &material).unwrap(),
                protocol_opening_to_relation(opening)
            );
        }
    }

    #[test]
    fn repaired_carriers_build_wallet_owned_spend_and_reject_old_carriers() {
        let root = RootSecret::from_bytes([0x51; 32]);
        let keys = root.derive();
        let material = keys.poseidon2_v8_address(9).unwrap();
        let address = material.shielded_address();
        let recipient = poseidon2_v8_words_from_canonical_bytes(address.pk_recipient).unwrap();
        let authorization = poseidon2_v8_words_from_canonical_bytes(address.pk_auth).unwrap();
        let mut input_openings = [
            Poseidon2V8CoinbaseNoteOpening {
                value: 499_429_223,
                asset_id: NATIVE_ASSET_ID,
                recipient_key: recipient,
                authorization_key: authorization,
                rho: [31, 32, 33, 34],
                randomness: [41, 42, 43, 44],
            },
            Poseidon2V8CoinbaseNoteOpening {
                value: 499_429_223,
                asset_id: NATIVE_ASSET_ID,
                recipient_key: recipient,
                authorization_key: authorization,
                rho: [51, 52, 53, 54],
                randomness: [61, 62, 63, 64],
            },
        ];

        for opening in &mut input_openings {
            opening.randomness[..3].copy_from_slice(
                &material
                    .poseidon2_v8_authorization_extension_words()
                    .unwrap(),
            );
        }
        // New relation carriers are distinct; retained old bytes stay unchanged.
        let mut rng = StdRng::seed_from_u64(301);
        let expected_coinbase = [
            RETAINED_V8_COINBASE_0_SCALE.as_slice(),
            RETAINED_V8_COINBASE_1_SCALE.as_slice(),
        ];
        let mut fresh_coinbase = Vec::new();
        for input in 0..2 {
            let args = build_poseidon2_v8_coinbase_args_from_opening(
                &address,
                input_openings[input],
                &mut rng,
            )
            .unwrap();
            assert_ne!(args.encode(), expected_coinbase[input]);
            fresh_coinbase.push(args.encode());
        }
        assert!(build_poseidon2_v8_two_coinbase_self_spend(
            &root,
            9,
            expected_coinbase,
            2,
            [9, 9],
            &mut rng,
        )
        .is_err());
        let spend = build_poseidon2_v8_two_coinbase_self_spend(
            &root,
            9,
            [fresh_coinbase[0].as_slice(), fresh_coinbase[1].as_slice()],
            2,
            [9, 9],
            &mut rng,
        )
        .unwrap();

        let compiled = transaction_circuit::smallwood_poseidon2_v8_semantics::compile_smallwood_poseidon2_v8_relation(
            &spend.statement, &spend.witness).unwrap();
        compiled
            .adapter
            .verify_packed_witness(&compiled.witness_values)
            .unwrap();

        assert_ne!(
            spend.inline_ciphertexts.ciphertexts,
            [
                Some(*RETAINED_V8_OUTPUT_0_RAW),
                Some(*RETAINED_V8_OUTPUT_1_RAW)
            ]
        );
        assert_ne!(
            spend.witness.outputs.map(|output| output.note),
            RETAINED_V8_OUTPUT_OPENINGS.map(protocol_opening_to_relation)
        );
        assert_ne!(
            sha512_hex(&spend.statement.to_public_bytes()),
            RETAINED_V8_STATEMENT_SHA512
        );
        assert_ne!(
            sha512_hex(&spend.witness.to_witness_bytes()),
            RETAINED_V8_WITNESS_SHA512
        );
        assert_ne!(
            sha512_hex(&spend.inline_ciphertexts.to_inline_ciphertext_bytes()),
            RETAINED_V8_INLINE_CIPHERTEXT_SHA512
        );
        assert_eq!(sha512_hex(&spend.statement.to_public_bytes()),
            "4d7d28543e8a795ede947da241226543d7d14bd79a2e67e3de3e23ef005496502e1efc674527531433b1d479a53ea464936bbf5108cf1a789ad09a2ebcd94a80");
        assert_eq!(sha512_hex(&spend.witness.to_witness_bytes()),
            "14215237086f0c130bfb70f6025bdf1a54f34d2c37afe93a60f5b7346b66d000736fafcf6df545b55970697786045025b92a70b1389811937925e75f0f65ecd6");
        assert_eq!(sha512_hex(&spend.inline_ciphertexts.to_inline_ciphertext_bytes()),
            "1101e122f9164f05ee7c27bf159eee0ad5985aa03924d4433633360848dc68d7a0ecb2b137cc3c62f8e2bdcca6a5dd394466960f7051b95a9dc196f3d4315077");

        let commitments = [
            poseidon2_v8_note_commitment(protocol_opening_to_relation(input_openings[0])).unwrap(),
            poseidon2_v8_note_commitment(protocol_opening_to_relation(input_openings[1])).unwrap(),
        ];
        let frontier = poseidon2_v8_two_note_frontier(commitments).unwrap();
        assert_eq!(spend.statement.merkle_root, frontier.root);
        for input in 0..2 {
            assert_eq!(spend.witness.inputs[input].position, input as u64);
            assert_eq!(spend.witness.inputs[input].siblings, frontier.paths[input]);
            assert_eq!(
                spend.witness.inputs[input].spend_key,
                keys.spend.poseidon2_v8_words().unwrap()
            );
        }

        for output in 0..2 {
            let raw = spend.inline_ciphertexts.ciphertexts[output].unwrap();
            let plaintext = NoteCiphertext::from_da_bytes(&raw)
                .unwrap()
                .decrypt(&material)
                .unwrap();
            let opening = spend.witness.outputs[output].note;
            assert_eq!(plaintext.value, opening.value);
            assert_eq!(plaintext.asset_id, opening.asset_id);
            assert_eq!(plaintext.rho, poseidon2_v8_words_to_bytes(opening.rho));
            assert_eq!(plaintext.r, poseidon2_v8_words_to_bytes(opening.randomness));
        }

        let mut mutated_coinbase = fresh_coinbase[0].clone();
        *mutated_coinbase.last_mut().unwrap() ^= 1;
        let mut mutation_rng = StdRng::seed_from_u64(999);
        assert!(build_poseidon2_v8_two_coinbase_self_spend(
            &root,
            9,
            [&mutated_coinbase, fresh_coinbase[1].as_slice()],
            2,
            [9, 9],
            &mut mutation_rng,
        )
        .is_err());
        assert!(build_poseidon2_v8_two_coinbase_self_spend(
            &root,
            9,
            [fresh_coinbase[0].as_slice(), fresh_coinbase[0].as_slice(),],
            2,
            [9, 9],
            &mut mutation_rng,
        )
        .is_err());
        let mut mutated_output = spend.inline_ciphertexts.ciphertexts[0].unwrap();
        *mutated_output.last_mut().unwrap() ^= 1;
        assert!(NoteCiphertext::from_da_bytes(&mutated_output)
            .and_then(|ciphertext| ciphertext.decrypt(&material))
            .is_err());
    }
}
