use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, PaymentDisclosureClaim,
    PaymentDisclosureProofBundle, PaymentDisclosureWitness,
};
use rand::{rngs::StdRng, SeedableRng};
use state_merkle::CommitmentTree;
use transaction_circuit::hashing::{
    bytes32_to_felt, felt_to_bytes32, is_canonical_bytes32, note_commitment_bytes, Felt,
};
use transaction_circuit::note::{MerklePath, MERKLE_TREE_DEPTH};
use wallet::address::ShieldedAddress;
use wallet::disclosure::{
    decode_base64, encode_base64, DisclosureChainInfo, DisclosureClaim, DisclosureConfirmation,
    DisclosurePackage, DisclosureProof,
};
use wallet::keys::RootSecret;
use wallet::notes::{MemoPlaintext, NotePlaintext};

fn build_package() -> DisclosurePackage {
    let root = RootSecret::from_bytes([7u8; 32]);
    let keys = root.derive();
    let address = keys.address(0).expect("address").shielded_address();
    let recipient_address = address.encode().expect("encode address");

    let mut rng = StdRng::seed_from_u64(1234);
    let memo = MemoPlaintext::new(b"deposit".to_vec());
    let note = NotePlaintext::random(100_000_000, 0, memo, &mut rng);
    let note_data = note.to_note_data(address.pk_recipient);

    let commitment = note_commitment_bytes(
        note_data.value,
        note_data.asset_id,
        &note_data.pk_recipient,
        &note_data.rho,
        &note_data.r,
    );

    let claim = PaymentDisclosureClaim {
        value: note_data.value,
        asset_id: note_data.asset_id,
        pk_recipient: note_data.pk_recipient,
        commitment,
    };
    let witness = PaymentDisclosureWitness {
        rho: note_data.rho,
        r: note_data.r,
    };
    let proof_bundle = prove_payment_disclosure(&claim, &witness).expect("proof");

    let mut tree = CommitmentTree::new(MERKLE_TREE_DEPTH).expect("tree");
    let commitment_felt = bytes32_to_felt(&commitment).expect("canonical commitment");
    let (leaf_index, _) = tree.append(commitment_felt).expect("append");
    let auth_path = tree.authentication_path(leaf_index).expect("path");
    let anchor = felt_to_bytes32(tree.root());
    let siblings: Vec<[u8; 32]> = auth_path.into_iter().map(felt_to_bytes32).collect();

    DisclosurePackage {
        version: 1,
        chain: DisclosureChainInfo {
            genesis_hash: [9u8; 32],
        },
        claim: DisclosureClaim {
            recipient_address,
            pk_recipient: address.pk_recipient,
            value: note_data.value,
            asset_id: note_data.asset_id,
            commitment,
        },
        confirmation: DisclosureConfirmation {
            anchor,
            leaf_index: leaf_index as u64,
            siblings,
        },
        proof: DisclosureProof {
            air_hash: proof_bundle.air_hash,
            bytes: encode_base64(&proof_bundle.proof_bytes),
        },
        disclosed_memo: Some("deposit".to_string()),
    }
}

fn verify_package(
    package: &DisclosurePackage,
    expected_genesis_hash: [u8; 32],
    anchor_valid: bool,
) -> Result<(), String> {
    if package.version != 1 {
        return Err("unsupported disclosure package version".to_string());
    }

    let recipient = ShieldedAddress::decode(&package.claim.recipient_address)
        .map_err(|e| e.to_string())?;
    if recipient.pk_recipient != package.claim.pk_recipient {
        return Err("recipient address does not match pk_recipient".to_string());
    }

    if !is_canonical_bytes32(&package.claim.commitment) {
        return Err("commitment is not a canonical field encoding".to_string());
    }
    if !is_canonical_bytes32(&package.confirmation.anchor) {
        return Err("anchor is not a canonical field encoding".to_string());
    }
    for (idx, sibling) in package.confirmation.siblings.iter().enumerate() {
        if !is_canonical_bytes32(sibling) {
            return Err(format!("siblings[{idx}] is not a canonical field encoding"));
        }
    }
    if package.confirmation.siblings.len() != MERKLE_TREE_DEPTH {
        return Err("merkle path length mismatch".to_string());
    }

    let commitment_felt = bytes32_to_felt(&package.claim.commitment)
        .ok_or_else(|| "commitment is not canonical".to_string())?;
    let anchor_felt = bytes32_to_felt(&package.confirmation.anchor)
        .ok_or_else(|| "anchor is not canonical".to_string())?;
    let sibling_felts: Vec<Felt> = package
        .confirmation
        .siblings
        .iter()
        .map(|bytes| bytes32_to_felt(bytes).ok_or_else(|| "non-canonical sibling".to_string()))
        .collect::<Result<_, _>>()?;

    let merkle_path = MerklePath {
        siblings: sibling_felts,
    };
    if !merkle_path.verify(commitment_felt, package.confirmation.leaf_index, anchor_felt) {
        return Err("merkle path verification failed".to_string());
    }

    if package.chain.genesis_hash != expected_genesis_hash {
        return Err("genesis hash mismatch".to_string());
    }
    if !anchor_valid {
        return Err("anchor is not valid on chain".to_string());
    }

    let proof_bytes = decode_base64(&package.proof.bytes).map_err(|e| e.to_string())?;
    let bundle = PaymentDisclosureProofBundle {
        claim: PaymentDisclosureClaim {
            value: package.claim.value,
            asset_id: package.claim.asset_id,
            pk_recipient: package.claim.pk_recipient,
            commitment: package.claim.commitment,
        },
        proof_bytes,
        air_hash: package.proof.air_hash,
    };

    verify_payment_disclosure(&bundle).map_err(|e| format!("{e}"))?;

    Ok(())
}

#[test]
fn disclosure_package_roundtrip_verifies() {
    let package = build_package();
    let genesis_hash = package.chain.genesis_hash;
    verify_package(&package, genesis_hash, true).expect("verify");
}

#[test]
fn disclosure_package_tamper_rejects() {
    let package = build_package();
    let genesis_hash = package.chain.genesis_hash;

    let mut bad_value = package.clone();
    bad_value.claim.value += 1;
    assert!(verify_package(&bad_value, genesis_hash, true).is_err());

    let mut bad_merkle = package.clone();
    bad_merkle.confirmation.siblings[0][0] ^= 0x01;
    assert!(verify_package(&bad_merkle, genesis_hash, true).is_err());

    let mut other_genesis = genesis_hash;
    other_genesis[0] ^= 0x01;
    assert!(verify_package(&package, other_genesis, true).is_err());

    assert!(verify_package(&package, genesis_hash, false).is_err());
}
