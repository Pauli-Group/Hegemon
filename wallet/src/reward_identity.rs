//! Public reward-account authority derived from the existing encrypted root.
//! This does not change shielded keys or confer node/proof authority.
use crate::{AddressNetwork, WalletError};
use protocol_reward_accounts::{AccountPolicy, PublicAccountAddress};
use synthetic_crypto::{
    hash384::blake2b_384_domain_hash, ml_dsa::MlDsaSecretKey, traits::SigningKey,
};
use zeroize::Zeroizing;

pub fn derive_reward_account_key(
    root: &[u8; 32],
    network: AddressNetwork,
    index: u32,
) -> Result<MlDsaSecretKey, WalletError> {
    network
        .validate()
        .map_err(|_| WalletError::InvalidState("invalid reward-account network"))?;
    let class = [match network.class {
        crate::NetworkClass::Testnet => 0,
        crate::NetworkClass::Mainnet => 1,
    }];
    let seed = Zeroizing::new(blake2b_384_domain_hash(
        b"hegemon.wallet.reward-account-key.v1",
        [
            root.as_slice(),
            class.as_slice(),
            network.discriminator.as_slice(),
            index.to_le_bytes().as_slice(),
        ],
    ));
    Ok(MlDsaSecretKey::generate_deterministic(seed.as_ref()))
}
pub fn reward_account_address(
    root: &[u8; 32],
    network: AddressNetwork,
    index: u32,
) -> Result<String, WalletError> {
    let key = derive_reward_account_key(root, network, index)?;
    PublicAccountAddress {
        network,
        policy: AccountPolicy::single(&key.verify_key())
            .identifier()
            .map_err(|_| WalletError::InvalidState("reward policy"))?,
    }
    .encode()
    .map_err(|_| WalletError::InvalidState("reward address"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reward_identity_recovered_root_preserves_account_and_separates_networks() {
        let network = AddressNetwork {
            class: crate::NetworkClass::Testnet,
            discriminator: [9; 32],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let store = crate::store::WalletStore::create_from_root(
            &path,
            "passphrase",
            crate::RootSecret::from_bytes([8; 32]),
        )
        .unwrap();
        let root = Zeroizing::new(store.signing_seed().unwrap());
        let first = reward_account_address(&root, network, 0).unwrap();
        let recipient = store.private_spend_address(0).unwrap();
        let vector = serde_json::json!({"accountTest":PublicAccountAddress{network,policy:protocol_reward_accounts::AccountPolicyId48::new([34;48])}.encode().unwrap(),"accountMain":PublicAccountAddress{network:AddressNetwork{class:crate::NetworkClass::Mainnet,..network},policy:protocol_reward_accounts::AccountPolicyId48::new([34;48])}.encode().unwrap(),"shieldedTest":crate::NetworkShieldedAddress::from_recipient(network,recipient.clone()).unwrap().encode().unwrap(),"shieldedMain":crate::NetworkShieldedAddress::from_recipient(AddressNetwork{class:crate::NetworkClass::Mainnet,..network},recipient).unwrap().encode().unwrap()});
        assert_eq!(
            vector,
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../tests/fixtures/reward-addresses.json"
            ))
            .unwrap()
        );

        drop(store);
        let store = crate::store::WalletStore::open(&path, "passphrase").unwrap();
        let recovered = Zeroizing::new(store.signing_seed().unwrap());
        assert_eq!(
            first,
            reward_account_address(&recovered, network, 0).unwrap()
        );
        assert_ne!(
            first,
            reward_account_address(
                &recovered,
                AddressNetwork {
                    discriminator: [10; 32],
                    ..network
                },
                0
            )
            .unwrap()
        );
        assert_ne!(
            first,
            reward_account_address(&recovered, network, 1).unwrap()
        );
        let key = derive_reward_account_key(&recovered, network, 0).unwrap();
        let policy = AccountPolicy::single(&key.verify_key());
        let approval = protocol_reward_accounts::AccountApproval::sign(0, &key, &[6; 48]);
        policy.verify(&[6; 48], &[approval]).unwrap();
    }
}
