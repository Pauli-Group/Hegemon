//! Network-aware reset address. Historical `shca` encoding remains inspection-only
//! for successor callers, which must use this typed address and explicit context.
use crate::{
    address::{ShieldedAddress, POSEIDON2_V8_ADDRESS_VERSION},
    WalletError,
};
use protocol_reward_accounts::{
    decode_address_body, decode_address_bytes, encode_address_body, encode_address_bytes,
    AddressKind, AddressNetwork,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkShieldedAddress {
    network: AddressNetwork,
    recipient: ShieldedAddress,
}
impl NetworkShieldedAddress {
    /// Explicitly export owned/currently verified recipient material to a network.
    /// This never guesses the network of pasted historical address text.
    pub fn from_recipient(
        network: AddressNetwork,
        recipient: ShieldedAddress,
    ) -> Result<Self, WalletError> {
        network.validate().map_err(address_error)?;
        if recipient.version != POSEIDON2_V8_ADDRESS_VERSION {
            return Err(WalletError::AddressEncoding(
                "reset recipient requires full V8 authorization".into(),
            ));
        }
        let recipient = ShieldedAddress::from_bytes(&recipient.to_bytes())?;
        Ok(Self { network, recipient })
    }
    pub fn network(&self) -> AddressNetwork {
        self.network
    }
    pub fn recipient(&self) -> &ShieldedAddress {
        &self.recipient
    }
    pub fn encode(&self) -> Result<String, WalletError> {
        encode_address_body(
            AddressKind::Shielded,
            self.network,
            &self.recipient.to_bytes(),
        )
        .map_err(address_error)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletError> {
        encode_address_bytes(
            AddressKind::Shielded,
            self.network,
            &self.recipient.to_bytes(),
        )
        .map_err(address_error)
    }
    pub fn decode(text: &str, expected_network: AddressNetwork) -> Result<Self, WalletError> {
        let body = decode_address_body(text, AddressKind::Shielded, expected_network)
            .map_err(address_error)?;
        Self::from_recipient(expected_network, ShieldedAddress::from_bytes(&body)?)
    }
    pub fn from_bytes(bytes: &[u8], expected_network: AddressNetwork) -> Result<Self, WalletError> {
        let body = decode_address_bytes(bytes, AddressKind::Shielded, expected_network)
            .map_err(address_error)?;
        Self::from_recipient(expected_network, ShieldedAddress::from_bytes(&body)?)
    }
}
fn address_error(error: protocol_reward_accounts::RewardAccountsError) -> WalletError {
    WalletError::AddressEncoding(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RootSecret;
    use protocol_reward_accounts::{AccountPolicyId48, NetworkClass, PublicAccountAddress};

    #[test]
    fn reward_accounts_network_shielded_long_round_trip_and_type_separation() {
        let network = AddressNetwork {
            class: NetworkClass::Testnet,
            discriminator: [1; 32],
        };
        let recipient = RootSecret::from_bytes([17; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address();
        let address = NetworkShieldedAddress::from_recipient(network, recipient.clone()).unwrap();
        let encoded = address.encode().unwrap();
        assert!(encoded.starts_with("heg_shield_test1"));
        assert!(encoded.len() > 90 && encoded.len() <= 4096);
        assert_eq!(
            NetworkShieldedAddress::decode(&encoded, network).unwrap(),
            address
        );
        assert_eq!(
            NetworkShieldedAddress::decode(&encoded.to_uppercase(), network).unwrap(),
            address
        );
        assert_eq!(
            NetworkShieldedAddress::from_bytes(&address.to_bytes().unwrap(), network).unwrap(),
            address
        );
        assert!(NetworkShieldedAddress::decode(&recipient.encode().unwrap(), network).is_err());
        let account = PublicAccountAddress {
            network,
            policy: AccountPolicyId48::new([2; 48]),
        };
        assert!(NetworkShieldedAddress::decode(&account.encode().unwrap(), network).is_err());
        assert!(PublicAccountAddress::decode(&encoded, network).is_err());
        let main = AddressNetwork {
            class: NetworkClass::Mainnet,
            ..network
        };
        assert!(NetworkShieldedAddress::decode(&encoded, main).is_err());
        assert!(NetworkShieldedAddress::from_bytes(&address.to_bytes().unwrap(), main).is_err());
        let other = AddressNetwork {
            discriminator: [3; 32],
            ..network
        };
        assert!(NetworkShieldedAddress::decode(&encoded, other).is_err());
        let main_address = NetworkShieldedAddress::from_recipient(main, recipient)
            .unwrap()
            .encode()
            .unwrap();
        assert!(main_address.starts_with("heg_shield1"));
        let (_, data, variant) = bech32::decode(&encoded).unwrap();
        let relabeled = bech32::encode("heg_shield", data, variant).unwrap();
        assert!(NetworkShieldedAddress::decode(&relabeled, main).is_err());
    }
}
