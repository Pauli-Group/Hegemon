use crate::{AccountPolicyId48, RewardAccountsError as Error};
use bech32::{FromBase32, ToBase32, Variant};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub const ADDRESS_FORMAT_V1: u8 = 1;
pub const MAX_ACCOUNT_ADDRESS_CHARS: usize = 256;
pub const MAX_SHIELDED_ADDRESS_CHARS: usize = 4096;
const HEADER_BYTES: usize = 35;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkClass {
    Testnet,
    Mainnet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressNetwork {
    pub class: NetworkClass,
    pub discriminator: [u8; 32],
}
impl AddressNetwork {
    pub fn validate(self) -> Result<(), Error> {
        if self.discriminator == [0; 32] {
            Err(Error::InvalidNetwork)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    PublicAccount,
    Shielded,
}
impl AddressKind {
    fn tag(self) -> u8 {
        match self {
            Self::PublicAccount => 0,
            Self::Shielded => 1,
        }
    }
    fn hrp(self, class: NetworkClass) -> &'static str {
        match (self, class) {
            (Self::PublicAccount, NetworkClass::Mainnet) => "heg",
            (Self::PublicAccount, NetworkClass::Testnet) => "heg_test",
            (Self::Shielded, NetworkClass::Mainnet) => "heg_shield",
            (Self::Shielded, NetworkClass::Testnet) => "heg_shield_test",
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::PublicAccount => MAX_ACCOUNT_ADDRESS_CHARS,
            Self::Shielded => MAX_SHIELDED_ADDRESS_CHARS,
        }
    }
}

/// Typed public address. The network is part of the encoded identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicAccountAddress {
    pub network: AddressNetwork,
    pub policy: AccountPolicyId48,
}
impl PublicAccountAddress {
    pub fn encode(self) -> Result<String, Error> {
        if self.policy == AccountPolicyId48::ZERO {
            return Err(Error::InvalidPolicy);
        }
        encode_address_body(
            AddressKind::PublicAccount,
            self.network,
            self.policy.as_bytes(),
        )
    }
    pub fn decode(text: &str, expected_network: AddressNetwork) -> Result<Self, Error> {
        let body = decode_address_body(text, AddressKind::PublicAccount, expected_network)?;
        let bytes: [u8; 48] = body
            .try_into()
            .map_err(|_| Error::Address("wrong account identifier length".into()))?;
        let policy = AccountPolicyId48::new(bytes);
        if policy == AccountPolicyId48::ZERO {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            network: expected_network,
            policy,
        })
    }
}

/// Shared envelope only; callers must also validate their typed body.
pub fn encode_address_body(
    kind: AddressKind,
    network: AddressNetwork,
    body: &[u8],
) -> Result<String, Error> {
    let bytes = encode_address_bytes(kind, network, body)?;
    bech32::encode(kind.hrp(network.class), bytes.to_base32(), Variant::Bech32m)
        .map_err(|e| Error::Address(e.to_string()))
}

pub fn encode_address_bytes(
    kind: AddressKind,
    network: AddressNetwork,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    network.validate()?;
    if body.len() > kind.limit() {
        return Err(Error::Address("address exceeds size limit".into()));
    }
    // Bound before base conversion/allocation, including the checksum and HRP.
    let encoded_len =
        kind.hrp(network.class).len() + 1 + ((HEADER_BYTES + body.len()) * 8).div_ceil(5) + 6;
    if encoded_len > kind.limit() {
        return Err(Error::Address("address exceeds size limit".into()));
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[
        ADDRESS_FORMAT_V1,
        kind.tag(),
        match network.class {
            NetworkClass::Testnet => 0,
            NetworkClass::Mainnet => 1,
        },
    ]);
    bytes.extend_from_slice(&network.discriminator);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

pub fn decode_address_body(
    text: &str,
    kind: AddressKind,
    expected: AddressNetwork,
) -> Result<Vec<u8>, Error> {
    expected.validate()?;
    if text.len() > kind.limit() {
        return Err(Error::Address("address exceeds size limit".into()));
    }
    let (hrp, data, variant) = bech32::decode(text).map_err(|e| Error::Address(e.to_string()))?;
    if variant != Variant::Bech32m {
        return Err(Error::Address("expected Bech32m checksum".into()));
    }
    if hrp != kind.hrp(expected.class) {
        return Err(Error::WrongAddressNetworkOrKind);
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|e| Error::Address(e.to_string()))?;
    decode_address_bytes(&bytes, kind, expected)
}

/// Binary entrypoints enforce exactly the same network/type checks as text.
pub fn decode_address_bytes(
    bytes: &[u8],
    kind: AddressKind,
    expected: AddressNetwork,
) -> Result<Vec<u8>, Error> {
    expected.validate()?;
    let max_body = (kind.limit() * 5 / 8).saturating_sub(HEADER_BYTES);
    if bytes.len() < HEADER_BYTES
        || bytes.len() > HEADER_BYTES + max_body
        || bytes[0] != ADDRESS_FORMAT_V1
    {
        return Err(Error::Address("invalid address envelope".into()));
    }
    let class = match expected.class {
        NetworkClass::Testnet => 0,
        NetworkClass::Mainnet => 1,
    };
    if bytes[1] != kind.tag()
        || bytes[2] != class
        || bytes[3..HEADER_BYTES] != expected.discriminator
    {
        return Err(Error::WrongAddressNetworkOrKind);
    }
    Ok(bytes[HEADER_BYTES..].to_vec())
}
