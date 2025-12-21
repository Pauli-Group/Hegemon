use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::{error::WalletError, notes::NoteCiphertext};
use transaction_circuit::StablecoinPolicyBinding;

/// Transaction bundle for submission to the node.
///
/// This contains all data needed to submit a shielded transfer to the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBundle {
    /// STARK proof bytes (serialized winterfell proof).
    #[serde(with = "serde_bytes_vec")]
    pub proof_bytes: Vec<u8>,
    /// Nullifiers (32 bytes each, left-padded field elements).
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments (32 bytes each, left-padded field elements).
    pub commitments: Vec<[u8; 32]>,
    /// Encrypted note ciphertexts.
    #[serde(with = "serde_ciphertexts")]
    pub ciphertexts: Vec<Vec<u8>>,
    /// Merkle tree anchor (root hash).
    pub anchor: [u8; 32],
    /// Binding hash commitment.
    #[serde(with = "serde_bytes_64")]
    pub binding_hash: [u8; 64],
    /// Native fee encoded in the proof.
    pub fee: u64,
    /// Value balance (must be 0 when no transparent pool is enabled).
    pub value_balance: i128,
    /// Optional stablecoin policy binding (disabled by default).
    #[serde(default)]
    pub stablecoin: StablecoinPolicyBinding,
}

impl TransactionBundle {
    /// Create a new transaction bundle from proof components.
    pub fn new(
        proof_bytes: Vec<u8>,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        ciphertexts: &[NoteCiphertext],
        anchor: [u8; 32],
        binding_hash: [u8; 64],
        fee: u64,
        value_balance: i128,
        stablecoin: StablecoinPolicyBinding,
    ) -> Result<Self, WalletError> {
        let mut encoded = Vec::with_capacity(ciphertexts.len());
        for ct in ciphertexts {
            // Use pallet-compatible format (1699 bytes) instead of bincode
            encoded.push(ct.to_pallet_bytes()?);
        }
        Ok(Self {
            proof_bytes,
            nullifiers,
            commitments,
            ciphertexts: encoded,
            anchor,
            binding_hash,
            fee,
            value_balance,
            stablecoin,
        })
    }

    pub fn decode_notes(&self) -> Result<Vec<NoteCiphertext>, WalletError> {
        let mut notes = Vec::with_capacity(self.ciphertexts.len());
        for bytes in &self.ciphertexts {
            // Decode from pallet format (1699 bytes)
            notes.push(NoteCiphertext::from_pallet_bytes(bytes)?);
        }
        Ok(notes)
    }
}

const AUTH_HEADER: &str = "x-auth-token";

#[derive(Clone, Debug)]
pub struct WalletRpcClient {
    client: Client,
    base: Url,
    token: String,
}

impl WalletRpcClient {
    pub fn new(base: Url, token: impl Into<String>) -> Result<Self, WalletError> {
        Self::new_with_cert(base, token, None)
    }

    pub fn new_with_cert(
        base: Url,
        token: impl Into<String>,
        cert_pem: Option<&[u8]>,
    ) -> Result<Self, WalletError> {
        let mut builder = Client::builder();
        if let Some(pem) = cert_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|err| WalletError::Http(err.to_string()))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|err| WalletError::Http(err.to_string()))?;
        Ok(Self {
            client,
            base,
            token: token.into(),
        })
    }

    pub fn latest_block(&self) -> Result<LatestBlock, WalletError> {
        self.get_json("/blocks/latest", None)
    }

    pub fn note_status(&self) -> Result<NoteStatusResponse, WalletError> {
        self.get_json("/wallet/notes", None)
    }

    pub fn commitments(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CommitmentEntry>, WalletError> {
        let query: Vec<(&str, String)> =
            vec![("start", start.to_string()), ("limit", limit.to_string())];
        let response: CommitmentResponse = self.get_json("/wallet/commitments", Some(&query))?;
        response
            .entries
            .into_iter()
            .map(|entry| {
                let value = hex_to_array32(&entry.value)?;
                Ok(CommitmentEntry {
                    index: entry.index,
                    value,
                })
            })
            .collect()
    }

    pub fn ciphertexts(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<CiphertextEntry>, WalletError> {
        let query: Vec<(&str, String)> =
            vec![("start", start.to_string()), ("limit", limit.to_string())];
        let response: CiphertextResponse = self.get_json("/wallet/ciphertexts", Some(&query))?;
        let mut entries = Vec::with_capacity(response.entries.len());
        for entry in response.entries {
            // Parse from pallet format (1699 bytes)
            let ciphertext = NoteCiphertext::from_pallet_bytes(&entry.ciphertext)?;
            entries.push(CiphertextEntry {
                index: entry.index,
                ciphertext,
            });
        }
        Ok(entries)
    }

    pub fn nullifiers(&self) -> Result<Vec<[u8; 32]>, WalletError> {
        let response: NullifierResponse = self.get_json("/wallet/nullifiers", None)?;
        response
            .nullifiers
            .iter()
            .map(|hex| {
                let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
                let bytes = hex::decode(trimmed)
                    .map_err(|err| WalletError::Serialization(err.to_string()))?;
                if bytes.len() != 32 {
                    return Err(WalletError::Serialization(
                        "invalid nullifier length".into(),
                    ));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(out)
            })
            .collect()
    }

    pub fn submit_transaction(&self, bundle: &TransactionBundle) -> Result<[u8; 32], WalletError> {
        let url = self
            .base
            .join("/transactions")
            .map_err(|err| WalletError::Http(err.to_string()))?;
        let response = self
            .client
            .post(url)
            .headers(self.headers()?)
            .json(bundle)
            .send()?;
        if !response.status().is_success() {
            return Err(WalletError::Http(format!(
                "submission failed: {}",
                response.status()
            )));
        }
        let tx: TransactionResponse = response.json()?;
        hex_to_array(&tx.tx_id)
    }

    fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: Option<&[(&str, String)]>,
    ) -> Result<T, WalletError> {
        let mut url = self
            .base
            .join(path)
            .map_err(|err| WalletError::Http(err.to_string()))?;
        if let Some(params) = query {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in params {
                pairs.append_pair(key, value);
            }
        }
        let response = self.client.get(url).headers(self.headers()?).send()?;
        if !response.status().is_success() {
            return Err(WalletError::Http(format!(
                "request failed: {}",
                response.status()
            )));
        }
        Ok(response.json()?)
    }

    fn headers(&self) -> Result<HeaderMap, WalletError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTH_HEADER,
            HeaderValue::from_str(&self.token).map_err(|err| WalletError::Http(err.to_string()))?,
        );
        Ok(headers)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LatestBlock {
    pub height: u64,
    pub hash: String,
    pub state_root: String,
    pub nullifier_root: String,
    pub supply_digest: u128,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NoteStatusResponse {
    pub leaf_count: u64,
    pub depth: u64,
    pub root: String,
    pub next_index: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CommitmentResponse {
    entries: Vec<CommitmentWireEntry>,
}

#[derive(Clone, Debug)]
pub struct CommitmentEntry {
    pub index: u64,
    pub value: [u8; 32],
}

#[derive(Clone, Debug, Deserialize)]
struct CommitmentWireEntry {
    pub index: u64,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct CiphertextEntry {
    pub index: u64,
    pub ciphertext: NoteCiphertext,
}

#[derive(Deserialize)]
struct CiphertextResponse {
    entries: Vec<CiphertextWireEntry>,
}

#[derive(Deserialize)]
struct CiphertextWireEntry {
    index: u64,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct NullifierResponse {
    nullifiers: Vec<String>,
}

#[derive(Deserialize)]
struct TransactionResponse {
    tx_id: String,
}

fn hex_to_array(hex_str: &str) -> Result<[u8; 32], WalletError> {
    hex_to_array32(hex_str)
}

fn hex_to_array32(hex_str: &str) -> Result<[u8; 32], WalletError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(trimmed).map_err(|err| WalletError::Serialization(err.to_string()))?;
    if bytes.len() != 32 {
        return Err(WalletError::Serialization("expected 32-byte hash".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

mod serde_ciphertexts {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wrappers: Vec<_> = values
            .iter()
            .map(|value| serde_bytes::Bytes::new(value))
            .collect();
        wrappers.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrappers: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        Ok(wrappers.into_iter().map(|buf| buf.into_vec()).collect())
    }
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Ok(buf.into_vec())
    }
}

mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(value).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let vec = buf.into_vec();
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}
