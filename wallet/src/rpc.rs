use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use transaction_circuit::proof::TransactionProof;
use url::Url;

use crate::{error::WalletError, notes::NoteCiphertext};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBundle {
    pub proof: TransactionProof,
    #[serde(with = "serde_ciphertexts")]
    pub ciphertexts: Vec<Vec<u8>>,
}

impl TransactionBundle {
    pub fn from_notes(
        proof: TransactionProof,
        ciphertexts: &[NoteCiphertext],
    ) -> Result<Self, WalletError> {
        let mut encoded = Vec::with_capacity(ciphertexts.len());
        for ct in ciphertexts {
            encoded.push(bincode::serialize(ct)?);
        }
        Ok(Self {
            proof,
            ciphertexts: encoded,
        })
    }

    pub fn decode_notes(&self) -> Result<Vec<NoteCiphertext>, WalletError> {
        let mut notes = Vec::with_capacity(self.ciphertexts.len());
        for bytes in &self.ciphertexts {
            notes.push(bincode::deserialize(bytes)?);
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
        Ok(response.entries)
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
            let ciphertext: NoteCiphertext = bincode::deserialize(&entry.ciphertext)?;
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
                let bytes =
                    hex::decode(hex).map_err(|err| WalletError::Serialization(err.to_string()))?;
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
    pub root: u64,
    pub next_index: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CommitmentResponse {
    entries: Vec<CommitmentEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CommitmentEntry {
    pub index: u64,
    pub value: u64,
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
    let bytes = hex::decode(hex_str).map_err(|err| WalletError::Serialization(err.to_string()))?;
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
