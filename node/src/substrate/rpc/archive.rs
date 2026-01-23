//! Archive provider RPC endpoints.

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use pallet_archive_market::{ArchiveContract, ContractStatus, ProviderInfo};
use runtime::{AccountId, Runtime};

/// Archive provider entry returned by RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveProviderEntry {
    pub provider: String,
    pub bond: u128,
    pub price_per_byte_block: u128,
    pub min_duration_blocks: u64,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveContractStatus {
    Active,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveContractEntry {
    pub contract_id: u64,
    pub buyer: String,
    pub provider: String,
    pub start_block: u64,
    pub end_block: u64,
    pub retention_blocks: u64,
    pub expires_at: u64,
    pub byte_count: u64,
    pub price_per_byte_block: u128,
    pub total_cost: u128,
    pub bond_stake: u128,
    pub created_at: u64,
    pub status: ArchiveContractStatus,
}

/// Trait for archive market queries.
pub trait ArchiveMarketService: Send + Sync {
    fn provider_count(&self) -> Result<u32, String>;
    fn provider(&self, provider: AccountId) -> Result<Option<ProviderInfo<Runtime>>, String>;
    fn providers(&self) -> Result<Vec<(AccountId, ProviderInfo<Runtime>)>, String>;
    fn contract(
        &self,
        contract_id: u64,
    ) -> Result<Option<ArchiveContract<Runtime>>, String>;
    fn contracts(
        &self,
        provider: AccountId,
    ) -> Result<Vec<ArchiveContract<Runtime>>, String>;
}

#[rpc(server, client, namespace = "archive")]
pub trait ArchiveApi {
    /// List all archive providers.
    #[method(name = "listProviders")]
    async fn list_providers(&self) -> RpcResult<Vec<ArchiveProviderEntry>>;

    /// Fetch a single provider by account id (hex-encoded).
    #[method(name = "getProvider")]
    async fn get_provider(&self, provider: String) -> RpcResult<Option<ArchiveProviderEntry>>;

    /// Return the number of registered providers.
    #[method(name = "providerCount")]
    async fn provider_count(&self) -> RpcResult<u32>;

    /// List contracts for a provider (hex-encoded).
    #[method(name = "listContracts")]
    async fn list_contracts(&self, provider: String) -> RpcResult<Vec<ArchiveContractEntry>>;

    /// Fetch a single contract by id.
    #[method(name = "getContract")]
    async fn get_contract(&self, contract_id: u64) -> RpcResult<Option<ArchiveContractEntry>>;
}

pub struct ArchiveRpc<S> {
    service: Arc<S>,
}

impl<S> ArchiveRpc<S>
where
    S: ArchiveMarketService + Send + Sync + 'static,
{
    pub fn new(service: Arc<S>) -> Self {
        Self { service }
    }
}

#[jsonrpsee::core::async_trait]
impl<S> ArchiveApiServer for ArchiveRpc<S>
where
    S: ArchiveMarketService + Send + Sync + 'static,
{
    async fn list_providers(&self) -> RpcResult<Vec<ArchiveProviderEntry>> {
        let providers = self
            .service
            .providers()
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;

        Ok(providers
            .into_iter()
            .map(|(provider, info)| to_entry(provider, info))
            .collect())
    }

    async fn get_provider(&self, provider: String) -> RpcResult<Option<ArchiveProviderEntry>> {
        let provider_id = parse_account_id(&provider)?;
        let info = self
            .service
            .provider(provider_id.clone())
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;

        Ok(info.map(|info| to_entry(provider_id, info)))
    }

    async fn provider_count(&self) -> RpcResult<u32> {
        self.service
            .provider_count()
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))
    }

    async fn list_contracts(&self, provider: String) -> RpcResult<Vec<ArchiveContractEntry>> {
        let provider_id = parse_account_id(&provider)?;
        let contracts = self
            .service
            .contracts(provider_id)
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;

        Ok(contracts
            .into_iter()
            .map(to_contract_entry)
            .collect())
    }

    async fn get_contract(&self, contract_id: u64) -> RpcResult<Option<ArchiveContractEntry>> {
        let contract = self
            .service
            .contract(contract_id)
            .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
        Ok(contract.map(to_contract_entry))
    }
}

fn to_entry(provider: AccountId, info: ProviderInfo<Runtime>) -> ArchiveProviderEntry {
    let endpoint_bytes = info.endpoint.into_inner();
    let endpoint = String::from_utf8(endpoint_bytes.clone())
        .unwrap_or_else(|_| format!("0x{}", hex::encode(endpoint_bytes)));

    ArchiveProviderEntry {
        provider: format!("0x{}", hex::encode(provider.as_ref())),
        bond: info.bond,
        price_per_byte_block: info.price_per_byte_block,
        min_duration_blocks: info.min_duration_blocks,
        endpoint,
    }
}

fn to_contract_entry(contract: ArchiveContract<Runtime>) -> ArchiveContractEntry {
    let status = match contract.status {
        ContractStatus::Active => ArchiveContractStatus::Active,
        ContractStatus::Failed => ArchiveContractStatus::Failed,
    };
    ArchiveContractEntry {
        contract_id: contract.contract_id,
        buyer: format!("0x{}", hex::encode(contract.buyer.as_ref())),
        provider: format!("0x{}", hex::encode(contract.provider.as_ref())),
        start_block: contract.start_block,
        end_block: contract.end_block,
        retention_blocks: contract.retention_blocks,
        expires_at: contract.expires_at,
        byte_count: contract.byte_count,
        price_per_byte_block: contract.price_per_byte_block,
        total_cost: contract.total_cost,
        bond_stake: contract.bond_stake,
        created_at: contract.created_at,
        status,
    }
}

fn parse_account_id(value: &str) -> Result<AccountId, ErrorObjectOwned> {
    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("invalid hex: {err}"),
            None::<()>,
        )
    })?;

    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("expected 32-byte account id, got {}", bytes.len()),
            None::<()>,
        ));
    }

    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    Ok(AccountId::from(raw))
}
