//! A quorum certificate authenticates a scheduled signer replacement. It is
//! insufficient to activate rules: the adopting node must separately supply
//! the compiled fork identity both when scheduling and at activation. Unknown
//! certificates must never give signers a future chain-halt power.
use crate::*;
use codec::{Decode, Encode};
use crypto::hash384::RulesHash48;

/// Hash of the reserved, versioned authorization policy that looks up the
/// current protocol treasury committee. It is independent of committee keys;
/// binary address network tags distinguish networks with this same script.
pub fn protocol_treasury_account_id() -> AccountPolicyId48 {
    AccountPolicyId48::new(hash48(
        b"hegemon.reward-account.protocol-authorization-policy.v1",
        b"fixed-treasury/current-genesis-or-certified-hard-fork-committee",
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TreasuryForkIntent {
    pub context: AccountChainContext,
    pub current_generation: u64,
    pub activation_height: u64,
    pub successor_rules: RulesHash48,
    pub successor_policy: AccountPolicy,
}
impl TreasuryForkIntent {
    pub fn authorization_digest(&self) -> [u8; 48] {
        hash48(b"hegemon.treasury.hard-fork-certificate.v1", &self.encode())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TreasuryForkCertificate {
    pub intent: TreasuryForkIntent,
    pub approvals: BoundedVec<AccountApproval, MAX_ACCOUNT_SIGNERS>,
}

/// Constructed from the adopting software's compiled fork schedule, never
/// from an untrusted certificate, RPC parameter or mutable network config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTreasuryFork {
    pub activation_height: u64,
    pub successor_rules: RulesHash48,
    pub successor_policy: AccountPolicyId48,
}
