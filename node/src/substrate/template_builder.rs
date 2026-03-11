use consensus::MiningWork;
use serde::{Deserialize, Serialize};
use sp_core::{hashing::blake2_256, H256};

/// Compact miner-facing job derived from the current block template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactMiningJob {
    pub job_id: [u8; 32],
    pub height: u64,
    pub pre_hash: H256,
    pub parent_hash: H256,
    pub network_bits: u32,
    pub share_bits: u32,
}

pub fn job_id_for_work(work: &MiningWork, share_bits: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 + 32 + 8 + 4 + 4);
    bytes.extend_from_slice(work.pre_hash.as_bytes());
    bytes.extend_from_slice(work.parent_hash.as_bytes());
    bytes.extend_from_slice(&work.height.to_le_bytes());
    bytes.extend_from_slice(&work.pow_bits.to_le_bytes());
    bytes.extend_from_slice(&share_bits.to_le_bytes());
    blake2_256(&bytes)
}

pub fn compact_job_from_work(work: &MiningWork, share_bits: u32) -> CompactMiningJob {
    CompactMiningJob {
        job_id: job_id_for_work(work, share_bits),
        height: work.height,
        pre_hash: work.pre_hash,
        parent_hash: work.parent_hash,
        network_bits: work.pow_bits,
        share_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_work() -> MiningWork {
        MiningWork {
            pre_hash: H256::repeat_byte(0x11),
            pow_bits: 0x207fffff,
            height: 42,
            parent_hash: H256::repeat_byte(0x22),
        }
    }

    #[test]
    fn compact_job_derivation_is_deterministic() {
        let work = sample_work();
        assert_eq!(
            compact_job_from_work(&work, work.pow_bits),
            compact_job_from_work(&work, work.pow_bits)
        );
    }

    #[test]
    fn compact_job_id_changes_with_share_target() {
        let work = sample_work();
        let default_job = compact_job_from_work(&work, work.pow_bits);
        let easier_job = compact_job_from_work(&work, 0x2100ffff);
        assert_ne!(default_job.job_id, easier_job.job_id);
    }
}
