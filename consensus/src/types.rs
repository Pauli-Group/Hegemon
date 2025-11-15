use crypto::hashes::sha256;
use sha2::{Digest, Sha384};

pub type Nullifier = [u8; 32];
pub type Commitment = [u8; 32];
pub type BalanceTag = [u8; 32];
pub type FeeCommitment = [u8; 32];
pub type ValidatorSetCommitment = [u8; 32];
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];
pub type StarkCommitment = [u8; 48];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub id: BlockHash,
    pub nullifiers: Vec<Nullifier>,
    pub commitments: Vec<Commitment>,
    pub balance_tag: BalanceTag,
}

impl Transaction {
    pub fn new(
        nullifiers: Vec<Nullifier>,
        commitments: Vec<Commitment>,
        balance_tag: BalanceTag,
    ) -> Self {
        let id = compute_transaction_id(&nullifiers, &commitments, &balance_tag);
        Self {
            id,
            nullifiers,
            commitments,
            balance_tag,
        }
    }

    pub fn hash(&self) -> BlockHash {
        compute_transaction_id(&self.nullifiers, &self.commitments, &self.balance_tag)
    }
}

fn compute_transaction_id(
    nullifiers: &[Nullifier],
    commitments: &[Commitment],
    balance_tag: &BalanceTag,
) -> BlockHash {
    let mut hasher = Sha384::new();
    for nf in nullifiers {
        hasher.update(nf);
    }
    for cm in commitments {
        hasher.update(cm);
    }
    hasher.update(balance_tag);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha256(digest.as_slice()));
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<BH> {
    pub header: BH,
    pub transactions: Vec<Transaction>,
}

impl<BH> Block<BH> {
    pub fn map_header<T>(self, header: T) -> Block<T> {
        Block {
            header,
            transactions: self.transactions,
        }
    }
}

pub type ConsensusBlock = Block<crate::header::BlockHeader>;

pub fn compute_fee_commitment(transactions: &[Transaction]) -> FeeCommitment {
    let mut tags: Vec<BalanceTag> = transactions.iter().map(|tx| tx.balance_tag).collect();
    tags.sort_unstable();
    let mut data = Vec::with_capacity(tags.len() * BalanceTag::default().len());
    for tag in tags {
        data.extend_from_slice(&tag);
    }
    sha256(&data)
}

pub fn compute_proof_commitment(transactions: &[Transaction]) -> StarkCommitment {
    let mut hasher = Sha384::new();
    for tx in transactions {
        hasher.update(tx.hash());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_id_is_deterministic() {
        let tx = Transaction::new(vec![[1u8; 32]], vec![[2u8; 32]], [3u8; 32]);
        assert_eq!(tx.hash(), tx.id);
    }

    #[test]
    fn fee_commitment_sorted() {
        let tx_a = Transaction::new(vec![[1u8; 32]], vec![], [3u8; 32]);
        let tx_b = Transaction::new(vec![[2u8; 32]], vec![], [1u8; 32]);
        let tag = compute_fee_commitment(&[tx_a.clone(), tx_b.clone()]);
        let tag_swapped = compute_fee_commitment(&[tx_b, tx_a]);
        assert_eq!(tag, tag_swapped);
    }

    #[test]
    fn proof_commitment_depends_on_transaction_order() {
        let tx_a = Transaction::new(vec![[1u8; 32]], vec![], [3u8; 32]);
        let tx_b = Transaction::new(vec![[2u8; 32]], vec![], [4u8; 32]);
        let commitment = compute_proof_commitment(&[tx_a.clone(), tx_b.clone()]);
        let commitment_swapped = compute_proof_commitment(&[tx_b, tx_a]);
        assert_ne!(commitment, commitment_swapped);
    }
}
