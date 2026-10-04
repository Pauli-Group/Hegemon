//! Lightweight public-binding/field-lowering checks. These integration tests
//! build the existing source facade without enabling its historical unit tests.
use hegemon_isolated_htlc_smallwood::hashlock_claim::{
    self as claim, ClaimAdapter, ClaimStatement, CLAIM_VERSION,
};
use sha2::{Digest, Sha256};

#[test]
fn verifier_construction_requires_only_public_statement() {
    let statement = ClaimStatement {
        version: CLAIM_VERSION,
        digest: Sha256::digest([3; 32]).into(),
        context: vec![0, 1, 2],
    };
    let a = ClaimAdapter::from_statement(&statement).unwrap();
    assert_eq!(a.geometry().total_rows, 4159);
    assert_eq!(a.geometry().maximum_degree, 3);
    assert_eq!(a.geometry().private_input_pins, 0);
    let binding = claim::binding_bytes(&statement).unwrap();
    assert_eq!(binding.len() % 8, 0);
    for change in 0..3 {
        let mut other = statement.clone();
        match change {
            0 => other.digest[0] ^= 1,
            1 => other.context.push(0),
            _ => other.context[0] ^= 1,
        }
        assert_ne!(binding, claim::binding_bytes(&other).unwrap());
    }
    let mut other = statement.clone();
    other.version += 1;
    assert!(claim::binding_bytes(&other).is_err());
    assert!(ClaimAdapter::from_statement(&other).is_err());
    let mut other = statement;
    other.context.resize(4097, 0);
    assert!(claim::binding_bytes(&other).is_err());
}
