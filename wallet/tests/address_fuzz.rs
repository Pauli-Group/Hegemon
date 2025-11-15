use proptest::prelude::*;
use wallet::{RootSecret, ShieldedAddress};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    fn bech32_roundtrip(seed in prop::array::uniform32(any::<u8>()), index in any::<u32>()) {
        let root = RootSecret::from_bytes(seed);
        let keys = root.derive();
        let address = keys.address(index).expect("address").shielded_address();
        let encoded = address.encode().expect("encode");
        let decoded = ShieldedAddress::decode(&encoded).expect("decode");
        prop_assert_eq!(decoded, address);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    fn tampering_changes_checksum(seed in prop::array::uniform32(any::<u8>()), index in any::<u32>(), flip in any::<usize>()) {
        let root = RootSecret::from_bytes(seed);
        let keys = root.derive();
        let address = keys.address(index).expect("address").shielded_address();
        let mut bytes = address.encode().expect("encode").into_bytes();
        let idx = flip % bytes.len();
        bytes[idx] = bytes[idx].wrapping_add(1);
        let mutated = String::from_utf8(bytes).expect("utf8");
        let result = ShieldedAddress::decode(&mutated);
        prop_assert!(result.is_err());
    }
}
