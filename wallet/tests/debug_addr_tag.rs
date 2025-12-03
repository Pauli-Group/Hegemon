use wallet::address::ShieldedAddress;
use wallet::keys::RootSecret;
use wallet::viewing::IncomingViewingKey;

#[test]
fn test_addr_tag_derivation_consistency() {
    use rand::{rngs::StdRng, SeedableRng};
    
    // Create wallet from a specific seed
    let mut rng = StdRng::seed_from_u64(12345);
    let root = RootSecret::from_rng(&mut rng);
    let derived = root.derive();
    
    // Create IVK from the same derived keys
    let ivk = IncomingViewingKey::from_keys(&derived);
    
    // Get address material from DerivedKeys directly
    let material_from_keys = derived.address(0).unwrap();
    let addr_from_keys = material_from_keys.shielded_address();
    
    // Get address material from IVK
    let material_from_ivk = ivk.address_material(0).unwrap();
    let addr_from_ivk = material_from_ivk.shielded_address();
    
    println!("From DerivedKeys:");
    println!("  addr_tag: {}", hex::encode(&addr_from_keys.address_tag));
    println!("  pk_recipient: {}", hex::encode(&addr_from_keys.pk_recipient));
    
    println!("\nFrom IVK:");
    println!("  addr_tag: {}", hex::encode(&addr_from_ivk.address_tag));
    println!("  pk_recipient: {}", hex::encode(&addr_from_ivk.pk_recipient));
    
    println!("\nAddresses match: {}", addr_from_keys == addr_from_ivk);
    
    // Now encode and decode the address
    let encoded = addr_from_keys.encode().unwrap();
    let decoded = ShieldedAddress::decode(&encoded).unwrap();
    
    println!("\nAfter encode/decode:");
    println!("  addr_tag: {}", hex::encode(&decoded.address_tag));
    println!("  pk_recipient: {}", hex::encode(&decoded.pk_recipient));
    
    println!("\nOriginal == Decoded: {}", addr_from_keys == decoded);
    
    // Now check if IVK's address_material gives the same addr_tag
    // when using the DECODED diversifier_index
    let re_derived = ivk.address_material(decoded.diversifier_index).unwrap();
    
    println!("\nRe-derived from IVK (index={}):", decoded.diversifier_index);
    println!("  addr_tag: {}", hex::encode(&re_derived.addr_tag));
    println!("  pk_recipient: {}", hex::encode(&re_derived.pk_recipient));
    
    println!("\nRe-derived addr_tag == decoded.address_tag: {}", re_derived.addr_tag == decoded.address_tag);
    
    assert_eq!(addr_from_keys, decoded, "Encode/decode should be lossless");
    assert_eq!(re_derived.addr_tag, decoded.address_tag, "Re-derived addr_tag should match encoded");
}
