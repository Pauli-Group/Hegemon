//! Fixed, transparent demonstration of the B128-lane/E384 IOP seam.
//!
//! This binary is a protocol KAT. It transmits the full coefficient-lane table
//! and therefore makes no PCS, hiding, zero-knowledge, PQ, or production claim.

use hegemon_strict_mixed_field_prototype::{
    B128, prove_toy_mixed_sumcheck, verify_toy_mixed_sumcheck_exact,
};

fn main() {
    let codeword = [
        B128::new(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
        B128::new(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210),
        B128::new(0xdead_beef),
        B128::ONE,
    ];
    let context = b"hegemon-strict-mixed-field-toy-v1";
    let proved = prove_toy_mixed_sumcheck(&codeword, context).expect("fixed toy proving succeeds");
    let (encoded, counters) = proved
        .proof
        .encode_counted()
        .expect("fixed toy serialization succeeds");
    let verified = verify_toy_mixed_sumcheck_exact(&encoded, proved.public_claim, context)
        .expect("fixed toy verification succeeds");
    assert_eq!(verified.challenges, proved.challenges);
    assert_eq!(verified.transcript_digest, proved.transcript_digest);

    println!(
        "research_only=true proof_bytes={} fixed_bytes={} b128_symbols={} explicit_e384_claims={} roots={} rounds={} public_claim={}",
        encoded.len(),
        counters.fixed_bytes,
        counters.base_symbol_elements,
        counters.explicit_wide_elements,
        counters.merkle_root_count,
        proved.challenges.len(),
        proved.public_claim,
    );
}
