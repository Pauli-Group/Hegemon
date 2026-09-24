//! Exact wallet-owned carriers for the retained positive-value V8 lifecycle.
//!
//! These bytes are test/release evidence only. They do not authorize either
//! action 10 or action 11 and are never consulted by consensus validity.

#![forbid(unsafe_code)]

use crate::poseidon2_v8_coinbase::{
    Poseidon2V8CoinbaseNoteOpening, POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES,
    POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
};

pub const RETAINED_V8_COINBASE_0_SCALE: &[u8; POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES] =
    include_bytes!("../test-vectors/poseidon2_v8_retained/coinbase_0.scale");
pub const RETAINED_V8_COINBASE_1_SCALE: &[u8; POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES] =
    include_bytes!("../test-vectors/poseidon2_v8_retained/coinbase_1.scale");
pub const RETAINED_V8_OUTPUT_0_RAW: &[u8; POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES] =
    include_bytes!("../test-vectors/poseidon2_v8_retained/output_0.raw");
pub const RETAINED_V8_OUTPUT_1_RAW: &[u8; POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES] =
    include_bytes!("../test-vectors/poseidon2_v8_retained/output_1.raw");

/// Exact private openings recovered by the retained wallet builder from the
/// two public output ciphertext carriers. They are vectors, never consensus
/// authority.
pub const RETAINED_V8_OUTPUT_OPENINGS: [Poseidon2V8CoinbaseNoteOpening; 2] = [
    Poseidon2V8CoinbaseNoteOpening {
        value: 499_429_223,
        asset_id: 0,
        recipient_key: [
            14_132_942_956_216_209_493,
            7_685_267_610_787_277_800,
            16_563_171_182_421_170_277,
            17_300_113_818_709_955_652,
        ],
        authorization_key: [
            1_741_146_651_100_274_088,
            9_539_478_460_468_656_252,
            7_097_725_263_314_205_436,
            1_436_916_868_072_586_276,
        ],
        rho: [
            8_460_803_422_008_399_631,
            580_471_469_097_181_722,
            15_982_347_602_180_612_085,
            547_882_540_585_853_547,
        ],
        randomness: [
            1_754_816_846_831_268_925,
            3_356_685_173_151_501_607,
            4_523_828_679_424_895_879,
            10_333_239_576_993_045_621,
        ],
    },
    Poseidon2V8CoinbaseNoteOpening {
        value: 499_429_223,
        asset_id: 0,
        recipient_key: [
            14_132_942_956_216_209_493,
            7_685_267_610_787_277_800,
            16_563_171_182_421_170_277,
            17_300_113_818_709_955_652,
        ],
        authorization_key: [
            1_741_146_651_100_274_088,
            9_539_478_460_468_656_252,
            7_097_725_263_314_205_436,
            1_436_916_868_072_586_276,
        ],
        rho: [
            13_686_641_653_694_575_410,
            18_028_614_499_108_587_011,
            15_680_976_473_712_613_592,
            5_789_072_406_834_315_374,
        ],
        randomness: [
            7_937_814_101_332_040_661,
            2_083_783_752_441_714_509,
            2_932_697_315_522_233_358,
            5_822_396_724_259_220_524,
        ],
    },
];

pub const RETAINED_V8_COINBASE_0_SHA512: &str = concat!(
    "fe367d01fca30b2571315e3bd75d49a2a3aff8fdd248019760a522bf98bf3c7f",
    "0ecb2115d119a345b6ed08699fd492788d69bc77dee690390d8a4551f80471ed"
);
pub const RETAINED_V8_COINBASE_1_SHA512: &str = concat!(
    "f6ebbd0bfc18b24949dd75dbab49b5be9b33d8f7c0a4d75a4947c6c699cf53d",
    "37bfb7aeb3e76b5b2b4390a9f51a68162fd4e6b1e9a6e97f2d78c8680e3abdab4"
);
pub const RETAINED_V8_OUTPUT_0_SHA512: &str = concat!(
    "7e4ded0179dffaf0f6d75249ebff03cd4a3b70a8c2b9f4c2caddcf48ea3ddf8e",
    "b72c54878191eae91ced58938c4e53ff6ab628519ac9788453ede495053b61b3"
);
pub const RETAINED_V8_OUTPUT_1_SHA512: &str = concat!(
    "7cee8c17f7581cacade29ed15534449b65b1e29e7fffa764400902b5af86dbdd8",
    "ac8b086a8af9804627d39ca50102e822f074689088abcda517cf4ceec35a01b"
);

pub const RETAINED_V8_STATEMENT_SHA512: &str = concat!(
    "5364e28a4dcc2087db4a56cb52a761f411fd49acd203d52da2a0ee6f1970f0ac",
    "a2f846c378eec33c9a748dc12a3f9b2edab45f12e678326962abec0aeed877a3"
);
pub const RETAINED_V8_WITNESS_SHA512: &str = concat!(
    "8e77fc538021936b7b0a1ac0e756a9df4e02b16f3053a9f5d52ff0a9a38f63ad",
    "569aca6459750e1b7b69a6a85b148392dbb05ee8cd43a0dbba1a57a2904a7a8c"
);
pub const RETAINED_V8_INLINE_CIPHERTEXT_SHA512: &str = concat!(
    "eeb7dd2b0e780317df7ef5a38d916512fad1d5be190fa647dc4822d965e9a2789",
    "2fd097f8800013df6f2f0cfb4f7a2e84c514377ae04d1705272611a23375ce4"
);

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};
    use sha2::{Digest, Sha512};

    use crate::poseidon2_v8_coinbase::MintPoseidon2V8CoinbaseArgs;

    fn assert_sha512(bytes: &[u8], expected: &str) {
        assert_eq!(hex::encode(Sha512::digest(bytes)), expected);
    }

    #[test]
    fn retained_wallet_carriers_are_exact_and_canonical() {
        for (bytes, digest) in [
            (
                RETAINED_V8_COINBASE_0_SCALE.as_slice(),
                RETAINED_V8_COINBASE_0_SHA512,
            ),
            (
                RETAINED_V8_COINBASE_1_SCALE.as_slice(),
                RETAINED_V8_COINBASE_1_SHA512,
            ),
        ] {
            assert_sha512(bytes, digest);
            let mut cursor = bytes;
            let decoded = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor).unwrap();
            assert!(cursor.is_empty());
            assert_eq!(decoded.encode(), bytes);
        }
        for (bytes, digest) in [
            (
                RETAINED_V8_OUTPUT_0_RAW.as_slice(),
                RETAINED_V8_OUTPUT_0_SHA512,
            ),
            (
                RETAINED_V8_OUTPUT_1_RAW.as_slice(),
                RETAINED_V8_OUTPUT_1_SHA512,
            ),
        ] {
            assert_sha512(bytes, digest);
            assert_eq!(bytes[0], 4);
            assert_eq!(
                u16::from_le_bytes(bytes[1..3].try_into().unwrap()),
                protocol_versioning::CRYPTO_SUITE_ETA
            );
            assert_eq!(u32::from_le_bytes(bytes[3..7].try_into().unwrap()), 9);
        }
    }
}
