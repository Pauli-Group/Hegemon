//! Executable geometry contract for the prospective full M4 circuit.
//!
//! This does not prove or benchmark anything. Raw circuit construction remains
//! private so it cannot bypass the composed statement/derived-intent binding.

#![forbid(unsafe_code)]

const PUBLIC_BYTES: usize = 853;
const STATEMENT_WORDS: usize = 107;
const DERIVED_INTENT_WORDS: usize = 7;
const PUBLIC_WORDS: usize = STATEMENT_WORDS + DERIVED_INTENT_WORDS;
const PRIVATE_WORDS: usize = 671;
const INPUT_WORDS: usize = 261;
const OUTPUT_WORDS: usize = 30;
const AUTH_WORDS: usize = 89;
const KECCAK_ANDS_PER_PERMUTATION: usize = 24 * 5 * 5 * 64;

#[derive(Clone, Copy)]
struct ShakeRole {
    name: &'static str,
    frame_bytes: usize,
    output_bytes: usize,
    permutations: usize,
    instances: usize,
}

const COMMON_ROLES: [ShakeRole; 4] = [
    ShakeRole {
        name: "note.cm3",
        frame_bytes: 232,
        output_bytes: 56,
        permutations: 2,
        instances: 4,
    },
    ShakeRole {
        name: "nullif.2",
        frame_bytes: 135,
        output_bytes: 56,
        permutations: 1,
        instances: 2,
    },
    ShakeRole {
        name: "merk.nd2",
        frame_bytes: 133,
        output_bytes: 56,
        permutations: 1,
        instances: 64,
    },
    ShakeRole {
        name: "sp.keys2",
        frame_bytes: 77,
        output_bytes: 112,
        permutations: 1,
        instances: 2,
    },
];

// Logical auth work after the common roles. A naive five-branch universal
// circuit allocates the sum. M4 instead one-hot multiplexes framed inputs into
// one seven-permutation schedule, with every unused lane constrained to its
// canonical dummy frame.
const AUTH_PERMUTATIONS_BY_MODE: [(&str, usize); 5] = [
    ("single", 0),
    ("accumulator_init", 5),
    ("approval", 7),
    ("value_lock_creation", 5),
    ("final", 7),
];

fn main() {
    assert_eq!(STATEMENT_WORDS, PUBLIC_BYTES.div_ceil(8));
    assert_eq!(PUBLIC_WORDS, 114);
    assert_eq!(
        PRIVATE_WORDS,
        INPUT_WORDS * 2 + OUTPUT_WORDS * 2 + AUTH_WORDS
    );

    let common_permutations: usize = COMMON_ROLES
        .iter()
        .map(|role| role.permutations * role.instances)
        .sum();
    assert_eq!(common_permutations, 76);
    let naive_auth_permutations: usize = AUTH_PERMUTATIONS_BY_MODE
        .iter()
        .map(|(_, permutations)| permutations)
        .sum();
    let multiplexed_auth_permutations = AUTH_PERMUTATIONS_BY_MODE
        .iter()
        .map(|(_, permutations)| *permutations)
        .max()
        .expect("five auth modes");
    assert_eq!(naive_auth_permutations, 24);
    assert_eq!(multiplexed_auth_permutations, 7);

    let naive_total = common_permutations + naive_auth_permutations;
    let multiplexed_total = common_permutations + multiplexed_auth_permutations;
    assert_eq!(naive_total, 100);
    assert_eq!(multiplexed_total, 83);
    let naive_shake_ands = naive_total * KECCAK_ANDS_PER_PERMUTATION;
    let multiplexed_shake_ands = multiplexed_total * KECCAK_ANDS_PER_PERMUTATION;
    assert_eq!(multiplexed_shake_ands, 3_187_200);
    assert_eq!(naive_shake_ands - multiplexed_shake_ands, 652_800);

    let max_common_frame = COMMON_ROLES
        .iter()
        .map(|role| role.frame_bytes)
        .max()
        .expect("common roles");
    assert_eq!(max_common_frame, 232);
    let max_frame = 385usize;
    assert!(COMMON_ROLES.iter().all(|role| !role.name.is_empty()));
    assert!(COMMON_ROLES.iter().all(|role| role.output_bytes <= 112));

    println!(
        "public_bytes={PUBLIC_BYTES} statement_words={STATEMENT_WORDS} derived_intent_words={DERIVED_INTENT_WORDS} public_words={PUBLIC_WORDS} private_words={PRIVATE_WORDS} \
         naive_keccak_f={naive_total} multiplexed_keccak_f={multiplexed_total} \
         multiplexed_shake_ands={multiplexed_shake_ands} saved_shake_ands={} max_frame={max_frame}",
        naive_shake_ands - multiplexed_shake_ands,
    );
}
