//! Reproducible release benchmark for the V3 consensus-hash decision.
//!
//! Run with:
//! `cargo run --release -p hegemon-hash384 --example consensus_hash_bench`.

use hegemon_hash384::{
    blake2b_384, HeaderPrecommit48, PowWorkContextV3, POW_WORK_TRANSCRIPT_BYTES_V3,
};
use sha2::{Digest as _, Sha256, Sha384};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_384, Shake256,
};
use std::{hint::black_box, time::Instant};

const SAMPLES: usize = 7;
const HEADER_BYTES: usize = 772;
const ACTION_BYTES: usize = 128_984;
const BODY_BYTES: usize = 67_074_197;
const MMR_LEAVES: usize = 520;
const POW_ATTEMPTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug)]
enum Candidate {
    Blake2b384,
    Sha384,
    Sha3_384,
    Shake256_384,
}

impl Candidate {
    const ALL: [Self; 4] = [
        Self::Blake2b384,
        Self::Sha384,
        Self::Sha3_384,
        Self::Shake256_384,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Blake2b384 => "BLAKE2b-384",
            Self::Sha384 => "SHA-384",
            Self::Sha3_384 => "SHA3-384",
            Self::Shake256_384 => "SHAKE256-384",
        }
    }
}

fn main() {
    println!(
        "hegemon consensus hash benchmark; release={}",
        !cfg!(debug_assertions)
    );
    println!("samples={SAMPLES}");
    println!("workload,candidate,median_ns_per_operation");

    let header = deterministic_bytes(HEADER_BYTES);
    let action = deterministic_bytes(ACTION_BYTES);
    let body = deterministic_bytes(BODY_BYTES);

    for candidate in Candidate::ALL {
        report_bytes("header-772B", candidate, &header, 100_000);
        report_bytes("action-128984B", candidate, &action, 100);
        report_mmr(candidate, 20);
        report_bytes("body-67074197B", candidate, &body, 1);
    }

    report_pow();
}

fn report_bytes(name: &str, candidate: Candidate, input: &[u8], iterations: usize) {
    let median = median_ns_per_operation(iterations, || {
        black_box(hash(candidate, black_box(input)));
    });
    println!("{name},{},{median:.2}", candidate.name());
}

fn report_mmr(candidate: Candidate, iterations: usize) {
    let median = median_ns_per_operation(iterations, || {
        black_box(mmr_root(candidate));
    });
    println!("mmr-520-leaves,{},{median:.2}", candidate.name());
}

fn report_pow() {
    let precommit = HeaderPrecommit48::new([0x42; 48]);
    let context = PowWorkContextV3::new(precommit);
    let sha_pre_hash = [0x42; 32];

    let sha256d = median_ns_per_indexed_operation(POW_ATTEMPTS, |attempt| {
        let nonce = nonce(attempt);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&sha_pre_hash);
        input[32..].copy_from_slice(&nonce);
        let first = Sha256::digest(input);
        black_box(Sha256::digest(first));
    });
    let blake2b = median_ns_per_indexed_operation(POW_ATTEMPTS, |attempt| {
        black_box(context.hash_nonce(nonce(attempt)));
    });

    println!("pow-current-sha256d-64B,SHA256d,{sha256d:.2}");
    println!(
        "pow-v3-{}B,BLAKE2b-384,{blake2b:.2}",
        POW_WORK_TRANSCRIPT_BYTES_V3
    );
    println!("pow-v3-speedup-over-current,{:.2}x", sha256d / blake2b);
}

fn median_ns_per_operation(iterations: usize, mut operation: impl FnMut()) -> f64 {
    assert!(iterations > 0);
    let mut samples = [0f64; SAMPLES];
    for sample in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        *sample = start.elapsed().as_nanos() as f64 / iterations as f64;
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

fn median_ns_per_indexed_operation(iterations: usize, mut operation: impl FnMut(usize)) -> f64 {
    let mut samples = [0f64; SAMPLES];
    for sample in &mut samples {
        let start = Instant::now();
        for index in 0..iterations {
            operation(black_box(index));
        }
        *sample = start.elapsed().as_nanos() as f64 / iterations as f64;
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

fn nonce(attempt: usize) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&(attempt as u64).to_le_bytes());
    nonce
}

fn deterministic_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(131).wrapping_add(17))
        .collect()
}

fn hash(candidate: Candidate, input: &[u8]) -> [u8; 48] {
    match candidate {
        Candidate::Blake2b384 => blake2b_384(input),
        Candidate::Sha384 => Sha384::digest(input).into(),
        Candidate::Sha3_384 => Sha3_384::digest(input).into(),
        Candidate::Shake256_384 => {
            let mut hasher = Shake256::default();
            Update::update(&mut hasher, input);
            let mut reader = hasher.finalize_xof();
            let mut output = [0u8; 48];
            reader.read(&mut output);
            output
        }
    }
}

fn mmr_root(candidate: Candidate) -> [u8; 48] {
    let mut level = Vec::with_capacity(MMR_LEAVES);
    for index in 0..MMR_LEAVES {
        let mut leaf = [0u8; 52];
        leaf[..4].copy_from_slice(&(index as u32).to_le_bytes());
        leaf[4..].fill((index as u8).wrapping_mul(17));
        level.push(hash(candidate, &leaf));
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                let mut node = [0u8; 96];
                node[..48].copy_from_slice(&pair[0]);
                node[48..].copy_from_slice(&pair[1]);
                next.push(hash(candidate, &node));
            }
        }
        level = next;
    }
    level[0]
}
