use codec::Encode;
use state_da::{encode_da_blob, sample_indices, DaParams};
use std::hint::black_box;
use std::time::Instant;

const SAMPLE_COUNT: u32 = 4;
const FIXTURE_CIPHERTEXT_BYTES: usize = 579 + 32;

fn native_blob(tx_count: usize, ciphertext_bytes: usize) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4usize.saturating_add(tx_count.saturating_mul(
        4usize.saturating_add(2usize.saturating_mul(4usize.saturating_add(ciphertext_bytes))),
    )));
    blob.extend_from_slice(&(tx_count as u32).to_le_bytes());
    for tx_index in 0..tx_count {
        blob.extend_from_slice(&2u32.to_le_bytes());
        for output_index in 0..2usize {
            blob.extend_from_slice(&(ciphertext_bytes as u32).to_le_bytes());
            let tag = (tx_index.wrapping_mul(2).wrapping_add(output_index) & 0xff) as u8;
            blob.resize(blob.len().saturating_add(ciphertext_bytes), tag);
        }
    }
    blob
}

fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() {
    let repetitions = std::env::args()
        .nth(1)
        .map(|raw| raw.parse::<usize>().expect("repetitions"))
        .unwrap_or(25);
    let ciphertext_bytes = std::env::args()
        .nth(2)
        .map(|raw| raw.parse::<usize>().expect("ciphertext bytes"))
        .unwrap_or(FIXTURE_CIPHERTEXT_BYTES);
    let target_tx_count = std::env::args()
        .nth(3)
        .map(|raw| raw.parse::<usize>().expect("target transaction count"));
    assert!(repetitions > 0);

    println!(
        "tx_count,ciphertext_bytes,chunk_bytes,blob_bytes,status,data_shards,parity_shards,total_shards,allocation_bytes,sample_payload_bytes,sample_proof_wire_bytes,median_encode_root_ns"
    );
    let tx_counts = target_tx_count.map_or_else(
        || vec![1usize, 40, 41, 141, 161, 162, 500, 515, 520, 537, 564, 646],
        |tx_count| vec![tx_count],
    );
    for tx_count in tx_counts {
        let blob = native_blob(tx_count, ciphertext_bytes);
        for chunk_size in [1_024u32, 4_096u32, 16_384u32] {
            let params = DaParams {
                chunk_size,
                sample_count: SAMPLE_COUNT,
            };
            let warm = encode_da_blob(&blob, params);
            let Ok(warm) = warm else {
                let started = Instant::now();
                for _ in 0..repetitions {
                    black_box(encode_da_blob(black_box(&blob), params).expect_err("must reject"));
                }
                let ns = started.elapsed().as_nanos() / repetitions as u128;
                println!(
                    "{tx_count},{ciphertext_bytes},{chunk_size},{},rejected,0,0,0,0,0,0,{ns}",
                    blob.len()
                );
                continue;
            };

            let total_shards = warm.chunks().len();
            let data_shards = usize::try_from(warm.data_shards()).expect("data shard count");
            let parity_shards = usize::try_from(warm.parity_shards()).expect("parity shard count");
            let allocation_bytes = total_shards.saturating_mul(chunk_size as usize);
            let sampled = sample_indices(
                [0x11; 32],
                [0x22; 32],
                u32::try_from(total_shards).expect("total shard count"),
                SAMPLE_COUNT,
            );
            let sample_payload_bytes = sampled.len().saturating_mul(chunk_size as usize);
            let sample_proof_wire_bytes = sampled
                .iter()
                .map(|index| warm.proof(*index).expect("sample proof").encode().len())
                .sum::<usize>();

            let mut elapsed = Vec::with_capacity(repetitions);
            for _ in 0..repetitions {
                let started = Instant::now();
                let encoded = encode_da_blob(black_box(&blob), params).expect("DA encode");
                black_box(encoded.root());
                elapsed.push(started.elapsed().as_nanos());
            }
            let median_ns = median(&mut elapsed);
            println!(
                "{tx_count},{ciphertext_bytes},{chunk_size},{},ok,{data_shards},{parity_shards},{total_shards},{allocation_bytes},{sample_payload_bytes},{sample_proof_wire_bytes},{median_ns}",
                blob.len()
            );
        }
    }
}
