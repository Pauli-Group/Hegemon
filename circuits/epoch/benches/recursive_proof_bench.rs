use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use epoch_circuit::BaseElement;
use epoch_circuit::{compute_proof_root, recursion::rpo_merge, Epoch, RecursiveEpochProver};

fn hash_to_elements(hash: &[u8; 32]) -> [BaseElement; 4] {
    let mut elements = [BaseElement::new(0); 4];
    for (i, chunk) in hash.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        elements[i] = BaseElement::new(u64::from_le_bytes(buf));
    }
    elements
}

fn make_hashes(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            h[8..16].copy_from_slice(&(i as u64).wrapping_mul(17).to_le_bytes());
            h[16..24].copy_from_slice(&(i as u64).wrapping_mul(31).to_le_bytes());
            h[24..32].copy_from_slice(&(i as u64).wrapping_mul(97).to_le_bytes());
            h
        })
        .collect()
}

fn make_epoch(epoch_number: u64, proof_hashes: &[[u8; 32]]) -> Epoch {
    let mut epoch = Epoch::new(epoch_number);
    epoch.proof_root = compute_proof_root(proof_hashes);
    epoch.state_root = [2u8; 32];
    epoch.nullifier_set_root = [3u8; 32];
    epoch.commitment_tree_root = [4u8; 32];
    epoch
}

fn bench_recursive_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("recursive_epoch_proofs");
    group.sample_size(10);

    for &n in &[100usize, 500, 1000] {
        let hashes = make_hashes(n);
        let epoch = make_epoch(0, &hashes);

        group.bench_with_input(
            BenchmarkId::new("compute_accumulator", n),
            &hashes,
            |b, hashes| {
                b.iter(|| {
                    let mut acc = [BaseElement::new(0); 4];
                    for h in hashes {
                        let elems = hash_to_elements(h);
                        acc = rpo_merge(&acc, &elems);
                    }
                    acc
                })
            },
        );

        let prover = RecursiveEpochProver::fast();
        group.bench_with_input(
            BenchmarkId::new("prove_epoch_inner", n),
            &hashes,
            |b, hashes| b.iter(|| prover.prove_epoch(&epoch, hashes).unwrap()),
        );
    }

    // The full proof-of-proof recursion is significantly heavier; keep sampling low.
    // Criterion enforces a minimum sample size of 10, so we stay at that floor.
    group.sample_size(10);
    let hashes = make_hashes(1000);
    let epoch = make_epoch(0, &hashes);
    let prover = RecursiveEpochProver::fast();
    group.bench_function("prove_epoch_recursive_outer", |b| {
        b.iter(|| prover.prove_epoch_recursive(&epoch, &hashes).unwrap())
    });

    group.finish();
}

criterion_group!(benches, bench_recursive_proofs);
criterion_main!(benches);
