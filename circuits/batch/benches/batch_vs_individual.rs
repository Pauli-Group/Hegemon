//! Benchmark comparing batch proof verification vs individual proof verification.
//!
//! Run with: cargo bench -p batch-circuit
//!
//! This benchmark measures:
//! 1. Estimated proof sizes for batch vs individual
//! 2. Public input validation overhead
//! 3. Trace dimension calculations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

use batch_circuit::public_inputs::BatchPublicInputs;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::dimensions::{
    batch_trace_rows, commitment_output_row, estimated_proof_size, nullifier_output_row,
    TRACE_WIDTH,
};

/// Create mock batch public inputs for benchmarking
fn mock_batch_public_inputs(batch_size: u32) -> BatchPublicInputs {
    let mk_hash = |seed: u64| -> [BaseElement; 4] {
        [
            BaseElement::new(seed),
            BaseElement::new(seed + 1),
            BaseElement::new(seed + 2),
            BaseElement::new(seed + 3),
        ]
    };

    let nullifiers: Vec<[BaseElement; 4]> = (0..batch_size * 2)
        .map(|i| mk_hash(1000 + i as u64))
        .collect();
    let commitments: Vec<[BaseElement; 4]> = (0..batch_size * 2)
        .map(|i| mk_hash(2000 + i as u64))
        .collect();

    BatchPublicInputs {
        batch_size,
        anchor: mk_hash(12_345),
        nullifiers,
        commitments,
        total_fee: BaseElement::ZERO,
        circuit_version: 1,
    }
}

/// Print proof size comparison table
fn bench_proof_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size_comparison");

    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║                  PROOF SIZE COMPARISON                            ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!(
        "║ {:>6} │ {:>12} │ {:>12} │ {:>8} │ {:>10} ║",
        "Batch", "Batch Proof", "Individual", "Savings", "Trace Rows"
    );
    println!("╠════════╪══════════════╪══════════════╪══════════╪════════════╣");

    for batch_size in [1usize, 2, 4, 8, 16] {
        let batch_rows = batch_trace_rows(batch_size);
        let batch_proof_size = estimated_proof_size(batch_rows, TRACE_WIDTH);

        let single_rows = batch_trace_rows(1);
        let single_proof_size = estimated_proof_size(single_rows, TRACE_WIDTH);
        let individual_total = batch_size * single_proof_size;

        let savings = if batch_size > 1 {
            format!("{:.1}x", individual_total as f64 / batch_proof_size as f64)
        } else {
            "1.0x".to_string()
        };

        println!(
            "║ {:>6} │ {:>9} B │ {:>9} B │ {:>8} │ {:>10} ║",
            batch_size, batch_proof_size, individual_total, savings, batch_rows
        );
    }
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");

    // Benchmark the size calculation itself
    group.bench_function("calculate_proof_size_16", |b| {
        b.iter(|| {
            let rows = batch_trace_rows(16);
            estimated_proof_size(rows, TRACE_WIDTH)
        });
    });

    group.finish();
}

/// Benchmark public input validation
fn bench_public_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("public_inputs");
    group.measurement_time(Duration::from_secs(5));

    for batch_size in [2u32, 4, 8, 16] {
        let pub_inputs = mock_batch_public_inputs(batch_size);

        group.bench_with_input(
            BenchmarkId::new("validate", batch_size),
            &pub_inputs,
            |b, inputs| {
                b.iter(|| inputs.validate());
            },
        );
    }

    group.finish();
}

/// Benchmark trace row calculations
fn bench_row_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("row_calculations");

    for batch_size in [2usize, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::new("nullifier_rows", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    // Calculate all nullifier output rows for batch
                    let mut rows = Vec::with_capacity(size * MAX_INPUTS);
                    for tx_idx in 0..size {
                        for nf_idx in 0..MAX_INPUTS {
                            rows.push(nullifier_output_row(tx_idx, nf_idx));
                        }
                    }
                    rows
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("commitment_rows", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    // Calculate all commitment output rows for batch
                    let mut rows = Vec::with_capacity(size * MAX_OUTPUTS);
                    for tx_idx in 0..size {
                        for cm_idx in 0..MAX_OUTPUTS {
                            rows.push(commitment_output_row(tx_idx, cm_idx));
                        }
                    }
                    rows
                });
            },
        );
    }

    group.finish();
}

/// Print verification time estimates
fn print_verification_estimates(_c: &mut Criterion) {
    println!("\n╔═══════════════════════════════════════════════════════════════════╗");
    println!("║              ESTIMATED VERIFICATION TIME COMPARISON               ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║ Based on winterfell benchmarks: ~3ms per 2048-row trace verify    ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!(
        "║ {:>6} │ {:>15} │ {:>15} │ {:>12} ║",
        "Batch", "Batch Verify", "Individual", "Speedup"
    );
    println!("╠════════╪═════════════════╪═════════════════╪══════════════╣");

    // Base verification time per 2048 rows (empirical from winterfell)
    let base_verify_ms = 3.0f64;

    for batch_size in [1usize, 2, 4, 8, 16] {
        let batch_rows = batch_trace_rows(batch_size);
        // Verification time scales with log2(rows) for FRI
        let batch_log = (batch_rows as f64).log2();
        let single_log = (2048f64).log2();
        let batch_verify_ms = base_verify_ms * (batch_log / single_log);

        let individual_total_ms = batch_size as f64 * base_verify_ms;

        let speedup = if batch_size > 1 {
            format!("{:.1}x", individual_total_ms / batch_verify_ms)
        } else {
            "1.0x".to_string()
        };

        println!(
            "║ {:>6} │ {:>12.1} ms │ {:>12.1} ms │ {:>12} ║",
            batch_size, batch_verify_ms, individual_total_ms, speedup
        );
    }
    println!("╚═══════════════════════════════════════════════════════════════════╝\n");
}

criterion_group!(
    benches,
    bench_proof_sizes,
    bench_public_inputs,
    bench_row_calculations,
    print_verification_estimates,
);
criterion_main!(benches);
